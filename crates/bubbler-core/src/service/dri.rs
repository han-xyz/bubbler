//! GPU access: the render node of every GPU by default, `kms` adding the
//! primary (`card*`) nodes and their sysfs, and the primary-node exception
//! for a GPU on the proprietary NVIDIA driver — see the manual's `dri` entry.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::os::unix::fs::FileTypeExt;
use std::path::{Component, Path, PathBuf};

use crate::bwrap::BwrapArgs;
use crate::error::LaunchError;
use crate::host::Host;

use super::require_dir;

/// Where the kernel puts the DRM device nodes. A `dri` grant binds the
/// nodes it needs one by one, never this directory.
const DRI_DEV: &str = "/dev/dri";

/// Where the kernel publishes the DRM class: one entry per node, plus
/// the connector directories that carry a monitor's EDID.
const DRM_CLASS: &str = "/sys/class/drm";

/// GPU access: the render node of every GPU the host has, bound
/// read-write because bwrap has no read-only device bind, plus each GPU's
/// own `/sys/devices` directory and whichever NVIDIA nodes are there.
/// `kms` adds the primary (`card*`) nodes and leaves the sysfs behind
/// them readable, which is mode setting and everything that comes with
/// it: DRM master on a virtual terminal switch, the monitors' EDID, the
/// framebuffer geometry, every other client's flink names.
pub(super) fn dri(args: &mut BwrapArgs, host: &dyn Host, kms: bool) -> Result<(), LaunchError> {
    let dev = require_dir(host, "dri", PathBuf::from(DRI_DEV))?;
    // udev's `by-path` links are the only discovery path: a node's name
    // says nothing about which kind it is, and `/dev/dri` bound whole is
    // what this grant no longer does. The directory itself is not bound.
    let by_path = dev.join("by-path");
    let (render, card) = dri_nodes(host, &by_path);
    if render.is_empty() {
        return Err(LaunchError::MissingResource {
            service: "dri",
            path: by_path,
        });
    }
    for name in &render {
        let node = dev.join(name);
        args.dev_bind(&node, &node);
    }
    if kms {
        for name in &card {
            let node = dev.join(name);
            args.dev_bind(&node, &node);
        }
    }
    // Paths from Arch wiki Bubblewrap/Examples. `/sys/dev/char` is the
    // symlinks a driver maps a device number through; they lead into the
    // directories bound below.
    for p in ["/sys/dev/char", "/sys/devices/system/cpu"] {
        let p = require_dir(host, "dri", PathBuf::from(p))?;
        args.ro_bind(&p, &p);
    }
    for name in &render {
        dri_sysfs(args, host, name, kms)?;
    }
    // `/sys/class/drm` is rebuilt from the symlinks above rather than
    // bound, since its own entries are the primary nodes and their
    // connectors; `version` is the only file left of it. Missing on a
    // host with no DRM driver loaded, which is not an error when the
    // render node is there.
    let version = Path::new(DRM_CLASS).join("version");
    if host.file_type(&version).is_some_and(|t| t.is_file()) {
        args.ro_bind(&version, &version);
    }
    // The NVIDIA nodes are created by the setuid `nvidia-modprobe` a udev
    // rule runs, and a sandbox has `NoNewPrivs` set, so a node missing at
    // launch can never appear later: bind what the host has, fail over
    // nothing. The char-device check keeps the `/dev/nvidia-caps`
    // directory out: those are MIG capability files, and nothing outside
    // MIG reads them. They have no render/primary split of their own, so
    // `kms` says nothing about them.
    // `file_type` follows symlinks, but `/dev` and `/sys/module` are
    // root-owned, so a `nvidia*` symlink there is the host's decision.
    let dev_dir = Path::new("/dev");
    for name in host.list_dir(dev_dir) {
        if !name.as_encoded_bytes().starts_with(b"nvidia") {
            continue;
        }
        let p = dev_dir.join(&name);
        if host.file_type(&p).is_some_and(|t| t.is_char_device()) {
            args.dev_bind(&p, &p);
        }
    }
    // libnvidia-glvnd and NVML read `/sys/module/nvidia/initstate` and fall
    // back to Mesa when it is missing (verified on driver 610). The other
    // `nvidia_*` module directories cost nothing and cover CUDA.
    let modules = Path::new("/sys/module");
    for name in host.list_dir(modules) {
        if !name.as_encoded_bytes().starts_with(b"nvidia") {
            continue;
        }
        let p = modules.join(&name);
        if host.file_type(&p).is_some_and(|t| t.is_dir()) {
            args.ro_bind(&p, &p);
        }
    }
    Ok(())
}

/// The names of the render and the primary nodes `by_path` points at,
/// each once and in name order. udev writes those links as `../<node>`,
/// and a link of any other shape names nothing: what it points at is
/// then outside the device directory this grant is confined to. A link
/// that cannot be read is one GPU fewer, never one more; a host where
/// that leaves no render node at all fails in the caller.
fn dri_nodes(host: &dyn Host, by_path: &Path) -> (BTreeSet<OsString>, BTreeSet<OsString>) {
    let (mut render, mut card) = (BTreeSet::new(), BTreeSet::new());
    for entry in host.list_dir(by_path) {
        let kind = match entry.as_encoded_bytes() {
            b if b.ends_with(b"-render") => &mut render,
            b if b.ends_with(b"-card") => &mut card,
            _ => continue,
        };
        let Ok(Some(target)) = host.read_link(&by_path.join(&entry)) else {
            continue;
        };
        let mut parts = target.components();
        if let (Some(Component::ParentDir), Some(Component::Normal(node)), None) =
            (parts.next(), parts.next(), parts.next())
        {
            kind.insert(node.to_os_string());
        }
    }
    (render, card)
}

/// Whether a bare `dri` on this host binds a primary node as well as the
/// render nodes, which it does for a GPU on the proprietary NVIDIA
/// driver. The linter asks, so a config that says nothing about that
/// node can still tell the reader what the run opens.
pub(crate) fn dri_binds_a_primary_node(host: &dyn Host) -> bool {
    let (render, _) = dri_nodes(host, &Path::new(DRI_DEV).join("by-path"));
    render.iter().any(|name| {
        host.canonicalize(&Path::new(DRM_CLASS).join(name).join("device"))
            .and_then(|dir| dri_driver(host, &dir))
            .is_some_and(|driver| driver == "nvidia")
    })
}

/// The name of the kernel driver bound to the device at `dir`, from the
/// link its bus keeps beside it (`.../0000:01:00.0/driver` ->
/// `../../../../bus/pci/drivers/nvidia`). `None` where the device has no
/// driver or the link cannot be read.
fn dri_driver(host: &dyn Host, dir: &Path) -> Option<OsString> {
    let target = host.read_link(&dir.join("driver")).ok().flatten()?;
    target.file_name().map(OsStr::to_os_string)
}

/// The sysfs one render node needs: the GPU's own directory under
/// `/sys/devices`, with the primary nodes under it masked by an empty
/// read-only tmpfs unless `kms`, and `/sys/class/drm/<node>` as the
/// relative symlink the host has there, so a driver that walks the class
/// directory finds the device without the rest of the class being bound.
/// A GPU on the proprietary NVIDIA driver also keeps its primary node,
/// which is the one thing its EGL will not drive a Wayland display
/// without.
fn dri_sysfs(
    args: &mut BwrapArgs,
    host: &dyn Host,
    name: &OsStr,
    kms: bool,
) -> Result<(), LaunchError> {
    let class = Path::new(DRM_CLASS).join(name);
    let link = class.join("device");
    let devices = Path::new("/sys/devices");
    let Some(dir) = host.canonicalize(&link) else {
        return Err(LaunchError::MissingResource {
            service: "dri",
            path: link,
        });
    };
    // Every GPU's directory is under `/sys/devices`, and one that
    // resolves elsewhere is not a device this grant can hand over
    // without binding a tree it knows nothing about.
    let Ok(rel) = dir.strip_prefix(devices) else {
        return Err(LaunchError::BadValue {
            service: "dri",
            reason: format!(
                "`{}` resolves to `{}`, outside /sys/devices",
                link.display(),
                dir.display()
            ),
        });
    };
    args.ro_bind(&dir, &dir);
    let drm = dir.join("drm");
    if !kms {
        // NVIDIA's proprietary stack has no render/primary split, and its
        // EGL declines a Wayland display without the primary node:
        // measured on driver 610, a client inside falls back to llvmpipe
        // and Mesa reports `pci id 10de:…, driver (null)`. Only the node
        // is needed — with it bound and the sysfs below still masked, the
        // same client gets the GPU back.
        let nvidia = dri_driver(host, &dir).is_some_and(|d| d == "nvidia");
        for entry in host.list_dir(&drm) {
            let card = drm.join(&entry);
            if !entry.as_encoded_bytes().starts_with(b"card")
                || !host.file_type(&card).is_some_and(|t| t.is_dir())
            {
                continue;
            }
            if nvidia {
                let node = Path::new(DRI_DEV).join(&entry);
                args.dev_bind(&node, &node);
            }
            // The primary node's directory holds the connectors, and each
            // of those holds the monitor's EDID; the node's own
            // attributes carry the framebuffer geometry.
            args.mask_dir(&card);
        }
    }
    // Relative, as the host writes it: a driver comparing the link with
    // the one it read on the host sees the same text.
    args.symlink(
        &Path::new("../../devices").join(rel).join("drm").join(name),
        &class,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Service;

    use super::super::tests::Kind::{self, Char, Dir, File};
    use super::super::tests::{
        GPU_A, GPU_B, argv, argv_linked, binds, env, gamepad_host, has_seq, pad, seq_at,
        two_gpu_host, two_gpu_links,
    };

    /// [`two_gpu_links`] with the first GPU driven by the proprietary
    /// NVIDIA driver, as this desktop has it.
    fn nvidia_gpu_links() -> Vec<(&'static str, &'static str)> {
        two_gpu_links()
            .into_iter()
            .map(|(from, to)| match from {
                "/sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0/driver" => {
                    (from, "../../../../bus/pci/drivers/nvidia")
                }
                _ => (from, to),
            })
            .collect()
    }

    /// What a bare `dri` binds on [`two_gpu_host`]. The masks it also
    /// emits are [`two_gpu_masks`], which every grant's binds come
    /// before.
    fn two_gpu_binds() -> Vec<&'static str> {
        vec![
            "--dev-bind",
            "/dev/dri/renderD128",
            "/dev/dri/renderD128",
            "--dev-bind",
            "/dev/dri/renderD129",
            "/dev/dri/renderD129",
            "--ro-bind",
            "/sys/dev/char",
            "/sys/dev/char",
            "--ro-bind",
            "/sys/devices/system/cpu",
            "/sys/devices/system/cpu",
            "--ro-bind",
            GPU_A,
            GPU_A,
            "--symlink",
            "../../devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/renderD128",
            "/sys/class/drm/renderD128",
            "--ro-bind",
            GPU_B,
            GPU_B,
            "--symlink",
            "../../devices/pci0000:00/0000:00:08.1/0000:0c:00.0/drm/renderD129",
            "/sys/class/drm/renderD129",
            "--ro-bind",
            "/sys/class/drm/version",
            "/sys/class/drm/version",
        ]
    }

    /// The card directories a bare `dri` covers on [`two_gpu_host`], in
    /// the place the builder emits every mask: after the binds.
    fn two_gpu_masks() -> Vec<&'static str> {
        vec![
            "--size",
            "4096",
            "--tmpfs",
            "/sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/card1",
            "--remount-ro",
            "/sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/card1",
            "--size",
            "4096",
            "--tmpfs",
            "/sys/devices/pci0000:00/0000:00:08.1/0000:0c:00.0/drm/card0",
            "--remount-ro",
            "/sys/devices/pci0000:00/0000:00:08.1/0000:0c:00.0/drm/card0",
        ]
    }

    #[test]
    fn dri_binds_the_render_nodes_and_each_gpus_own_sysfs() {
        let a = argv_linked(
            &[Service::Dri { kms: false }],
            &env(),
            &two_gpu_host(),
            &two_gpu_links(),
        )
        .unwrap();
        assert_eq!(
            binds(&a),
            [two_gpu_binds(), two_gpu_masks()].concat(),
            "no card node, no `/dev/dri` itself, no `by-path`, no PCI root and no \
             `/sys/class/drm` around the two symlinks"
        );
    }

    #[test]
    fn dri_binds_the_primary_node_of_an_nvidia_gpu_and_of_no_other() {
        let a = argv_linked(
            &[Service::Dri { kms: false }],
            &env(),
            &two_gpu_host(),
            &nvidia_gpu_links(),
        )
        .unwrap();
        assert_eq!(
            binds(&a),
            [
                vec![
                    "--dev-bind",
                    "/dev/dri/renderD128",
                    "/dev/dri/renderD128",
                    "--dev-bind",
                    "/dev/dri/renderD129",
                    "/dev/dri/renderD129",
                    "--ro-bind",
                    "/sys/dev/char",
                    "/sys/dev/char",
                    "--ro-bind",
                    "/sys/devices/system/cpu",
                    "/sys/devices/system/cpu",
                    "--ro-bind",
                    GPU_A,
                    GPU_A,
                    "--dev-bind",
                    "/dev/dri/card1",
                    "/dev/dri/card1",
                    "--symlink",
                    "../../devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/renderD128",
                    "/sys/class/drm/renderD128",
                    "--ro-bind",
                    GPU_B,
                    GPU_B,
                    "--symlink",
                    "../../devices/pci0000:00/0000:00:08.1/0000:0c:00.0/drm/renderD129",
                    "/sys/class/drm/renderD129",
                    "--ro-bind",
                    "/sys/class/drm/version",
                    "/sys/class/drm/version",
                ],
                two_gpu_masks(),
            ]
            .concat(),
            "the Mesa-driven GPU keeps its primary node out, and both card \
             directories stay masked"
        );
    }

    #[test]
    fn dri_kms_adds_the_card_nodes_and_leaves_their_sysfs_readable() {
        let a = argv_linked(
            &[Service::Dri { kms: true }],
            &env(),
            &two_gpu_host(),
            &two_gpu_links(),
        )
        .unwrap();
        assert_eq!(
            binds(&a),
            vec![
                "--dev-bind",
                "/dev/dri/renderD128",
                "/dev/dri/renderD128",
                "--dev-bind",
                "/dev/dri/renderD129",
                "/dev/dri/renderD129",
                "--dev-bind",
                "/dev/dri/card0",
                "/dev/dri/card0",
                "--dev-bind",
                "/dev/dri/card1",
                "/dev/dri/card1",
                "--ro-bind",
                "/sys/dev/char",
                "/sys/dev/char",
                "--ro-bind",
                "/sys/devices/system/cpu",
                "/sys/devices/system/cpu",
                "--ro-bind",
                GPU_A,
                GPU_A,
                "--symlink",
                "../../devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/renderD128",
                "/sys/class/drm/renderD128",
                "--ro-bind",
                GPU_B,
                GPU_B,
                "--symlink",
                "../../devices/pci0000:00/0000:00:08.1/0000:0c:00.0/drm/renderD129",
                "/sys/class/drm/renderD129",
                "--ro-bind",
                "/sys/class/drm/version",
                "/sys/class/drm/version",
            ]
        );
    }

    #[test]
    fn dris_card_masks_survive_a_gamepads_whole_device_tree() {
        let card_a = "/sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/card1";
        let mut host = gamepad_host();
        host.extend(two_gpu_host());
        for order in [
            [Service::Dri { kms: false }, pad(false, false)],
            [pad(false, false), Service::Dri { kms: false }],
        ] {
            let a = argv_linked(&order, &env(), &host, &two_gpu_links()).unwrap();
            let tree = seq_at(&a, &["--ro-bind", "/sys/devices", "/sys/devices"])
                .expect("gamepad binds the device tree");
            let mask = seq_at(&a, &["--size", "4096", "--tmpfs", card_a])
                .expect("dri masks the card directory");
            // A bind of the tree over a mask already laid would hand the
            // card sysfs back, so the masks are emitted last of all.
            assert!(tree < mask, "{order:?}: {a:?}");
            assert!(has_seq(&a, &["--remount-ro", card_a]), "{a:?}");
        }
        let kms = argv_linked(
            &[Service::Dri { kms: true }, pad(false, false)],
            &env(),
            &host,
            &two_gpu_links(),
        )
        .unwrap();
        assert!(
            !has_seq(&kms, &["--size", "4096", "--tmpfs", card_a]),
            "{kms:?}"
        );
    }

    #[test]
    fn dri_without_a_render_node_under_by_path_is_an_error() {
        // `by-path` is the only place a render node is discovered, so a
        // host that has none there fails rather than falling back to a
        // wider bind of `/dev/dri`.
        let host: Vec<(&str, Kind)> = two_gpu_host()
            .into_iter()
            .filter(|(p, _)| !p.ends_with("-render"))
            .collect();
        let links: Vec<(&str, &str)> = two_gpu_links()
            .into_iter()
            .filter(|(from, _)| !from.ends_with("-render"))
            .collect();
        assert!(matches!(
            argv_linked(&[Service::Dri { kms: false }], &env(), &host, &links),
            Err(LaunchError::MissingResource { service: "dri", path })
                if path == Path::new("/dev/dri/by-path")
        ));
    }

    #[test]
    fn dri_refuses_a_render_node_whose_sysfs_leaves_the_device_tree() {
        let links: Vec<(&str, &str)> = two_gpu_links()
            .into_iter()
            .map(|(from, to)| match from {
                "/sys/class/drm/renderD128/device" => (from, "/sys/class/misc"),
                _ => (from, to),
            })
            .collect();
        let r = argv_linked(
            &[Service::Dri { kms: false }],
            &env(),
            &two_gpu_host(),
            &links,
        );
        assert!(
            matches!(&r, Err(LaunchError::BadValue { service: "dri", reason })
                if reason.contains("/sys/devices")),
            "{r:?}"
        );
    }

    #[test]
    fn dri_binds_the_nvidia_nodes_and_the_module_directories() {
        let mut host = two_gpu_host();
        host.extend([
            ("/dev/nvidia0", Char),
            ("/dev/nvidiactl", Char),
            ("/dev/nvidia-modeset", Char),
            ("/dev/nvidia-uvm", Char),
            ("/dev/nvidia-uvm-tools", Char),
            ("/dev/nvidia-caps", Dir),
            ("/sys/module/nvidia", Dir),
            ("/sys/module/nvidia_drm", Dir),
            ("/sys/module/nvidia_uvm", Dir),
            ("/sys/module/amdgpu", Dir),
        ]);
        let a = argv_linked(
            &[Service::Dri { kms: false }],
            &env(),
            &host,
            &two_gpu_links(),
        )
        .unwrap();
        let mut expected = two_gpu_binds();
        expected.extend([
            "--dev-bind",
            "/dev/nvidia-modeset",
            "/dev/nvidia-modeset",
            "--dev-bind",
            "/dev/nvidia-uvm",
            "/dev/nvidia-uvm",
            "--dev-bind",
            "/dev/nvidia-uvm-tools",
            "/dev/nvidia-uvm-tools",
            "--dev-bind",
            "/dev/nvidia0",
            "/dev/nvidia0",
            "--dev-bind",
            "/dev/nvidiactl",
            "/dev/nvidiactl",
            "--ro-bind",
            "/sys/module/nvidia",
            "/sys/module/nvidia",
            "--ro-bind",
            "/sys/module/nvidia_drm",
            "/sys/module/nvidia_drm",
            "--ro-bind",
            "/sys/module/nvidia_uvm",
            "/sys/module/nvidia_uvm",
        ]);
        expected.extend(two_gpu_masks());
        assert_eq!(
            binds(&a),
            expected,
            "the /dev/nvidia-caps directory and unrelated module directories stay out, \
             and the card masks follow every bind"
        );
    }

    #[test]
    fn dri_adds_nothing_on_a_host_without_the_nvidia_stack() {
        let mut host = two_gpu_host();
        host.extend([
            ("/sys/module/amdgpu", Dir),
            // A directory named like a node is not one.
            ("/dev/nvidia-caps", Dir),
        ]);
        let a = argv_linked(
            &[Service::Dri { kms: false }],
            &env(),
            &host,
            &two_gpu_links(),
        )
        .unwrap();
        assert_eq!(binds(&a), [two_gpu_binds(), two_gpu_masks()].concat());
    }

    #[test]
    fn dri_requires_dev_dri_to_be_a_directory() {
        assert!(matches!(
            argv(
                &[Service::Dri { kms: false }],
                &env(),
                &[("/dev/dri", File)]
            ),
            Err(LaunchError::WrongType {
                service: "dri",
                expected: "a directory",
                ..
            })
        ));
    }
}
