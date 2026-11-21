//! Handing the sandbox one host file at a time through the document
//! portal. `org.freedesktop.portal.Documents.AddFull`
//! takes an `O_PATH` descriptor of the file and returns a document id;
//! the file then appears inside at `$XDG_RUNTIME_DIR/doc/<id>/<name>`.
//!
//! Nothing here widens a sandbox on its own: [`plan`] only classifies
//! arguments, [`register`](crate::forward_register::register) grants each file `read`, or
//! `read`+`write` where the user could write it anyway, in one call per
//! permission set, and every failure leaves the argument as it was.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use crate::bwrap::ETC_ALLOWLIST;
use crate::config::{InstanceConfig, Service};
use crate::dbus_wire::Value;
use crate::env::{Env, SANDBOX_HOME};
use crate::host::Host;

pub(crate) const DOC_DIR: &str = "doc";

// Bound at the same path inside. `/etc` is not one of them — it is a tmpfs with
// `ETC_ALLOWLIST` bound over it — nor are the `/bin` and `/lib` symlinks.
const BASELINE_ROOTS: [&str; 2] = ["/usr", "/opt"];

pub(crate) const REFUSED_ROOTS: [&str; 3] = ["/proc", "/sys", "/dev"];

/// One file the portal exported, and where the sandbox will find it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    /// Position of the argument to replace.
    pub arg_index: usize,
    /// The file on the host.
    pub host: PathBuf,
    /// `$XDG_RUNTIME_DIR/doc/<id>/<name>`, the path inside the sandbox.
    pub inside: PathBuf,
    /// Whether the sandbox was granted `write` as well as `read`.
    pub write: bool,
}

/// A host file an argument names, worth asking the portal for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Position in the argument list this was found at.
    pub arg_index: usize,
    /// The path the argument named: absolute, `file://` decoded, and
    /// with its symlinks still in it. Messages name this one, since it
    /// is what the user wrote.
    pub given: PathBuf,
    /// The file on the host with every symlink resolved. This is what
    /// is opened, what the permission and visibility rules are decided
    /// on, and what the portal ends up exporting.
    pub host: PathBuf,
    /// Basename the file keeps inside the document view: the canonical
    /// one, since the portal reads the name off the descriptor.
    pub name: OsString,
    /// Whether `write` is asked for as well as `read`: true only where
    /// the user may already write the file.
    pub write: bool,
}

/// Why an argument that named a path is not forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// Not an absolute path. What it resolves against is the caller's
    /// working directory, which the sandbox does not share.
    Relative,
    /// Not a regular file: a socket, a device, or nothing at all.
    NotAFile,
    /// A directory. The portal can export one, but a directory handed
    /// over wholesale is what `path-share` and `home-share` are for.
    Directory,
    /// Under `/proc`, `/sys` or `/dev`: a kernel interface, not a
    /// document, and one the sandbox has its own of already.
    Refused,
    /// Holds a `..` component. Refused rather than folded: what it resolves to
    /// depends on symlinks along the way.
    DotDot,
    /// Already reachable inside *at the same path*: a `path-share`
    /// source, an `etc-share` entry, or one of the trees the baseline
    /// binds. The argument is left alone and nothing is warned about.
    AlreadyVisible,
}

/// What [`plan`] decided about one argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Planned {
    /// A host file to ask the portal for.
    Forward(Candidate),
    /// A file the sandbox already sees, under another name, so the argument becomes
    /// the path inside. No portal and no grant are involved.
    Rename {
        /// Position in the argument list this was found at.
        arg_index: usize,
        /// The file on the host.
        host: PathBuf,
        /// Where the sandbox sees the same file.
        inside: PathBuf,
    },
    /// An argument that named a path bubbler will not forward, with the
    /// path as it was decoded and the reason.
    Skip(usize, PathBuf, Skip),
    /// Not a path at all: a flag, a bare word, another URI scheme.
    Untouched,
}

/// Classify every argument: which name a host file worth forwarding,
/// which name one bubbler will not forward and why, which are not paths. `args` are the
/// *arguments* of the sandboxed command, never the program itself; nothing is opened here.
pub fn plan(
    env: &Env,
    cfg: &InstanceConfig,
    instance_home: &Path,
    args: &[OsString],
    host: &dyn Host,
) -> Vec<Planned> {
    plan_from(0, env, cfg, instance_home, args, host)
}

/// [`plan`] over a whole command line, the program included: index 0 is
/// never a document, and the indices are into `cmd`, so [`rewrite`] takes that same slice.
pub fn plan_args(
    env: &Env,
    cfg: &InstanceConfig,
    instance_home: &Path,
    cmd: &[OsString],
    host: &dyn Host,
) -> Vec<Planned> {
    let Some((_program, args)) = cmd.split_first() else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(cmd.len());
    out.push(Planned::Untouched);
    out.extend(plan_from(1, env, cfg, instance_home, args, host));
    out
}

fn plan_from(
    offset: usize,
    env: &Env,
    cfg: &InstanceConfig,
    instance_home: &Path,
    args: &[OsString],
    host: &dyn Host,
) -> Vec<Planned> {
    let visible = visible_roots(env, cfg, instance_home, host);
    args.iter()
        .enumerate()
        .map(|(index, arg)| classify(offset + index, arg, &visible, host))
        .collect()
}

/// `args` with every file the sandbox will see put at its path inside; the rest are copied
/// as they were, and an index past the end is dropped. `planned` must be the [`plan`] (or
/// [`plan_args`]) of these same `args`, and `forwards` the [`register`](crate::forward_register::register) of its candidates.
pub fn rewrite(args: &[OsString], planned: &[Planned], forwards: &[Forward]) -> Vec<OsString> {
    debug_assert!(
        planned.len() <= args.len()
            && forwards.iter().all(|f| f.arg_index < args.len())
            && planned.iter().all(|p| match p {
                Planned::Rename { arg_index, .. } => *arg_index < args.len(),
                _ => true,
            }),
        "rewrite was given positions from another argument list"
    );
    let mut out = args.to_vec();
    let mut put = |index: usize, path: &Path| {
        if let Some(arg) = out.get_mut(index) {
            *arg = path.to_path_buf().into_os_string();
        }
    };
    for entry in planned {
        if let Planned::Rename {
            arg_index, inside, ..
        } = entry
        {
            put(*arg_index, inside);
        }
    }
    for forward in forwards {
        put(forward.arg_index, &forward.inside);
    }
    out
}

/// One line per file that would be forwarded, for `--explain` and
/// `--dry-run`. The document id is a literal `<id>`: it exists only
/// once the portal has been called, which neither of those does.
pub fn explain_lines(planned: &[Planned]) -> Vec<String> {
    planned
        .iter()
        .filter_map(|entry| match entry {
            Planned::Forward(candidate) => Some(format!(
                "forward: {}{} → $XDG_RUNTIME_DIR/{DOC_DIR}/<id>/{} ({})",
                candidate.given.display(),
                resolved_clause(candidate),
                Path::new(&candidate.name).display(),
                permission_text(candidate.write),
            )),
            Planned::Rename { host, inside, .. } => Some(format!(
                "visible: {} → {}",
                host.display(),
                inside.display()
            )),
            _ => None,
        })
        .collect()
}

/// One line per argument that named a path bubbler will not forward,
/// for the caller to print as a warning. A path that is already visible
/// inside, or that is not a path at all, says nothing.
pub fn warning_lines(planned: &[Planned]) -> Vec<String> {
    planned
        .iter()
        .filter_map(|entry| match entry {
            Planned::Skip(_, path, Skip::Directory) => Some(format!(
                "{} is a directory; grant path-share or home-share to expose it",
                path.display()
            )),
            Planned::Skip(_, path, Skip::NotAFile) => Some(format!(
                "{} is not a regular file, not forwarded",
                path.display()
            )),
            Planned::Skip(_, path, Skip::Refused) => Some(format!(
                "{} is under /proc, /sys or /dev, not forwarded",
                path.display()
            )),
            Planned::Skip(_, path, Skip::DotDot) => {
                Some(format!("{} contains `..`, not forwarded", path.display()))
            }
            _ => None,
        })
        .collect()
}

fn classify(index: usize, arg: &OsStr, visible: &[Root], host: &dyn Host) -> Planned {
    let given = match host_path(arg) {
        Some(path) if path.is_absolute() => path,
        Some(path) => return Planned::Skip(index, path, Skip::Relative),
        None => return Planned::Untouched,
    };
    if given
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Planned::Skip(index, given, Skip::DotDot);
    }
    // Every rule below is applied to the file the path ends at, not to
    // the name: `~/shared/link` may point anywhere.
    let real = host.canonicalize(&given).unwrap_or_else(|| given.clone());
    let refused = |p: &Path| REFUSED_ROOTS.iter().any(|root| p.starts_with(root));
    if refused(&given) || refused(&real) {
        return Planned::Skip(index, given, Skip::Refused);
    }
    // The longest matching root wins: an instance home under a shared
    // `~/.local/share` is bound by the more specific of the two.
    let root = visible
        .iter()
        .filter(|root| real.starts_with(&root.host))
        .max_by_key(|root| root.host.components().count());
    if let Some(root) = root {
        return match (&root.inside, real.strip_prefix(&root.host)) {
            (Some(inside), Ok(rest)) => {
                // Joining an empty remainder would leave a trailing
                // separator, and the root itself is the argument here.
                let inside = match rest.as_os_str().is_empty() {
                    true => inside.clone(),
                    false => inside.join(rest),
                };
                match inside == given {
                    true => Planned::Skip(index, given, Skip::AlreadyVisible),
                    false => Planned::Rename {
                        arg_index: index,
                        inside,
                        host: given,
                    },
                }
            }
            _ => Planned::Skip(index, given, Skip::AlreadyVisible),
        };
    }
    let Some(kind) = host.file_type(&real) else {
        return Planned::Skip(index, given, Skip::NotAFile);
    };
    if kind.is_dir() {
        return Planned::Skip(index, given, Skip::Directory);
    }
    // A regular file always has a name; the `None` is `/`, which is a
    // directory anyway.
    let (true, Some(name)) = (kind.is_file(), real.file_name().map(OsStr::to_os_string)) else {
        return Planned::Skip(index, given, Skip::NotAFile);
    };
    let write = host.writable(&real);
    Planned::Forward(Candidate {
        arg_index: index,
        given,
        host: real,
        name,
        write,
    })
}

struct Root {
    host: PathBuf,
    inside: Option<PathBuf>,
}

// The mapping mirrors the binds: `home-share` puts `$HOME/<path>` at
// `SANDBOX_HOME/<path>` and the instance home is the sandbox home.
fn visible_roots(
    env: &Env,
    cfg: &InstanceConfig,
    instance_home: &Path,
    host: &dyn Host,
) -> Vec<Root> {
    let same = |host: PathBuf| Root { host, inside: None };
    let mut roots: Vec<Root> = Vec::new();
    add_root(
        &mut roots,
        host,
        Root {
            host: instance_home.to_path_buf(),
            inside: Some(PathBuf::from(SANDBOX_HOME)),
        },
        |_| true,
    );
    for root in BASELINE_ROOTS {
        add_root(&mut roots, host, same(PathBuf::from(root)), |_| true);
    }
    for name in ETC_ALLOWLIST {
        // The baseline binds each entry wherever it resolves (bwrap resolves the
        // source), so the tree it lands on is visible at that path.
        add_root(&mut roots, host, same(etc(name)), |_| true);
    }
    for service in &cfg.services {
        match service {
            Service::HomeShare { path, optional, .. } => {
                // A missing optional source binds nothing, the same skip
                // `home_share` itself makes, so it is not a root either.
                if *optional && host.file_type(&env.home.join(path)).is_none() {
                    continue;
                }
                add_root(
                    &mut roots,
                    host,
                    Root {
                        host: env.home.join(path),
                        inside: Some(Path::new(SANDBOX_HOME).join(path)),
                    },
                    // `home_share` confines the resolved source to the home
                    // directory and fails the launch when it leaves it.
                    |real| real.starts_with(&env.home),
                )
            }
            Service::PathShare { path, optional, .. } => {
                if *optional && host.file_type(path).is_none() {
                    continue;
                }
                add_root(
                    &mut roots,
                    host,
                    same(path.clone()),
                    // The launcher refuses a `path-share` that meets a reserved root; a source
                    // resolving to `/` or to the user's home would otherwise claim every argument.
                    |_| crate::service::reserved_reason(host, env, path).is_none(),
                )
            }
            Service::EtcShare { name } => add_root(
                &mut roots,
                host,
                same(etc(name)),
                // `etc_share` confines the entry to `/etc` and fails
                // the launch when a symlink there names anything else.
                |real| real.starts_with("/etc"),
            ),
            _ => {}
        }
    }
    // A `--share` is a bind like the two share nodes above, so a file
    // under one is inside already.
    for share in &cfg.shares {
        match share.path.strip_prefix(&env.home) {
            // The same mapping `service::share_paths` binds by.
            Ok(rel) => add_root(
                &mut roots,
                host,
                Root {
                    host: share.path.clone(),
                    inside: Some(Path::new(SANDBOX_HOME).join(rel)),
                },
                |real| real.starts_with(&env.home),
            ),
            Err(_) => add_root(&mut roots, host, same(share.path.clone()), |_| {
                crate::service::reserved_reason(host, env, &share.path).is_none()
            }),
        }
    }
    // `/` or an empty root is a prefix of every path — which would quietly
    // forward no file at all.
    roots.retain(|root| root.host.is_absolute() && root.host != Path::new("/"));
    roots
}

// A bind resolves its source but mounts it at the path the config wrote, so the tree a
// source really names is a root too. `keep` answers what the launcher would refuse.
fn add_root(roots: &mut Vec<Root>, host: &dyn Host, root: Root, keep: impl FnOnce(&Path) -> bool) {
    if let Some(real) = host.canonicalize(&root.host)
        && real != root.host
        && real != Path::new("/")
        && keep(&real)
    {
        roots.push(Root {
            host: real,
            inside: Some(root.inside.clone().unwrap_or_else(|| root.host.clone())),
        });
    }
    roots.push(root);
}

fn etc(name: impl AsRef<Path>) -> PathBuf {
    Path::new("/etc").join(name)
}

fn host_path(arg: &OsStr) -> Option<PathBuf> {
    let bytes = arg.as_bytes();
    let decoded;
    let path: &[u8] = match bytes.split_at_checked(5) {
        // RFC 8089 gives an empty authority and "localhost" that meaning and nothing
        // else. A host bubbler cannot reach is not a file to forward.
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case(b"file:") => {
            let rest = match rest.strip_prefix(b"//") {
                None => rest,
                Some(rest) => {
                    let split = rest.iter().position(|b| *b == b'/')?;
                    let (authority, path) = rest.split_at(split);
                    if !(authority.is_empty() || authority.eq_ignore_ascii_case(b"localhost")) {
                        return None;
                    }
                    path
                }
            };
            decoded = percent_decode(rest);
            &decoded
        }
        // A path only where the argument is shaped like one. Anything
        // else is the command's own business.
        _ if bytes.starts_with(b"/") || bytes.starts_with(b"./") || bytes.starts_with(b"../") => {
            bytes
        }
        _ => return None,
    };
    if path.is_empty() || path.contains(&0) {
        return None;
    }
    Some(PathBuf::from(OsString::from_vec(path.to_vec())))
}

// A `%` that does not start a valid escape is left as it is: senders that
// never encoded it meant the character.
fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while let Some((first, tail)) = rest.split_first() {
        match (first, tail.split_at_checked(2)) {
            (b'%', Some((digits, after))) => match (hex(digits[0]), hex(digits[1])) {
                (Some(high), Some(low)) => {
                    out.push(high << 4 | low);
                    rest = after;
                }
                _ => {
                    out.push(*first);
                    rest = tail;
                }
            },
            _ => {
                out.push(*first);
                rest = tail;
            }
        }
    }
    out
}

fn hex(b: u8) -> Option<u8> {
    char::from(b).to_digit(16).map(|d| d as u8)
}

// In the order they first occur, so the calls go out in a fixed order.
pub(crate) fn permission_sets(candidates: &[Candidate]) -> Vec<bool> {
    let mut sets: Vec<bool> = Vec::with_capacity(2);
    for candidate in candidates {
        if !sets.contains(&candidate.write) {
            sets.push(candidate.write);
        }
    }
    sets
}

pub(crate) fn permissions(write: bool) -> Vec<Value> {
    let mut list = vec![Value::Str("read".to_owned())];
    if write {
        list.push(Value::Str("write".to_owned()));
    }
    list
}

// What is exported is the file at the end of the link, and an explanation
// that hid that would name the wrong file.
fn resolved_clause(candidate: &Candidate) -> String {
    match candidate.host == candidate.given {
        true => String::new(),
        false => format!(" (→ {})", candidate.host.display()),
    }
}

fn permission_text(write: bool) -> &'static str {
    match write {
        true => "write",
        false => "read",
    }
}

#[cfg(test)]
mod tests {
    use std::fs::FileType;

    use super::*;
    use crate::config::{Share, ShareMode};
    use crate::host::fake::{FakeHost, char_type, types};

    fn env() -> Env {
        Env {
            home: "/home/user".into(),
            data_home: "/home/user/.local/share".into(),
            config_home: "/home/user/.config".into(),
            config_dirs: Vec::new(),
            data_dirs: crate::env::DEFAULT_DATA_DIRS
                .iter()
                .map(PathBuf::from)
                .collect(),
            runtime_dir: "/run/user/1000".into(),
            uid: 1000,
            gid: 1000,
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
            init_override: None,
            dbus_address: None,
            dbus_system_address: None,
            at_spi_bus_address: None,
            dbus_log: false,
            net_proxy_log: false,
            seccomp_log: false,
            test_allow_path: None,
            profile_dir_override: None,
            proxy_override: None,
            pasta_override: None,
            pw_dump_override: None,
            wl_proxy_override: None,
            net_proxy_override: None,
        }
    }

    /// A config sharing `~/Documents` and `/srv/data`, so the plan has
    /// both kinds of source to compare against.
    fn cfg() -> InstanceConfig {
        InstanceConfig {
            services: vec![
                Service::HomeShare {
                    path: "Documents".into(),
                    mode: ShareMode::ReadOnly,
                    optional: false,
                },
                Service::HomeShare {
                    path: "Downloads".into(),
                    mode: ShareMode::ReadWrite,
                    optional: false,
                },
                Service::PathShare {
                    path: "/srv/data".into(),
                    mode: ShareMode::ReadWrite,
                    optional: false,
                },
                Service::Portals {
                    children: Vec::new(),
                },
            ],
            ..InstanceConfig::default()
        }
    }

    /// The host every plan case is decided against. `file_type` follows
    /// symlinks, so `link.pdf` is entered with the type of the file it
    /// points at and `canonicalize` says where it lands.
    fn tree() -> FakeHost {
        let (file, dir, socket) = types();
        FakeHost::default()
            .with("/home/user/a.pdf", file)
            .rw("/home/user/a.pdf")
            .with("/home/user/a b.pdf", file)
            .with("/home/user/theirs.pdf", file)
            .with("/home/user/pics", dir)
            .with("/home/user/s.sock", socket)
            .with("/home/user/link.pdf", file)
            .link("/home/user/link.pdf", "/home/user/a.pdf")
            .rw("/home/user/link.pdf")
            .with("/home/user/Documents", dir)
            .with("/home/user/Documents/report.pdf", file)
            .with("/home/user/Downloads/b.pdf", file)
            .with("/home/user/.ssh/id_rsa", file)
            .with("/data/inst/home", dir)
            .link("/data/inst/home", "/pool/inst/home")
            .with("/pool/inst/home/note.txt", file)
            .with("/srv/data/x.csv", file)
            // The `path-share` source is a symlink: the sandbox sees the
            // tree at `/srv/data`, which is where the bind puts it.
            .link("/srv/data", "/mnt/pool/data")
            .with("/mnt/pool/data/x.csv", file)
            .with("/data/inst/home/note.txt", file)
            .with("/usr/share/doc/manual.pdf", file)
            .with("/opt/vendor/manual.pdf", file)
            .with("/etc/fonts/fonts.conf", file)
            .with("/etc/secret.conf", file)
            .with("/proc/self/exe", file)
            .with("/dev/null", char_type())
    }

    const INSTANCE_HOME: &str = "/data/inst/home";

    /// One planned argument as a line, so the table below reads as one.
    fn tag(planned: &Planned) -> String {
        match planned {
            Planned::Forward(c) => format!(
                "forward {}{} as {} ({})",
                c.given.display(),
                resolved_clause(c),
                Path::new(&c.name).display(),
                permission_text(c.write)
            ),
            Planned::Rename { host, inside, .. } => {
                format!("rename {} → {}", host.display(), inside.display())
            }
            Planned::Skip(_, path, why) => format!("skip {} {why:?}", path.display()),
            Planned::Untouched => "untouched".to_owned(),
        }
    }

    fn planned(args: &[&str], host: &dyn Host) -> Vec<Planned> {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        plan(&env(), &cfg(), Path::new(INSTANCE_HOME), &args, host)
    }

    #[test]
    fn every_argument_is_classified_once() {
        let cases: &[(&str, &str)] = &[
            (
                "/home/user/a.pdf",
                "forward /home/user/a.pdf as a.pdf (write)",
            ),
            (
                "/home/user/theirs.pdf",
                "forward /home/user/theirs.pdf as theirs.pdf (read)",
            ),
            (
                "file:///home/user/a%20b.pdf",
                "forward /home/user/a b.pdf as a b.pdf (read)",
            ),
            (
                "file://localhost/home/user/a.pdf",
                "forward /home/user/a.pdf as a.pdf (write)",
            ),
            (
                "file:/home/user/a.pdf",
                "forward /home/user/a.pdf as a.pdf (write)",
            ),
            (
                "/home/user/link.pdf",
                "forward /home/user/link.pdf (→ /home/user/a.pdf) as a.pdf (write)",
            ),
            ("file://other/home/user/a.pdf", "untouched"),
            ("file://localhost", "untouched"),
            ("https://example.invalid/a.pdf", "untouched"),
            ("--flag", "untouched"),
            ("a.pdf", "untouched"),
            ("", "untouched"),
            ("./rel", "skip ./rel Relative"),
            ("../up/a.pdf", "skip ../up/a.pdf Relative"),
            ("file:rel/a.pdf", "skip rel/a.pdf Relative"),
            ("/home/user/pics", "skip /home/user/pics Directory"),
            ("/home/user/s.sock", "skip /home/user/s.sock NotAFile"),
            ("/home/user/gone.pdf", "skip /home/user/gone.pdf NotAFile"),
            ("/proc/self/exe", "skip /proc/self/exe Refused"),
            ("/dev/null", "skip /dev/null Refused"),
            ("/sys/power/state", "skip /sys/power/state Refused"),
            (
                "/home/user/Documents/report.pdf",
                "rename /home/user/Documents/report.pdf → /home/bubbler/Documents/report.pdf",
            ),
            (
                "file:///home/user/Documents/a%20b.pdf",
                "rename /home/user/Documents/a b.pdf → /home/bubbler/Documents/a b.pdf",
            ),
            ("/srv/data/x.csv", "skip /srv/data/x.csv AlreadyVisible"),
            (
                "/data/inst/home/note.txt",
                "rename /data/inst/home/note.txt → /home/bubbler/note.txt",
            ),
            (
                "/usr/share/doc/manual.pdf",
                "skip /usr/share/doc/manual.pdf AlreadyVisible",
            ),
            (
                "/opt/vendor/manual.pdf",
                "skip /opt/vendor/manual.pdf AlreadyVisible",
            ),
            (
                "/etc/fonts/fonts.conf",
                "skip /etc/fonts/fonts.conf AlreadyVisible",
            ),
            // The rest of `/etc` inside is a tmpfs, so this one is not
            // there until the portal puts it there.
            (
                "/etc/secret.conf",
                "forward /etc/secret.conf as secret.conf (read)",
            ),
            // `..` is refused rather than folded: it would otherwise
            // walk out of the share the path appears to be under.
            (
                "/home/user/Documents/../.ssh/id_rsa",
                "skip /home/user/Documents/../.ssh/id_rsa DotDot",
            ),
            (
                "/usr/../home/user/.ssh/id_rsa",
                "skip /usr/../home/user/.ssh/id_rsa DotDot",
            ),
            (
                "file:///home/user/Documents%2F..%2F.ssh/id_rsa",
                "skip /home/user/Documents/../.ssh/id_rsa DotDot",
            ),
            // A read-write share renames the same way a read-only one
            // does; the mode is the bind's business, not the path's.
            (
                "/home/user/Downloads/b.pdf",
                "rename /home/user/Downloads/b.pdf → /home/bubbler/Downloads/b.pdf",
            ),
            // The share root itself, with no separator left dangling.
            (
                "/home/user/Documents",
                "rename /home/user/Documents → /home/bubbler/Documents",
            ),
            ("/data/inst/home", "rename /data/inst/home → /home/bubbler"),
            // A share whose source is a symlink: the tree it names is
            // seen at the written path, and the written path is already
            // right.
            (
                "/mnt/pool/data/x.csv",
                "rename /mnt/pool/data/x.csv → /srv/data/x.csv",
            ),
            (
                "/pool/inst/home/note.txt",
                "rename /pool/inst/home/note.txt → /home/bubbler/note.txt",
            ),
        ];
        let args: Vec<&str> = cases.iter().map(|(arg, _)| *arg).collect();
        let out = planned(&args, &tree());
        let got: Vec<String> = out.iter().map(tag).collect();
        let want: Vec<&str> = cases.iter().map(|(_, want)| *want).collect();
        assert_eq!(got, want);
        for (index, entry) in out.iter().enumerate() {
            match entry {
                Planned::Forward(c) => assert_eq!(c.arg_index, index),
                Planned::Rename { arg_index, .. } => assert_eq!(*arg_index, index),
                Planned::Skip(at, ..) => assert_eq!(*at, index),
                Planned::Untouched => {}
            }
        }
    }

    #[test]
    fn a_link_that_lands_in_proc_is_refused_like_the_path_itself() {
        let (file, ..) = types();
        let host = FakeHost::default()
            .with("/home/user/kernel", file)
            .link("/home/user/kernel", "/proc/self/exe");
        assert_eq!(
            planned(&["/home/user/kernel"], &host),
            vec![Planned::Skip(
                0,
                PathBuf::from("/home/user/kernel"),
                Skip::Refused
            )]
        );
    }

    /// A `--share` counts the way the config's own shares do: what lies
    /// under one is visible at the path the bind gives it, and what lies
    /// beside it is still a file only the portal can hand in.
    #[test]
    fn a_file_under_a_per_run_share_is_visible_and_a_sibling_is_not() {
        let (file, dir, _) = types();
        let (work, todo, spare) = (home("work"), home("work/todo.md"), home("spare.md"));
        let host = FakeHost::default()
            .with("/srv/proj", dir)
            .with("/srv/proj/note.txt", file)
            .with("/srv/other/note.txt", file)
            .with(&todo, file)
            .with(&spare, file);
        let cfg = InstanceConfig {
            shares: vec![
                Share {
                    path: "/srv/proj".into(),
                    mode: ShareMode::ReadWrite,
                },
                Share {
                    path: work.into(),
                    mode: ShareMode::ReadOnly,
                },
            ],
            ..InstanceConfig::default()
        };
        let args: Vec<OsString> = [
            "/srv/proj/note.txt",
            "/srv/other/note.txt",
            todo.as_str(),
            spare.as_str(),
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let out = plan(&env(), &cfg, Path::new(INSTANCE_HOME), &args, &host);
        let got: Vec<String> = out.iter().map(tag).collect();
        assert_eq!(
            got,
            [
                "skip /srv/proj/note.txt AlreadyVisible".to_owned(),
                "forward /srv/other/note.txt as note.txt (read)".to_owned(),
                format!("rename {todo} → /home/bubbler/work/todo.md"),
                format!("forward {spare} as spare.md (read)"),
            ]
        );
    }

    /// The home of [`env`], as a test writes a host path out.
    fn home(rel: &str) -> String {
        env().home.join(rel).to_string_lossy().into_owned()
    }

    #[test]
    fn a_share_that_is_not_granted_does_not_hide_a_file() {
        let (file, ..) = types();
        let host = FakeHost::default().with("/home/user/Documents/report.pdf", file);
        let args = vec![OsString::from("/home/user/Documents/report.pdf")];
        let bare = InstanceConfig::default();
        let out = plan(&env(), &bare, Path::new(INSTANCE_HOME), &args, &host);
        assert_eq!(
            tag(&out[0]),
            "forward /home/user/Documents/report.pdf as report.pdf (read)"
        );
    }

    #[test]
    fn a_path_that_is_not_utf8_survives_decoding() {
        let arg = OsString::from_vec(b"file:///home/user/%ff.pdf".to_vec());
        let file: FileType = types().0;
        let name = OsString::from_vec(b"\xff.pdf".to_vec());
        let host = FakeHost::default().with("/home/user/\u{fffd}", file);
        let out = plan(
            &env(),
            &cfg(),
            Path::new(INSTANCE_HOME),
            &[arg],
            &host as &dyn Host,
        );
        // The file is not in the fake tree under that name, but the
        // decoded bytes are what was looked up.
        assert_eq!(
            out,
            vec![Planned::Skip(
                0,
                PathBuf::from(OsString::from_vec(b"/home/user/\xff.pdf".to_vec())),
                Skip::NotAFile
            )]
        );
        assert_eq!(
            host_path(OsStr::new("file:///home/user/%ff.pdf"))
                .and_then(|p| p.file_name().map(OsStr::to_os_string)),
            Some(name)
        );
    }

    #[test]
    fn a_root_that_is_no_root_hides_nothing() {
        let args = vec![OsString::from("/home/user/a.pdf")];
        let out = plan(&env(), &cfg(), Path::new(""), &args, &tree());
        assert_eq!(tag(&out[0]), "forward /home/user/a.pdf as a.pdf (write)");
    }

    #[test]
    fn a_root_that_does_not_resolve_is_still_a_root() {
        let (file, dir, _) = types();
        // The share source is there, but nothing about it resolves —
        // what the real host answers for a path it cannot walk.
        let host = tree()
            .with("/home/user/Documents", dir)
            .with("/home/user/Documents/report.pdf", file)
            .unresolved("/home/user/Documents");
        assert_eq!(
            tag(&planned(&["/home/user/Documents/report.pdf"], &host)[0]),
            "rename /home/user/Documents/report.pdf → /home/bubbler/Documents/report.pdf"
        );
    }

    #[test]
    fn a_share_whose_source_is_refused_at_launch_is_no_root() {
        // `/srv/escape` resolves to the whole filesystem and
        // `/srv/store` to the user's home: `path-share` refuses both,
        // so neither may rewrite an argument either.
        let host = tree()
            .link("/srv/escape", "/")
            .link("/srv/store", "/home/user");
        let cfg = InstanceConfig {
            services: vec![
                Service::PathShare {
                    path: "/srv/escape".into(),
                    mode: ShareMode::ReadOnly,
                    optional: false,
                },
                Service::PathShare {
                    path: "/srv/store".into(),
                    mode: ShareMode::ReadWrite,
                    optional: false,
                },
            ],
            ..InstanceConfig::default()
        };
        let args = [OsString::from("/home/user/a.pdf")];
        let out = plan(&env(), &cfg, Path::new(INSTANCE_HOME), &args, &host);
        assert_eq!(tag(&out[0]), "forward /home/user/a.pdf as a.pdf (write)");
    }

    /// A skipped optional share binds nothing, so it is no root either:
    /// an argument under it is a file like any other, not a file the
    /// sandbox already sees under a renamed path that was never bound.
    #[test]
    fn an_optional_home_share_whose_source_is_absent_covers_nothing() {
        let (file, ..) = types();
        let host = tree().with("/home/user/Extras/report.pdf", file);
        let cfg = InstanceConfig {
            services: vec![Service::HomeShare {
                path: "Extras".into(),
                mode: ShareMode::ReadOnly,
                optional: true,
            }],
            ..InstanceConfig::default()
        };
        let args = [OsString::from("/home/user/Extras/report.pdf")];
        let out = plan(&env(), &cfg, Path::new(INSTANCE_HOME), &args, &host);
        assert_eq!(
            tag(&out[0]),
            "forward /home/user/Extras/report.pdf as report.pdf (read)"
        );
    }

    #[test]
    fn an_etc_share_that_leaves_etc_is_no_root() {
        // `etc_share` refuses an entry that resolves outside `/etc`, so
        // the tree it names is not visible inside and an argument under
        // it is a file like any other.
        let (file, ..) = types();
        let host = tree()
            .link("/etc/wild", "/mnt/wild")
            .with("/mnt/wild/x.conf", file);
        let cfg = InstanceConfig {
            services: vec![Service::EtcShare {
                name: "wild".into(),
            }],
            ..InstanceConfig::default()
        };
        let args = [OsString::from("/mnt/wild/x.conf")];
        let out = plan(&env(), &cfg, Path::new(INSTANCE_HOME), &args, &host);
        assert_eq!(tag(&out[0]), "forward /mnt/wild/x.conf as x.conf (read)");
    }

    #[test]
    fn a_home_share_that_leaves_the_home_is_no_root() {
        // `home-share` confines its source to the home directory, so a
        // source pointing out of it never becomes a rename root.
        let (file, ..) = types();
        let host = tree()
            .link("/home/user/Documents", "/mnt/elsewhere")
            .with("/mnt/elsewhere/report.pdf", file);
        assert_eq!(
            tag(&planned(&["/mnt/elsewhere/report.pdf"], &host)[0]),
            "forward /mnt/elsewhere/report.pdf as report.pdf (read)"
        );
    }

    #[test]
    fn a_nul_in_a_uri_names_no_file() {
        assert_eq!(host_path(OsStr::new("file:///home/user/a%00b.pdf")), None);
    }

    #[test]
    fn a_percent_that_starts_no_escape_stays_a_percent() {
        assert_eq!(percent_decode(b"100%.pdf"), b"100%.pdf");
        assert_eq!(percent_decode(b"a%zz"), b"a%zz");
        assert_eq!(percent_decode(b"a%2"), b"a%2");
        assert_eq!(percent_decode(b"%2f%2F"), b"//");
    }

    #[test]
    fn the_warning_lines_are_the_ones_the_cli_prints() {
        let out = planned(
            &[
                "/home/user/pics",
                "/home/user/s.sock",
                "/proc/self/exe",
                "/home/user/Documents/../.ssh/id_rsa",
                "/home/user/a.pdf",
                "/srv/data/x.csv",
                "./rel",
                "--flag",
            ],
            &tree(),
        );
        assert_eq!(
            warning_lines(&out),
            vec![
                "/home/user/pics is a directory; grant path-share or home-share to expose it",
                "/home/user/s.sock is not a regular file, not forwarded",
                "/proc/self/exe is under /proc, /sys or /dev, not forwarded",
                "/home/user/Documents/../.ssh/id_rsa contains `..`, not forwarded",
            ]
        );
    }

    #[test]
    fn the_explain_lines_name_the_document_path_with_a_literal_id() {
        let out = planned(
            &[
                "/home/user/a.pdf",
                "/home/user/theirs.pdf",
                "/home/user/link.pdf",
                "/home/user/Documents/report.pdf",
                "/srv/data/x.csv",
                "--flag",
            ],
            &tree(),
        );
        assert_eq!(
            explain_lines(&out),
            vec![
                "forward: /home/user/a.pdf → $XDG_RUNTIME_DIR/doc/<id>/a.pdf (write)",
                "forward: /home/user/theirs.pdf → $XDG_RUNTIME_DIR/doc/<id>/theirs.pdf (read)",
                // The link is not what is exported; the file it names is.
                "forward: /home/user/link.pdf (→ /home/user/a.pdf) → $XDG_RUNTIME_DIR/doc/<id>/a.pdf (write)",
                "visible: /home/user/Documents/report.pdf → /home/bubbler/Documents/report.pdf",
            ]
        );
    }

    #[test]
    fn rewrite_replaces_only_what_was_registered() {
        let args: Vec<OsString> = ["--flag", "/home/user/a.pdf", "file:///home/user/b.pdf"]
            .iter()
            .map(OsString::from)
            .collect();
        let renamed = vec![Planned::Rename {
            arg_index: 2,
            host: "/home/user/Documents/b.pdf".into(),
            inside: "/home/bubbler/Documents/b.pdf".into(),
        }];
        let forwards = vec![Forward {
            arg_index: 1,
            host: "/home/user/a.pdf".into(),
            inside: "/run/user/1000/doc/abc/a.pdf".into(),
            write: true,
        }];
        assert_eq!(
            rewrite(&args, &[], &forwards),
            vec![
                OsString::from("--flag"),
                OsString::from("/run/user/1000/doc/abc/a.pdf"),
                OsString::from("file:///home/user/b.pdf"),
            ]
        );
        // A rename needs no portal, so it applies with nothing registered.
        assert_eq!(
            rewrite(&args, &renamed, &[]),
            vec![
                OsString::from("--flag"),
                OsString::from("/home/user/a.pdf"),
                OsString::from("/home/bubbler/Documents/b.pdf"),
            ]
        );
        assert_eq!(rewrite(&args, &[], &[]), args);
    }

    #[test]
    fn the_program_is_never_a_document() {
        let cmd: Vec<OsString> = ["/usr/bin/cat", "/home/user/a.pdf"]
            .iter()
            .map(OsString::from)
            .collect();
        let out = plan_args(&env(), &cfg(), Path::new(INSTANCE_HOME), &cmd, &tree());
        assert_eq!(out[0], Planned::Untouched);
        assert_eq!(tag(&out[1]), "forward /home/user/a.pdf as a.pdf (write)");
        assert_eq!(
            plan_args(&env(), &cfg(), Path::new(INSTANCE_HOME), &[], &tree()),
            Vec::new()
        );
        // A bare argument list keeps the program's own index free.
        assert_eq!(planned(&["/home/user/a.pdf"], &tree()).len(), 1);
    }
}
