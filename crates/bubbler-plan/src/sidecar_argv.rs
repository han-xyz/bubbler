//! The bwrap argv of a sandbox and of each sidecar, and the explanation of
//! each, computed without creating or spawning anything. `--dry-run`,
//! `--explain` and a real run all build their argv here.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::bwrap::{Argv, BwrapArgs, Explained, FdAllocator, Origin};
use crate::config::{EtcMode, NetworkConfig, Service, Userns, WaylandMode};
use crate::env::Env;
use crate::error::ConfigError;
use crate::host::{Host, RealHost};
use crate::instance::Instance;
use crate::paths::instance_runtime_dir;
use crate::plan_error::PlanError;
use crate::wayland::ProxyPlan;
use crate::{dbus, init_bin, network, pipewire, seccomp, service, wayland};

/// The runtime-directory name of a generated file: its sandbox path flattened behind `prefix`,
/// so `--explain` names the file a run would write and no two destinations collide.
pub fn data_name(prefix: &str, dest: &Path) -> OsString {
    let mut name = OsString::from(prefix);
    let mut first = true;
    for part in dest.components() {
        if let Component::Normal(part) = part {
            if !first {
                name.push("-");
            }
            name.push(part);
            first = false;
        }
    }
    name
}

// Sandbox and sidecars write into the one runtime directory, and `portals` gives each a
// `/.flatpak-info`.
pub const SIDECAR_PREFIX: &str = "proxy-";

/// Allocator for `--dry-run`: numbers every fd 3, 4, ... and names each
/// generated file where a run would write it, without creating anything.
#[derive(Debug)]
pub struct DryRunAlloc {
    next: u32,
    dir: PathBuf,
    prefix: &'static str,
}

impl DryRunAlloc {
    /// `dir` is the run's runtime directory; fd numbering starts above stdio.
    pub fn new(dir: PathBuf) -> Self {
        Self {
            next: 2,
            dir,
            prefix: "",
        }
    }

    /// [`DryRunAlloc::new`] naming the files a sidecar's own allocator
    /// would write, which are never the application sandbox's.
    pub fn sidecar(dir: PathBuf) -> Self {
        Self {
            prefix: SIDECAR_PREFIX,
            ..Self::new(dir)
        }
    }

    fn bump(&mut self) -> io::Result<OsString> {
        self.next += 1;
        Ok(OsString::from(self.next.to_string()))
    }
}

impl FdAllocator for DryRunAlloc {
    fn data(&mut self, _content: &[u8]) -> io::Result<OsString> {
        self.bump()
    }
    fn file(&mut self, dest: &Path, _content: &[u8]) -> io::Result<OsString> {
        Ok(self.dir.join(data_name(self.prefix, dest)).into_os_string())
    }
    fn init_socket(&mut self) -> io::Result<OsString> {
        self.bump()
    }
    fn ready_pipe(&mut self) -> io::Result<OsString> {
        self.bump()
    }
    fn listener(&mut self) -> io::Result<OsString> {
        self.bump()
    }
    fn info_pipe(&mut self) -> io::Result<OsString> {
        self.bump()
    }
    fn block_pipe(&mut self) -> io::Result<OsString> {
        self.bump()
    }
}

pub fn network_of(services: &[Service]) -> Option<&NetworkConfig> {
    services.iter().find_map(|s| match s {
        Service::Network(cfg) => Some(cfg),
        _ => None,
    })
}

pub fn wayland_mode(services: &[Service]) -> Option<WaylandMode> {
    services.iter().find_map(|s| match s {
        Service::Wayland(mode) => Some(*mode),
        _ => None,
    })
}

/// The command to run: the CLI's if it gave one, else the config's.
pub fn resolve_command<'a>(
    inst: &'a Instance,
    command: Option<&'a [OsString]>,
) -> Result<&'a [OsString], ConfigError> {
    match command {
        Some(c) if !c.is_empty() => Ok(c),
        _ => inst
            .config
            .command
            .as_deref()
            .ok_or(ConfigError::MissingCommand),
    }
}

/// Complete bwrap argv (without the program name) for an instance; `command` replaces the
/// config's entirely. `ctty` says the sandbox's stdin is the slave of a pty bubbler allocated,
/// the only case in which the supervisor may claim it.
pub fn build_argv(
    env: &Env,
    inst: &Instance,
    command: Option<&[OsString]>,
    alloc: &mut dyn FdAllocator,
    ctty: bool,
) -> Result<Argv, PlanError> {
    build_argv_on(env, inst, command, alloc, ctty, &RealHost)
}

fn build_argv_on(
    env: &Env,
    inst: &Instance,
    command: Option<&[OsString]>,
    alloc: &mut dyn FdAllocator,
    ctty: bool,
    host: &dyn Host,
) -> Result<Argv, PlanError> {
    let (args, command) = build_args_on(env, inst, command, ctty, host)?;
    args.finish(command, alloc)
}

/// Every argument of an instance's argv with the node that produced it, fds numbered as
/// [`build_argv`] numbers them under `--dry-run`. Nothing is created.
pub fn explain(
    env: &Env,
    inst: &Instance,
    command: Option<&[OsString]>,
    ctty: bool,
) -> Result<Vec<Explained>, PlanError> {
    explain_on(env, inst, command, ctty, &RealHost)
}

fn explain_on(
    env: &Env,
    inst: &Instance,
    command: Option<&[OsString]>,
    ctty: bool,
    host: &dyn Host,
) -> Result<Vec<Explained>, PlanError> {
    let (args, command) = build_args_on(env, inst, command, ctty, host)?;
    let mut alloc = DryRunAlloc::new(instance_runtime_dir(env, &inst.name));
    args.finish_explained(command, &mut alloc)
}

// Nothing here asks the compositor: its answer decides only what the Wayland proxy connects
// to, which is the sidecar's argv.
pub fn build_args_on<'a>(
    env: &Env,
    inst: &'a Instance,
    command: Option<&'a [OsString]>,
    ctty: bool,
    host: &dyn Host,
) -> Result<(BwrapArgs, &'a [OsString]), PlanError> {
    let command = resolve_command(inst, command)?;
    let plan = dbus::plan(&inst.config.services, &inst.name);
    let instance_runtime = instance_runtime_dir(env, &inst.name);
    let wayland_plan =
        wayland_mode(&inst.config.services).map(|m| wayland::plan(m, &instance_runtime));
    // Before the services: `portals` binds the same file as the `flatpak-spawn` shim, so a missing
    // supervisor must fail before either.
    let init = init_bin::locate(env, host)?;
    let ctx = service::ServiceCtx {
        instance_runtime,
        dbus: plan.as_ref(),
        wayland: wayland_plan.as_ref(),
        init_bin: &init,
    };
    let mut args = BwrapArgs::baseline(env, &inst.home(), host);
    if inst.config.userns == Userns::Disable {
        args.tag(Origin::Userns);
        args.disable_userns();
    }
    if inst.config.etc == EtcMode::Host {
        args.tag(Origin::Etc);
        args.bind_host_etc(host);
    }
    if let Some(size) = inst.config.tmp {
        args.tag(Origin::Tmp);
        args.tmp_size(size.0);
    }
    if ctty {
        args.ctty();
    }
    // A portal call needs the published identity and an isolated `network` needs pasta, so either
    // grant makes the sandbox wait at startup.
    let waits = [
        inst.config
            .services
            .iter()
            .position(|s| matches!(s, Service::Portals { .. }))
            .filter(|_| plan.as_ref().is_some_and(|p| p.portals)),
        inst.config
            .services
            .iter()
            .position(|s| matches!(s, Service::Network(c) if c.is_isolated())),
    ];
    // One `--block-fd`: bwrap reads it once, and a second would wait on a pipe nothing closes.
    // The portal node is first, so it is the one named where both ask.
    if let Some(i) = waits.into_iter().flatten().next() {
        args.tag(Origin::Service(i));
        args.block_until_released();
    }
    args.tag(Origin::Seccomp);
    apply_seccomp(
        &mut args,
        seccomp::RuleSet::with(&inst.config.seccomp, inst.config.userns),
        env,
        &inst.name,
    )?;
    service::apply_all(&inst.config.services, env, &mut args, host, &ctx)?;
    service::apply_shares(
        &inst.config.services,
        &inst.config.shares,
        env,
        &mut args,
        host,
    )?;
    service::apply_env(&inst.config.env, &mut args)?;
    args.tag(Origin::Init);
    args.bind_init(&init);
    Ok((args, command))
}

// A profile asking for no filter, or whose `allow` list leaves nothing to deny, is honoured but
// never silently.
fn apply_seccomp(
    args: &mut BwrapArgs,
    set: Option<seccomp::RuleSet>,
    env: &Env,
    instance: &str,
) -> Result<(), PlanError> {
    let Some(set) = set else {
        eprintln!("bubbler: seccomp disabled for instance {instance}");
        return Ok(());
    };
    let Some(program) = seccomp::compile(&set, env.seccomp_log)? else {
        eprintln!("bubbler: seccomp has no rules left for instance {instance}");
        return Ok(());
    };
    args.add_seccomp(program.bytes, program.arches);
    Ok(())
}

/// Complete bwrap argv (without the program name) for the sidecar that creates one instance's
/// PipeWire security context. `alloc` keeps the read end of the pipe the holder reports on.
pub fn pw_context_argv(
    env: &Env,
    ctx: &pipewire::Context<'_>,
    host: &dyn Host,
    alloc: &mut dyn FdAllocator,
) -> Result<Argv, PlanError> {
    let report = alloc.ready_pipe().map_err(PlanError::Data)?;
    let init = init_bin::locate(env, host)?;
    let mut args = BwrapArgs::pw_context_baseline(
        &pipewire::host_socket(&env.runtime_dir),
        &pipewire::dir(ctx.instance_runtime),
        host,
    );
    // No instance `seccomp` node reaches here: an instance may relax its own filter, never the one
    // around the process holding its security context.
    args.tag(Origin::Seccomp);
    if let Some(program) = seccomp::compile(&seccomp::RuleSet::default_set(), env.seccomp_log)? {
        args.add_seccomp(program.bytes, program.arches);
    }
    args.tag(Origin::Command);
    // The supervisor binary again, under the name that selects its holder mode: `pw-container`
    // runs one word, and that word's basename alone chooses the mode.
    args.ro_bind(&init, Path::new(pipewire::HOLDER_INSIDE));
    // `pw-container` finds the daemon under this and the holder its report fd under the next;
    // nothing else survives the baseline's `--clearenv`.
    args.setenv(OsStr::new("XDG_RUNTIME_DIR"), env.runtime_dir.as_os_str());
    args.setenv(OsStr::new(pipewire::REPORT_FD), &report);
    let properties = pipewire::properties(ctx.instance, ctx.run_id, ctx.audio);
    args.finish_plain(&pipewire::command(&properties), alloc)
}

/// Complete bwrap argv (without the program name) for the sidecar serving one instance's
/// `pulseaudio` grant. It gets no readiness pipe: the socket appearing in the directory bound
/// as its `/tmp` is what says the server is up.
pub fn pw_pulse_argv(
    env: &Env,
    instance_runtime: &Path,
    host: &dyn Host,
    alloc: &mut dyn FdAllocator,
) -> Result<Argv, PlanError> {
    let mut args = BwrapArgs::pw_pulse_baseline(
        &pipewire::socket(instance_runtime),
        Path::new(pipewire::REMOTE_INSIDE),
        &pipewire::pulse_dir(instance_runtime),
        host,
    );
    // No instance `seccomp` node reaches here: the process serving a grant is not the
    // process the grant is for.
    args.tag(Origin::Seccomp);
    if let Some(program) = seccomp::compile(&seccomp::RuleSet::default_set(), env.seccomp_log)? {
        args.add_seccomp(program.bytes, program.arches);
    }
    args.tag(Origin::Command);
    // The bound `/tmp`: the session's runtime directory is not in this sandbox at all.
    args.setenv(OsStr::new("XDG_RUNTIME_DIR"), OsStr::new("/tmp"));
    args.setenv(
        OsStr::new("PIPEWIRE_REMOTE"),
        OsStr::new(pipewire::REMOTE_INSIDE),
    );
    // Replaces the whole config search path, so bubbler's copy is all this server can read.
    args.setenv(
        OsStr::new("PIPEWIRE_CONFIG_DIR"),
        OsStr::new(pipewire::PULSE_CONFIG_INSIDE),
    );
    args.finish_plain(&pipewire::pulse_command(), alloc)
}

/// Complete bwrap argv (without the program name) for an instance's D-Bus proxy sidecar.
/// `buses` are the granted host bus sockets, already type-checked; `alloc` keeps the read end
/// of the ready pipe.
pub fn proxy_argv(
    env: &Env,
    plan: &dbus::Plan,
    buses: dbus::HostBuses<'_>,
    dir: &Path,
    host: &dyn Host,
    alloc: &mut dyn FdAllocator,
) -> Result<Argv, PlanError> {
    let (args, command) = proxy_args(env, plan, buses, dir, host, alloc)?;
    let plain: Vec<OsString> = command.into_iter().map(|(arg, _)| arg).collect();
    args.finish_plain(&plain, alloc)
}

// `alloc` numbers the ready pipe first, which is where the sidecar's fd numbering starts.
pub fn proxy_args(
    env: &Env,
    plan: &dbus::Plan,
    buses: dbus::HostBuses<'_>,
    dir: &Path,
    host: &dyn Host,
    alloc: &mut dyn FdAllocator,
) -> Result<(BwrapArgs, Vec<(OsString, Origin)>), PlanError> {
    let ready = alloc.ready_pipe().map_err(PlanError::Data)?;
    let program = dbus::proxy_program(env);
    let command = dbus::proxy_command_nodes(&program, plan, buses, dir, env.dbus_log, &ready);
    let command: Vec<(OsString, Origin)> = command
        .into_iter()
        .map(|(arg, node)| (arg, node.map_or(Origin::Command, Origin::Service)))
        .collect();
    let mut args = BwrapArgs::proxy_baseline(
        buses.session,
        buses.system,
        buses.a11y,
        &dbus::socket_dir(dir),
        host,
    );
    // An instance may relax its own filter, never the one around the process holding its bus.
    args.tag(Origin::Seccomp);
    if let Some(program) = seccomp::compile(&seccomp::RuleSet::default_set(), env.seccomp_log)? {
        args.add_seccomp(program.bytes, program.arches);
    }
    // The proxy reads this to decide it talks for a sandboxed app; without `portals` it is only
    // the `[Application]` section.
    args.tag(Origin::Identity);
    args.ro_bind_data(plan.flatpak_info.clone(), Path::new(dbus::FLATPAK_INFO));
    // An overriding binary is not on the sandbox's `PATH`; the packaged proxy needs no bind.
    if env.proxy_override.is_some() {
        args.tag(Origin::Command);
        let program = service::require_file(host, "dbus", program)?;
        args.ro_bind(&program, &program);
    }
    Ok((args, command))
}

pub fn wayland_node(services: &[Service]) -> Option<usize> {
    services
        .iter()
        .position(|s| matches!(s, Service::Wayland(_)))
}

/// Complete bwrap argv (without the program name) for an instance's Wayland proxy sidecar.
/// `alloc` hands over the listening socket and keeps the read end of the ready pipe.
pub fn wl_proxy_argv(
    env: &Env,
    plan: &ProxyPlan,
    node: usize,
    host: &dyn Host,
    alloc: &mut dyn FdAllocator,
) -> Result<Argv, PlanError> {
    let (args, command) = wl_proxy_args(env, plan, node, host, alloc)?;
    let plain: Vec<OsString> = command.into_iter().map(|(arg, _)| arg).collect();
    args.finish_plain(&plain, alloc)
}

/// The Wayland sidecar's argv with what produced each argument, or `None` where no sandboxed
/// `wayland` is granted. Nothing is probed or started.
pub fn explain_wayland_proxy(
    env: &Env,
    inst: &Instance,
) -> Result<Option<Vec<Explained>>, PlanError> {
    let (Some(plan), Some(node)) = (
        wl_proxy_plan(env, inst),
        wayland_node(&inst.config.services),
    ) else {
        return Ok(None);
    };
    let mut alloc = DryRunAlloc::sidecar(instance_runtime_dir(env, &inst.name));
    let (args, command) = wl_proxy_args(env, &plan, node, &RealHost, &mut alloc)?;
    Ok(Some(args.finish_plain_explained(&command, &mut alloc)?))
}

/// The Wayland proxy plan an explanation of `inst` shows, or `None` without a sandboxed
/// `wayland`. The compositor is not asked, so this is the plan for one that implements
/// `wp_security_context_manager_v1`.
pub fn wl_proxy_plan(env: &Env, inst: &Instance) -> Option<ProxyPlan> {
    match wayland_mode(&inst.config.services) {
        Some(WaylandMode::Sandboxed { clipboard }) => Some(ProxyPlan::context(
            &instance_runtime_dir(env, &inst.name),
            clipboard,
        )),
        Some(WaylandMode::Host) | None => None,
    }
}

// `alloc` numbers the listening socket, then the ready pipe: the order the proxy's arguments
// name them in.
fn wl_proxy_args(
    env: &Env,
    plan: &ProxyPlan,
    node: usize,
    host: &dyn Host,
    alloc: &mut dyn FdAllocator,
) -> Result<(BwrapArgs, Vec<(OsString, Origin)>), PlanError> {
    let listen = alloc.listener().map_err(PlanError::Data)?;
    let ready = alloc.ready_pipe().map_err(PlanError::Data)?;
    let (program, found) = wayland::locate_proxy(env, host)?;
    let command: Vec<(OsString, Origin)> = plan
        .command_nodes(&program, node, &listen, &ready)
        .into_iter()
        .map(|(arg, node)| (arg, node.map_or(Origin::Command, Origin::Service)))
        .collect();
    let mut args = BwrapArgs::wl_proxy_baseline(&plan.upstream, host);
    // An instance may relax its own filter, never the one around its compositor connection.
    args.tag(Origin::Seccomp);
    if let Some(program) = seccomp::compile(&seccomp::RuleSet::default_set(), env.seccomp_log)? {
        args.add_seccomp(program.bytes, program.arches);
    }
    // The installed binary is under this sandbox's read-only `/usr`, where bwrap would refuse a
    // destination anyway; an override or a build tree's copy is bound in at its own path.
    if found != init_bin::Found::Installed {
        args.tag(Origin::Command);
        args.ro_bind(&program, &program);
    }
    Ok((args, command))
}

fn network_node(services: &[Service]) -> Option<usize> {
    services
        .iter()
        .position(|s| matches!(s, Service::Network(_)))
}

/// The egress proxy's program and arguments with what produced each, or `None` where no
/// `allow-host` is named. Not a bwrap argv: the proxy runs directly in the sandbox's
/// namespaces. Nothing is started; the readiness descriptor is named, not numbered.
pub fn explain_net_proxy(env: &Env, inst: &Instance) -> Result<Option<Vec<Explained>>, PlanError> {
    let (Some(cfg), Some(node)) = (
        network_of(&inst.config.services).filter(|c| !c.allow_hosts.is_empty()),
        network_node(&inst.config.services),
    ) else {
        return Ok(None);
    };
    // Probed like the sandbox's argv, which binds this path: an explanation naming a binary the
    // run could not find would describe a launch that fails.
    let (program, _) = network::net_proxy_program(env, &RealHost)?;
    let mut items = vec![Explained {
        origin: Origin::Command,
        args: vec![OsString::from(network::NET_PROXY_INSIDE)],
        note: Some(format!("bound read-only from {}", program.display())),
    }];
    let argv = network::net_proxy_argv(
        cfg,
        network::ProxyFds {
            ready: OsStr::new("<ready-fd>"),
            log: OsStr::new("2"),
        },
        env.net_proxy_log,
    );
    // One option and its value per line. Holds because every valued option comes first and the
    // bare `--log-tunnels` is appended last.
    items.extend(argv.chunks(2).map(|pair| Explained {
        origin: Origin::Service(node),
        args: pair.to_vec(),
        note: None,
    }));
    Ok(Some(items))
}

#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::disallowed_methods, reason = "tests write temp files")]
pub mod test_support {
    use super::*;

    /// A dry run's allocator pointed where a real run of the instance
    /// [`inst`] builds would write its generated files, so an argv built
    /// here and one built by the launcher itself name the same paths.
    pub fn dry(e: &Env) -> DryRunAlloc {
        DryRunAlloc::new(instance_runtime_dir(e, "t"))
    }

    /// An `Env` whose `$BUBBLER_INIT` points at a stand-in binary, so
    /// argv building does not depend on where the test binary lives.
    pub fn env(tmp: &Path) -> Env {
        let init = tmp.join("bubbler-init");
        std::fs::write(&init, b"").unwrap();
        Env {
            home: tmp.join("home"),
            data_home: tmp.join("data"),
            config_home: tmp.join("config"),
            config_dirs: Vec::new(),
            data_dirs: crate::env::DEFAULT_DATA_DIRS
                .iter()
                .map(PathBuf::from)
                .collect(),
            runtime_dir: tmp.join("run"),
            uid: 1000,
            gid: 1000,
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
            init_override: Some(init),
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

    pub fn inst(tmp: &Path, kdl: &str) -> Instance {
        Instance {
            name: "t".into(),
            dir: tmp.join("data/bubbler/instances/t"),
            config: crate::config::parse(kdl).unwrap(),
            config_version: Some(crate::instance::CONFIG_VERSION),
        }
    }

    pub fn strs(v: &[OsString]) -> Vec<String> {
        v.iter().map(|s| s.to_string_lossy().into_owned()).collect()
    }

    /// A host with everything the origin tests grant: the stand-in
    /// supervisor, a home to share and `/etc/resolv.conf` for `network`.
    pub fn share_host(tmp: &Path) -> crate::host::fake::FakeHost {
        let (file, dir, _) = crate::host::fake::types();
        crate::host::fake::FakeHost::default()
            .with(&tmp.join("bubbler-init").display().to_string(), file)
            .with(&tmp.join("home").display().to_string(), dir)
            .with(&tmp.join("home/Downloads").display().to_string(), dir)
            .with("/etc/resolv.conf", file)
    }

    pub fn explained(tmp: &Path, e: &Env, kdl: &str) -> Vec<Explained> {
        explain_on(e, &inst(tmp, kdl), None, false, &share_host(tmp)).unwrap()
    }

    /// The one line each origin owns, for an assertion that reads like the
    /// output does.
    pub fn line(items: &[Explained], origin: Origin) -> String {
        strs(
            &items
                .iter()
                .filter(|i| i.origin == origin)
                .flat_map(|i| i.args.clone())
                .collect::<Vec<_>>(),
        )
        .join(" ")
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods, reason = "tests write temp files")]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::bwrap::INIT_INSIDE;

    /// A host holding the stand-in supervisor binary and everything
    /// `gamepad hidraw=#true uinput=#true` looks for, so a device grant
    /// can be checked without the machine the tests run on having one.
    fn device_host(tmp: &Path) -> crate::host::fake::FakeHost {
        let (file, dir, _) = crate::host::fake::types();
        let mut host = crate::host::fake::FakeHost::default()
            .with(&tmp.join("bubbler-init").display().to_string(), file);
        for p in [
            "/dev/input",
            "/sys/class/input",
            "/sys/devices",
            "/sys/class/hidraw",
        ] {
            host = host.with(p, dir);
        }
        for p in ["/dev/hidraw0", "/dev/uinput"] {
            host = host.with(p, crate::host::fake::char_type());
        }
        host
    }

    fn device_argv(tmp: &Path, e: &Env, kdl: &str) -> Vec<String> {
        let argv = build_argv_on(
            e,
            &inst(tmp, kdl),
            None,
            &mut dry(e),
            false,
            &device_host(tmp),
        )
        .unwrap();
        strs(&argv)
    }

    #[test]
    fn an_explanation_flattens_back_to_the_argv_it_explains() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let kdl = "dbus\nportals\nnotify\nhome-share \"Downloads\"\nuserns \"disable\"\n\
                   env FOO=\"bar\"\ncommand \"true\"";
        let items = explained(tmp.path(), &e, kdl);
        let flat: Vec<OsString> = items.iter().flat_map(|i| i.args.clone()).collect();
        let argv = build_argv_on(
            &e,
            &inst(tmp.path(), kdl),
            None,
            &mut dry(&e),
            false,
            &share_host(tmp.path()),
        )
        .unwrap();
        assert_eq!(flat, argv.to_vec());
    }

    #[test]
    fn every_argument_is_attributed_to_the_node_that_asked_for_it() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let items = explained(
            tmp.path(),
            &e,
            "dbus\nportals\nnotify\nhome-share \"Downloads\"\nuserns \"disable\"\n\
             env FOO=\"bar\"\ncommand \"true\"",
        );
        let run = tmp.path().join("run");
        assert_eq!(
            line(&items, Origin::Service(0)),
            format!(
                "--ro-bind {run}/bubbler/t/bus {run}/bus \
                 --setenv DBUS_SESSION_BUS_ADDRESS unix:path={run}/bus",
                run = run.display()
            )
        );
        // The wait for the identity document belongs to the `portals`
        // node, next to the file that identity is written from — and so
        // does the `flatpak-spawn` shim that identity file calls for.
        assert_eq!(
            line(&items, Origin::Service(1)),
            format!(
                "--block-fd 4 --ro-bind {run}/bubbler/t/.flatpak-info /.flatpak-info \
                 --overlay-src /usr/bin --tmp-overlay /usr/bin \
                 --ro-bind {init} /usr/bin/flatpak-spawn --remount-ro /usr/bin",
                run = run.display(),
                init = tmp.path().join("bubbler-init").display()
            )
        );
        // `notify` is a rule for the proxy and nothing for bwrap.
        assert_eq!(line(&items, Origin::Service(2)), "");
        assert_eq!(
            line(&items, Origin::Service(3)),
            format!(
                "--ro-bind {home}/Downloads /home/bubbler/Downloads",
                home = tmp.path().join("home").display()
            )
        );
        assert_eq!(
            line(&items, Origin::Userns),
            "--unshare-user --disable-userns"
        );
        assert_eq!(line(&items, Origin::Seccomp), "--add-seccomp-fd 5");
        assert_eq!(line(&items, Origin::Env(0)), "--setenv FOO bar");
        assert_eq!(
            line(&items, Origin::Init),
            format!(
                "--ro-bind {init} /run/bubbler-init -- /run/bubbler-init --socket-fd 6",
                init = tmp.path().join("bubbler-init").display()
            )
        );
        assert_eq!(line(&items, Origin::Command), "-- true");
        // Nothing else is left over: what is not a grant is the baseline.
        let untagged: Vec<&Explained> = items
            .iter()
            .filter(|i| {
                !matches!(
                    i.origin,
                    Origin::Baseline
                        | Origin::Seccomp
                        | Origin::Userns
                        | Origin::Service(_)
                        | Origin::Env(_)
                        | Origin::Init
                        | Origin::Command
                )
            })
            .collect();
        assert!(untagged.is_empty(), "{untagged:?}");
    }

    /// The node replaces the value in place: one `--tmpfs /tmp`, still
    /// ahead of everything mounted under it, and the operation now
    /// belongs to the node that asked for it rather than to the baseline.
    #[test]
    fn a_tmp_node_replaces_the_cap_and_owns_the_operation() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let items = explained(tmp.path(), &e, "tmp size=\"64M\"\ncommand \"true\"");
        assert_eq!(line(&items, Origin::Tmp), "--size 67108864 --tmpfs /tmp");
        let flat = strs(
            &items
                .iter()
                .flat_map(|i| i.args.clone())
                .collect::<Vec<_>>(),
        );
        assert_eq!(flat.iter().filter(|a| *a == "/tmp").count(), 1, "{flat:?}");
        assert!(!flat.contains(&"2147483648".to_owned()), "{flat:?}");

        // Without the node the baseline keeps both the cap and the
        // operation.
        let items = explained(tmp.path(), &e, "command \"true\"");
        assert_eq!(line(&items, Origin::Tmp), "");
        assert!(
            strs(
                &items
                    .iter()
                    .flat_map(|i| i.args.clone())
                    .collect::<Vec<_>>()
            )
            .contains(&"2147483648".to_owned())
        );

        // And the explanation heads a group with the node as written.
        let cfg = crate::config::parse("tmp size=\"64M\"\ncommand \"true\"").unwrap();
        let items = explained(tmp.path(), &e, "tmp size=\"64M\"\ncommand \"true\"");
        let out = crate::explain::render(
            &items,
            &crate::explain::View {
                title: "bwrap",
                instance: "t",
                cfg: &cfg,
                source: crate::explain::Source {
                    file: "config.kdl",
                    lines: &crate::config::Lines::default(),
                },
                rules: &[],
                wl_proxy: None,
                audio_policy: "",
                own_cgroup: None,
                net_proxy_log: false,
                seccomp_log: false,
                proxy: false,
                full: false,
                bwrap: crate::version::Version::Known(0, 12, 0),
            },
        )
        .unwrap();
        assert!(
            out.iter().any(|l| l.starts_with("  tmp size=\"64M\"")),
            "{out:?}"
        );
    }

    /// A grant that finds nothing to bind on this host contributes no
    /// argument, and is still a group of the explanation rather than
    /// missing from it.
    #[test]
    fn a_grant_that_binds_nothing_here_is_still_explained() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        // `share_host` holds no `/dev/hidraw*` and no `/sys/class/hidraw`.
        let kdl = "hidraw\ncommand \"true\"";
        let items = explained(tmp.path(), &e, kdl);
        assert_eq!(line(&items, Origin::Service(0)), "");
        let cfg = crate::config::parse(kdl).unwrap();
        let lines = crate::config::node_lines(kdl).unwrap();
        let out = crate::explain::render(
            &items,
            &crate::explain::View {
                title: "bwrap",
                instance: "t",
                cfg: &cfg,
                source: crate::explain::Source {
                    file: "config.kdl",
                    lines: &lines,
                },
                rules: &[],
                wl_proxy: None,
                audio_policy: "",
                own_cgroup: None,
                net_proxy_log: false,
                seccomp_log: false,
                proxy: false,
                full: false,
                bwrap: crate::version::Version::Known(0, 12, 0),
            },
        )
        .unwrap();
        assert!(
            out.iter()
                .any(|l| l.starts_with("  hidraw ") && l.ends_with("0 arguments")),
            "{out:?}"
        );
    }

    /// `--share-net` is inserted into phase 1, far from the bind the same
    /// node contributes, and must still be attributed to that node.
    #[test]
    fn the_network_node_owns_the_share_net_it_inserts_into_phase_one() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let items = explained(
            tmp.path(),
            &e,
            "home-share \"Downloads\"\nnetwork \"host\"\ncommand \"true\"",
        );
        assert_eq!(
            line(&items, Origin::Service(1)),
            "--share-net --ro-bind /etc/resolv.conf /etc/resolv.conf"
        );
        let first = items.first().expect("the argv is never empty");
        assert_eq!(first.origin, Origin::Baseline);
        assert_eq!(first.args, [OsString::from("--unshare-all")]);
    }

    #[test]
    fn a_generated_fd_or_file_says_what_is_behind_it() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let items = explained(tmp.path(), &e, "command \"true\"");
        let note = |flag: &str| {
            items
                .iter()
                .find(|i| i.args[0] == flag)
                .and_then(|i| i.note.clone())
                .unwrap_or_else(|| panic!("no {flag} in {items:?}"))
        };
        assert_eq!(
            note("--info-fd"),
            "pipe: bwrap reports the sandbox pid on it"
        );
        assert!(
            note("--add-seccomp-fd").starts_with("filter, "),
            "{items:?}"
        );
        let generated = items
            .iter()
            .find_map(|i| i.note.clone().filter(|n| n.starts_with("generated file")));
        assert_eq!(generated.as_deref(), Some("generated file, 88 bytes"));
        assert_eq!(note("--"), "socket: the exec channel bubbler-init serves");
    }

    #[test]
    fn the_userns_node_reaches_the_namespace_phase() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let plain = device_argv(tmp.path(), &e, "command \"x\"");
        assert!(!plain.iter().any(|a| a == "--unshare-user"), "{plain:?}");
        assert!(!plain.iter().any(|a| a == "--disable-userns"), "{plain:?}");

        let a = device_argv(tmp.path(), &e, "userns \"disable\"\ncommand \"x\"");
        let at = a
            .iter()
            .position(|s| s == "--unshare-user")
            .unwrap_or_else(|| panic!("{a:?}"));
        assert_eq!(a[at + 1], "--disable-userns", "{a:?}");
        // Phase 1: ahead of the filesystem skeleton the baseline lays down.
        let skeleton = a
            .iter()
            .position(|s| s == "--ro-bind")
            .unwrap_or_else(|| panic!("{a:?}"));
        assert!(at < skeleton, "{a:?}");
    }

    #[test]
    fn gamepad_device_properties_reach_the_argv() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let bare = device_argv(tmp.path(), &e, "gamepad\ncommand \"x\"");
        assert!(!bare.iter().any(|a| a.contains("hidraw")), "{bare:?}");
        assert!(!bare.iter().any(|a| a.contains("uinput")), "{bare:?}");

        let a = device_argv(
            tmp.path(),
            &e,
            "gamepad hidraw=#true uinput=#true\ncommand \"x\"",
        );
        let has = |seq: &[&str]| a.windows(seq.len()).any(|w| w == seq);
        // The nodes are enumerated as the argv is built, so they are
        // bound with the `-try` form; `/dev/uinput` was asked for by name.
        assert!(
            has(&["--dev-bind-try", "/dev/hidraw0", "/dev/hidraw0"]),
            "{a:?}"
        );
        assert!(
            has(&["--ro-bind", "/sys/class/hidraw", "/sys/class/hidraw"]),
            "{a:?}"
        );
        assert!(has(&["--dev-bind", "/dev/uinput", "/dev/uinput"]), "{a:?}");
    }

    #[test]
    fn argv_uses_config_command_unless_overridden() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "command \"foot\" \"-e\" \"fish\"");
        let a = build_argv(&e, &i, None, &mut dry(&e), false).unwrap();
        assert_eq!(
            &a[a.len() - 4..],
            &[
                OsString::from("--"),
                "foot".into(),
                "-e".into(),
                "fish".into()
            ]
        );
        let a = build_argv(&e, &i, Some(&[OsString::from("ls")]), &mut dry(&e), false).unwrap();
        assert_eq!(&a[a.len() - 2..], &[OsString::from("--"), "ls".into()]);
    }

    #[test]
    fn the_init_binary_is_bound_and_wraps_the_command() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "command \"foot\"");
        let a = strs(&build_argv(&e, &i, None, &mut dry(&e), false).unwrap());
        let init = tmp.path().join("bubbler-init").display().to_string();
        assert!(
            a.windows(3)
                .any(|w| w == ["--ro-bind", init.as_str(), INIT_INSIDE])
        );
        // Fd 3 went to the info pipe, 4 to the seccomp filter; passwd
        // and group are files.
        assert_eq!(
            &a[a.len() - 6..],
            &["--", INIT_INSIDE, "--socket-fd", "5", "--", "foot"]
        );
    }

    #[test]
    fn a_missing_init_binary_is_a_missing_resource() {
        let tmp = tempfile::tempdir().unwrap();
        let mut e = env(tmp.path());
        e.init_override = Some(tmp.path().join("gone"));
        let i = inst(tmp.path(), "command \"foot\"");
        assert!(matches!(
            build_argv(&e, &i, None, &mut dry(&e), false),
            Err(PlanError::MissingResource {
                service: "init",
                ..
            })
        ));
    }

    #[test]
    fn config_env_pairs_reach_the_argv() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(
            tmp.path(),
            "env MOZ_ENABLE_WAYLAND=\"1\"\ncommand \"firefox\"",
        );
        let a = build_argv(&e, &i, None, &mut dry(&e), false).unwrap();
        let s = strs(&a);
        assert!(
            s.windows(3)
                .any(|w| w == ["--setenv", "MOZ_ENABLE_WAYLAND", "1"])
        );
    }

    #[test]
    fn no_command_anywhere_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "");
        assert!(matches!(
            build_argv(&e, &i, None, &mut dry(&e), false),
            Err(PlanError::Config(ConfigError::MissingCommand))
        ));
        assert!(matches!(
            build_argv(&e, &i, Some(&[]), &mut dry(&e), false),
            Err(PlanError::Config(ConfigError::MissingCommand))
        ));
    }

    /// Pinned: the sandbox the Wayland proxy runs in and the argv it is
    /// run with are the contract with `bubbler-wl-proxy`. Nothing of the
    /// session is in here but the socket it forwards to — the socket it
    /// accepts on arrives as descriptor 3 and is bound nowhere.
    #[test]
    fn wl_proxy_argv_runs_the_proxy_in_its_own_sandbox() {
        use crate::config::Clipboard;
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let dir = Path::new("/run/user/1000/bubbler/t");
        let plan = ProxyPlan::context(dir, Clipboard::Paste);
        // A host holding the packaged proxy and nothing else, so this is
        // the installed layout's argv and not this build tree's.
        let (file, _, _) = crate::host::fake::types();
        let host = FakeHost::default().with(wayland::PROXY_BIN, file);
        let argv = wl_proxy_argv(&e, &plan, 0, &host, &mut dry(&e)).unwrap();
        assert_eq!(
            strs(&argv),
            vec![
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--add-seccomp-fd",
                "5",
                "--ro-bind",
                "/usr",
                "/usr",
                "--symlink",
                "usr/bin",
                "/bin",
                "--symlink",
                "usr/lib",
                "/lib",
                "--symlink",
                "usr/lib64",
                "/lib64",
                "--symlink",
                "usr/bin",
                "/sbin",
                "--size",
                "67108864",
                "--tmpfs",
                "/etc",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--size",
                "67108864",
                "--tmpfs",
                "/tmp",
                "--ro-bind",
                "/run/user/1000/bubbler/t/wayland-context",
                "/run/user/1000/bubbler/t/wayland-context",
                "--clearenv",
                "--",
                "/usr/lib/bubbler/bubbler-wl-proxy",
                "--listen-fd",
                "3",
                "--upstream",
                "/run/user/1000/bubbler/t/wayland-context",
                "--gate",
                "paste",
                "--log-fd",
                "2",
                "--ready-fd",
                "4",
            ]
        );
    }

    /// Without a security context the proxy is pointed at the session's
    /// own socket — the only one it can then reach — and told to hide
    /// the privileged globals itself. `clipboard="open"` is the gate.
    #[test]
    fn the_fallback_proxy_dials_the_session_socket_and_denies() {
        use crate::config::Clipboard;
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let dir = Path::new("/run/user/1000/bubbler/t");
        let plan = ProxyPlan::fallback(dir, "/run/user/1000/wayland-1".into(), Clipboard::Open);
        let (file, _, _) = crate::host::fake::types();
        let host = FakeHost::default().with(wayland::PROXY_BIN, file);
        let argv = strs(&wl_proxy_argv(&e, &plan, 0, &host, &mut dry(&e)).unwrap());
        let tail: Vec<&str> = argv
            .iter()
            .skip_while(|a| *a != "--")
            .map(String::as_str)
            .collect();
        assert_eq!(
            tail,
            [
                "--",
                "/usr/lib/bubbler/bubbler-wl-proxy",
                "--listen-fd",
                "3",
                "--upstream",
                "/run/user/1000/wayland-1",
                "--gate",
                "open",
                "--fallback-deny",
                "--log-fd",
                "2",
                "--ready-fd",
                "4",
            ]
        );
        assert!(
            argv.windows(3).any(|w| w
                == [
                    "--ro-bind",
                    "/run/user/1000/wayland-1",
                    "/run/user/1000/wayland-1"
                ]),
            "{argv:?}"
        );
        // The security-context socket is never bound: there is none.
        assert!(
            !argv.iter().any(|a| a.ends_with("wayland-context")),
            "{argv:?}"
        );
    }

    /// An overriding binary is not under the `/usr` the sidecar has, so
    /// it is bound in at its own path, and a name that is not a file is
    /// refused rather than handed to bwrap.
    #[test]
    fn an_overridden_proxy_binary_is_bound_into_its_own_sandbox() {
        use crate::config::Clipboard;
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let mut e = env(tmp.path());
        e.wl_proxy_override = Some("/build/bubbler-wl-proxy".into());
        let plan = ProxyPlan::context(Path::new("/run/user/1000/bubbler/t"), Clipboard::Paste);
        let (file, _, _) = crate::host::fake::types();
        let host = FakeHost::default().with("/build/bubbler-wl-proxy", file);
        let argv = strs(&wl_proxy_argv(&e, &plan, 0, &host, &mut dry(&e)).unwrap());
        assert!(
            argv.windows(3).any(|w| w
                == [
                    "--ro-bind",
                    "/build/bubbler-wl-proxy",
                    "/build/bubbler-wl-proxy"
                ]),
            "{argv:?}"
        );
        assert!(argv.contains(&"/build/bubbler-wl-proxy".to_owned()));
        assert!(matches!(
            wl_proxy_argv(&e, &plan, 0, &FakeHost::default(), &mut dry(&e)),
            Err(PlanError::MissingResource {
                service: "wayland",
                ..
            })
        ));
    }

    #[test]
    fn pw_context_argv_runs_pw_container_in_its_own_sandbox() {
        use crate::config::AudioSet;
        use crate::host::fake::{FakeHost, types};
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let (file, _, _) = types();
        let host =
            FakeHost::default().with(&tmp.path().join("bubbler-init").display().to_string(), file);
        let dir = instance_runtime_dir(&e, "t");
        let ctx = pipewire::Context {
            instance_runtime: &dir,
            instance: "t",
            run_id: "4711",
            audio: AudioSet {
                microphone: false,
                devices: false,
                exclusive: false,
                capturable: false,
            },
        };
        let argv =
            pw_context_argv(&e, &ctx, &host, &mut DryRunAlloc::sidecar(dir.clone())).unwrap();
        let run = e.runtime_dir.display().to_string();
        assert_eq!(
            strs(&argv),
            vec![
                "--unshare-all".to_owned(),
                "--die-with-parent".to_owned(),
                "--new-session".to_owned(),
                "--add-seccomp-fd".to_owned(),
                "4".to_owned(),
                "--ro-bind".to_owned(),
                "/usr".to_owned(),
                "/usr".to_owned(),
                "--symlink".to_owned(),
                "usr/bin".to_owned(),
                "/bin".to_owned(),
                "--symlink".to_owned(),
                "usr/lib".to_owned(),
                "/lib".to_owned(),
                "--symlink".to_owned(),
                "usr/lib64".to_owned(),
                "/lib64".to_owned(),
                "--symlink".to_owned(),
                "usr/bin".to_owned(),
                "/sbin".to_owned(),
                "--size".to_owned(),
                "67108864".to_owned(),
                "--tmpfs".to_owned(),
                "/etc".to_owned(),
                "--proc".to_owned(),
                "/proc".to_owned(),
                "--dev".to_owned(),
                "/dev".to_owned(),
                "--size".to_owned(),
                "67108864".to_owned(),
                "--tmpfs".to_owned(),
                "/tmp".to_owned(),
                "--ro-bind".to_owned(),
                format!("{run}/pipewire-0"),
                format!("{run}/pipewire-0"),
                "--bind".to_owned(),
                format!("{run}/bubbler/t/pw"),
                "/tmp".to_owned(),
                "--ro-bind".to_owned(),
                tmp.path().join("bubbler-init").display().to_string(),
                "/run/bubbler-pw-hold".to_owned(),
                "--clearenv".to_owned(),
                "--setenv".to_owned(),
                "XDG_RUNTIME_DIR".to_owned(),
                run.clone(),
                "--setenv".to_owned(),
                "BUBBLER_PW_REPORT_FD".to_owned(),
                "3".to_owned(),
                "--".to_owned(),
                "/usr/bin/pw-container".to_owned(),
                "-P".to_owned(),
                r#"{"pipewire.sec.engine":"org.bubbler","pipewire.sec.app-id":"t","pipewire.sec.instance-id":"4711","pipewire.access":"restricted","pipewire.sec.bubbler.audio":"playback"}"#.to_owned(),
                "--".to_owned(),
                "/run/bubbler-pw-hold".to_owned(),
            ]
        );
    }

    /// The grant set is the one thing about the sidecar that a config
    /// changes, and it reaches the daemon as a context property.
    #[test]
    fn a_microphone_grant_says_so_in_the_context_properties() {
        use crate::config::AudioSet;
        use crate::host::fake::{FakeHost, types};
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let (file, _, _) = types();
        let host =
            FakeHost::default().with(&tmp.path().join("bubbler-init").display().to_string(), file);
        let dir = instance_runtime_dir(&e, "t");
        let ctx = pipewire::Context {
            instance_runtime: &dir,
            instance: "t",
            run_id: "4711",
            audio: AudioSet {
                microphone: true,
                devices: false,
                exclusive: false,
                capturable: false,
            },
        };
        let mut alloc = DryRunAlloc::sidecar(dir.clone());
        let argv = strs(&pw_context_argv(&e, &ctx, &host, &mut alloc).unwrap());
        assert!(
            argv.iter()
                .any(|a| a.contains(r#""pipewire.sec.bubbler.audio":"playback,microphone""#)),
            "{argv:?}"
        );
    }

    /// R4, pulse half: the private pulse server reaches this run's own
    /// security context and nothing else of the session — not the
    /// daemon's socket, not a home, not the network.
    #[test]
    fn pw_pulse_argv_runs_the_pulse_server_in_its_own_sandbox() {
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let dir = instance_runtime_dir(&e, "t");
        let argv = pw_pulse_argv(
            &e,
            &dir,
            &FakeHost::default(),
            &mut DryRunAlloc::sidecar(dir.clone()),
        )
        .unwrap();
        let run = e.runtime_dir.display().to_string();
        assert_eq!(
            strs(&argv),
            vec![
                "--unshare-all".to_owned(),
                "--die-with-parent".to_owned(),
                "--new-session".to_owned(),
                "--add-seccomp-fd".to_owned(),
                "3".to_owned(),
                "--ro-bind".to_owned(),
                "/usr".to_owned(),
                "/usr".to_owned(),
                "--symlink".to_owned(),
                "usr/bin".to_owned(),
                "/bin".to_owned(),
                "--symlink".to_owned(),
                "usr/lib".to_owned(),
                "/lib".to_owned(),
                "--symlink".to_owned(),
                "usr/lib64".to_owned(),
                "/lib64".to_owned(),
                "--symlink".to_owned(),
                "usr/bin".to_owned(),
                "/sbin".to_owned(),
                "--size".to_owned(),
                "67108864".to_owned(),
                "--tmpfs".to_owned(),
                "/etc".to_owned(),
                "--proc".to_owned(),
                "/proc".to_owned(),
                "--dev".to_owned(),
                "/dev".to_owned(),
                "--size".to_owned(),
                "67108864".to_owned(),
                "--tmpfs".to_owned(),
                "/tmp".to_owned(),
                "--ro-bind".to_owned(),
                format!("{run}/bubbler/t/pipewire-0"),
                "/run/pipewire-0".to_owned(),
                "--bind".to_owned(),
                format!("{run}/bubbler/t/pwpulse"),
                "/tmp".to_owned(),
                "--clearenv".to_owned(),
                "--setenv".to_owned(),
                "XDG_RUNTIME_DIR".to_owned(),
                "/tmp".to_owned(),
                "--setenv".to_owned(),
                "PIPEWIRE_REMOTE".to_owned(),
                "/run/pipewire-0".to_owned(),
                "--setenv".to_owned(),
                "PIPEWIRE_CONFIG_DIR".to_owned(),
                "/tmp/cfg".to_owned(),
                "--".to_owned(),
                "/usr/bin/pipewire".to_owned(),
                "-c".to_owned(),
                "pipewire-pulse.conf".to_owned(),
            ]
        );
    }

    #[test]
    fn proxy_argv_runs_the_proxy_in_its_own_sandbox() {
        use crate::config::Service;
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let plan = dbus::plan(&[Service::Dbus { rules: vec![] }, Service::Notify], "t")
            .expect("dbus is granted");
        let argv = proxy_argv(
            &e,
            &plan,
            dbus::HostBuses {
                session: Some(Path::new("/run/user/1000/bus")),
                system: None,
                a11y: None,
            },
            Path::new("/run/user/1000/bubbler/t"),
            &FakeHost::default(),
            &mut DryRunAlloc::sidecar(PathBuf::from("/run/user/1000/bubbler/t")),
        )
        .unwrap();
        assert_eq!(
            strs(&argv),
            vec![
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--add-seccomp-fd",
                "4",
                "--ro-bind",
                "/usr",
                "/usr",
                "--symlink",
                "usr/bin",
                "/bin",
                "--symlink",
                "usr/lib",
                "/lib",
                "--symlink",
                "usr/lib64",
                "/lib64",
                "--symlink",
                "usr/bin",
                "/sbin",
                "--size",
                "67108864",
                "--tmpfs",
                "/etc",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--size",
                "67108864",
                "--tmpfs",
                "/tmp",
                "--ro-bind",
                "/run/user/1000/bus",
                "/run/user/1000/bus",
                "--bind",
                "/run/user/1000/bubbler/t/dbus",
                "/run/user/1000/bubbler/t/dbus",
                "--ro-bind",
                "/run/user/1000/bubbler/t/proxy-.flatpak-info",
                "/.flatpak-info",
                "--clearenv",
                "--",
                "xdg-dbus-proxy",
                "--fd=3",
                "unix:path=/run/user/1000/bus",
                "/run/user/1000/bubbler/t/dbus/bus",
                "--filter",
                "--talk=org.freedesktop.Notifications",
            ]
        );
    }

    #[test]
    fn a_system_bus_proxy_sees_that_socket_and_no_session_one() {
        use crate::config::{BusRule, Service};
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let plan = dbus::plan(
            &[Service::SystemBus {
                rules: vec![BusRule::Talk("org.freedesktop.UPower".into())],
            }],
            "t",
        )
        .expect("system-bus is granted");
        let argv = strs(
            &proxy_argv(
                &e,
                &plan,
                dbus::HostBuses {
                    session: None,
                    system: Some(Path::new(dbus::SYSTEM_BUS_PATH)),
                    a11y: None,
                },
                Path::new("/run/user/1000/bubbler/t"),
                &FakeHost::default(),
                &mut dry(&e),
            )
            .unwrap(),
        );
        assert!(
            argv.windows(3).any(|w| w
                == [
                    "--ro-bind",
                    "/run/dbus/system_bus_socket",
                    "/run/dbus/system_bus_socket",
                ]),
            "{argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a == "/run/user/1000/bus"),
            "the proxy reaches a session bus nothing granted: {argv:?}"
        );
        assert_eq!(
            &argv[argv.len() - 6..],
            &[
                "xdg-dbus-proxy",
                "--fd=3",
                "unix:path=/run/dbus/system_bus_socket",
                "/run/user/1000/bubbler/t/dbus/system",
                "--filter",
                "--talk=org.freedesktop.UPower",
            ]
        );
    }

    #[test]
    fn both_buses_run_in_one_proxy_sandbox() {
        use crate::config::{BusRule, Service};
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let plan = dbus::plan(
            &[
                Service::Dbus { rules: vec![] },
                Service::SystemBus {
                    rules: vec![BusRule::Talk("org.freedesktop.UPower".into())],
                },
            ],
            "t",
        )
        .expect("both buses are granted");
        assert_eq!(
            plan.buses(),
            vec![
                (dbus::SESSION_SOCKET, dbus::SESSION_NODE),
                (dbus::SYSTEM_SOCKET, dbus::SYSTEM_NODE)
            ]
        );
        let argv = strs(
            &proxy_argv(
                &e,
                &plan,
                dbus::HostBuses {
                    session: Some(Path::new("/run/user/1000/bus")),
                    system: Some(Path::new(dbus::SYSTEM_BUS_PATH)),
                    a11y: None,
                },
                Path::new("/run/user/1000/bubbler/t"),
                &FakeHost::default(),
                &mut dry(&e),
            )
            .unwrap(),
        );
        // One sandbox, one process, two addresses: the second pair's
        // options apply to it alone (`xdg-dbus-proxy(1)`).
        assert_eq!(
            argv.iter().filter(|a| *a == "xdg-dbus-proxy").count(),
            1,
            "{argv:?}"
        );
        assert_eq!(
            &argv[argv.len() - 9..],
            &[
                "xdg-dbus-proxy",
                "--fd=3",
                "unix:path=/run/user/1000/bus",
                "/run/user/1000/bubbler/t/dbus/bus",
                "--filter",
                "unix:path=/run/dbus/system_bus_socket",
                "/run/user/1000/bubbler/t/dbus/system",
                "--filter",
                "--talk=org.freedesktop.UPower",
            ]
        );
        // Still the one writable path, whatever the bus count.
        assert_eq!(
            argv.iter().filter(|a| *a == "--bind").count(),
            1,
            "{argv:?}"
        );
    }

    /// The third bus of the one sidecar: its host socket in the proxy's
    /// sandbox, its address in the proxy's command, and the nine rules
    /// behind the `--filter` of that address.
    #[test]
    fn the_a11y_bus_is_the_third_bus_of_the_one_proxy() {
        use crate::config::{BusRule, Service};
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let plan = dbus::plan(
            &[
                Service::Dbus { rules: vec![] },
                Service::SystemBus {
                    rules: vec![BusRule::Talk("org.freedesktop.UPower".into())],
                },
                Service::A11y,
            ],
            "t",
        )
        .expect("three buses are granted");
        assert_eq!(
            plan.buses(),
            vec![
                (dbus::SESSION_SOCKET, dbus::SESSION_NODE),
                (dbus::SYSTEM_SOCKET, dbus::SYSTEM_NODE),
                (dbus::A11Y_SOCKET, dbus::A11Y_NODE),
            ]
        );
        let argv = strs(
            &proxy_argv(
                &e,
                &plan,
                dbus::HostBuses {
                    session: Some(Path::new("/run/user/1000/bus")),
                    system: Some(Path::new(dbus::SYSTEM_BUS_PATH)),
                    a11y: Some(Path::new("/run/user/1000/at-spi/bus_0")),
                },
                Path::new("/run/user/1000/bubbler/t"),
                &FakeHost::default(),
                &mut dry(&e),
            )
            .unwrap(),
        );
        assert!(
            argv.windows(3).any(|w| w
                == [
                    "--ro-bind",
                    "/run/user/1000/at-spi/bus_0",
                    "/run/user/1000/at-spi/bus_0",
                ]),
            "{argv:?}"
        );
        assert_eq!(
            argv.iter().filter(|a| *a == "xdg-dbus-proxy").count(),
            1,
            "{argv:?}"
        );
        let mut expected = vec![
            "unix:path=/run/user/1000/at-spi/bus_0",
            "/run/user/1000/bubbler/t/dbus/a11y",
            "--filter",
        ];
        expected.extend_from_slice(dbus::A11Y_RULES);
        assert_eq!(&argv[argv.len() - expected.len()..], expected, "{argv:?}");
        // Still the one writable path, whatever the bus count.
        assert_eq!(
            argv.iter().filter(|a| *a == "--bind").count(),
            1,
            "{argv:?}"
        );
    }

    /// The egress proxy's traffic log is off unless the variable asked
    /// for it, and the explanation shows the argv a run would use: a
    /// flag printed here and not passed there, or the other way round,
    /// would be an explanation of a different process.
    #[test]
    fn the_net_proxy_is_explained_with_the_traffic_log_only_when_asked() {
        let tmp = tempfile::tempdir().unwrap();
        let proxy = tmp.path().join("bubbler-net-proxy");
        std::fs::write(&proxy, b"").unwrap();
        let inst = inst(
            tmp.path(),
            "network {\n    outbound \"deny\"\n    allow-host \"api.example\"\n}\n",
        );
        let words = |log: bool| {
            let mut e = env(tmp.path());
            e.net_proxy_override = Some(proxy.clone());
            e.net_proxy_log = log;
            let items = explain_net_proxy(&e, &inst)
                .expect("the proxy binary is there")
                .expect("an `allow-host` starts one");
            strs(&items.into_iter().flat_map(|i| i.args).collect::<Vec<_>>())
        };
        assert!(!words(false).iter().any(|w| w == "--log-tunnels"));
        assert_eq!(
            words(true).last().map(String::as_str),
            Some("--log-tunnels")
        );
    }

    #[test]
    fn proxy_argv_logs_only_when_asked() {
        use crate::config::Service;
        use crate::host::fake::FakeHost;
        let tmp = tempfile::tempdir().unwrap();
        let mut e = env(tmp.path());
        e.dbus_log = true;
        let plan = dbus::plan(&[Service::Dbus { rules: vec![] }], "t").expect("dbus is granted");
        let argv = strs(
            &proxy_argv(
                &e,
                &plan,
                dbus::HostBuses {
                    session: Some(Path::new("/run/user/1000/bus")),
                    system: None,
                    a11y: None,
                },
                Path::new("/run/user/1000/bubbler/t"),
                &FakeHost::default(),
                &mut dry(&e),
            )
            .unwrap(),
        );
        assert_eq!(&argv[argv.len() - 2..], &["--filter", "--log"]);
    }

    #[test]
    fn an_overriding_proxy_binary_is_bound_in_and_run() {
        use crate::config::Service;
        use crate::host::fake::{FakeHost, types};
        let tmp = tempfile::tempdir().unwrap();
        let mut e = env(tmp.path());
        let fake = tmp.path().join("fake-proxy");
        e.proxy_override = Some(fake.clone());
        let plan = dbus::plan(&[Service::Dbus { rules: vec![] }], "t").expect("dbus is granted");
        let (file, _, _) = types();
        let host = FakeHost::default().with(&fake.to_string_lossy(), file);
        let argv = strs(
            &proxy_argv(
                &e,
                &plan,
                dbus::HostBuses {
                    session: Some(Path::new("/run/user/1000/bus")),
                    system: None,
                    a11y: None,
                },
                Path::new("/run/user/1000/bubbler/t"),
                &host,
                &mut dry(&e),
            )
            .unwrap(),
        );
        let fake = fake.display().to_string();
        assert!(
            argv.windows(3)
                .any(|w| w == ["--ro-bind", fake.as_str(), fake.as_str()]),
            "{argv:?}"
        );
        assert_eq!(argv[argv.len() - 6..argv.len() - 4], ["--", fake.as_str()]);
        // Nothing is bound for a binary that is not there to run.
        assert!(matches!(
            proxy_argv(
                &e,
                &plan,
                dbus::HostBuses {
                    session: Some(Path::new("/run/user/1000/bus")),
                    system: None,
                    a11y: None,
                },
                Path::new("/run/user/1000/bubbler/t"),
                &FakeHost::default(),
                &mut dry(&e),
            ),
            Err(PlanError::MissingResource {
                service: "dbus",
                ..
            })
        ));
    }

    #[test]
    fn a_dbus_instance_binds_the_proxied_socket_in_a_dry_run() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "dbus\nportals\ncommand \"x\"");
        let a = strs(&build_argv(&e, &i, None, &mut dry(&e), false).unwrap());
        let bus = tmp.path().join("run/bubbler/t/bus").display().to_string();
        let inside = tmp.path().join("run/bus").display().to_string();
        assert!(
            a.windows(3)
                .any(|w| w == ["--ro-bind", bus.as_str(), inside.as_str()]),
            "{a:?}"
        );
        assert!(
            a.windows(3).any(|w| w
                == [
                    "--setenv",
                    "DBUS_SESSION_BUS_ADDRESS",
                    format!("unix:path={inside}").as_str()
                ]),
            "{a:?}"
        );
        assert!(a.contains(&"/.flatpak-info".to_string()), "{a:?}");
    }

    #[test]
    fn only_a_portals_instance_waits_for_its_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "dbus\nportals\ncommand \"x\"");
        let a = strs(&build_argv(&e, &i, None, &mut dry(&e), false).unwrap());
        assert!(a.windows(2).any(|w| w == ["--block-fd", "4"]), "{a:?}");
        for kdl in ["dbus\ncommand \"x\"", "command \"x\""] {
            let i = inst(tmp.path(), kdl);
            let a = strs(&build_argv(&e, &i, None, &mut dry(&e), false).unwrap());
            assert!(!a.contains(&"--block-fd".to_string()), "{kdl}: {a:?}");
        }
    }

    #[test]
    fn dry_run_alloc_numbers_every_fd_from_three() {
        let mut alloc = DryRunAlloc::new(PathBuf::from("/run/user/1000/bubbler/t"));
        assert_eq!(alloc.data(b"a").unwrap(), OsString::from("3"));
        assert_eq!(alloc.data(b"b").unwrap(), OsString::from("4"));
        assert_eq!(alloc.init_socket().unwrap(), OsString::from("5"));
        assert_eq!(alloc.ready_pipe().unwrap(), OsString::from("6"));
        assert_eq!(alloc.info_pipe().unwrap(), OsString::from("7"));
        assert_eq!(alloc.block_pipe().unwrap(), OsString::from("8"));
    }

    #[test]
    fn the_default_denylist_reaches_the_argv_as_one_seccomp_fd() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "command \"foot\"");
        let a = strs(&build_argv(&e, &i, None, &mut dry(&e), false).unwrap());
        // Straight after the info fd, and before the filesystem phase.
        assert_eq!(
            &a[7..12],
            &["--info-fd", "3", "--add-seccomp-fd", "4", "--ro-bind"],
            "{a:?}"
        );
        assert_eq!(
            &a[a.len() - 6..],
            &["--", INIT_INSIDE, "--socket-fd", "5", "--", "foot"]
        );
    }

    #[test]
    fn a_disabled_filter_leaves_the_argv_without_one() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(tmp.path(), "seccomp { disable }\ncommand \"foot\"");
        let a = strs(&build_argv(&e, &i, None, &mut dry(&e), false).unwrap());
        assert!(!a.iter().any(|x| x == "--add-seccomp-fd"), "{a:?}");
    }

    #[test]
    fn allowing_every_denied_syscall_leaves_no_program_to_load() {
        use crate::seccomp::{RuleSet, syscall_number};
        // A name no architecture in the filter has is a config error, so
        // only the ones it does can be allowed back. The numbered rules
        // of `enosys_numbered` have no such name at all, but config.rs
        // knows them by a second table, so they can still be named here.
        let set = RuleSet::default_set();
        let names: Vec<String> = set
            .eperm
            .iter()
            .chain(&set.enosys)
            .filter(|n| syscall_number(n).is_some())
            .map(|n| format!("\"{n}\""))
            .chain(
                set.enosys_numbered
                    .iter()
                    .map(|(n, _, _)| format!("\"{n}\"")),
            )
            .collect();
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let i = inst(
            tmp.path(),
            &format!(
                "seccomp {{ allow \"ioctl\" {} }}\ncommand \"foot\"",
                names.join(" ")
            ),
        );
        let a = strs(&build_argv(&e, &i, None, &mut dry(&e), false).unwrap());
        assert!(!a.iter().any(|x| x == "--add-seccomp-fd"), "{a:?}");
    }

    /// The sweep runs over the very operations a launch is built from, so
    /// a home-share whose destination sits behind a planted link is
    /// refused with the argv the run would have used.
    #[test]
    fn a_built_argv_with_a_planted_destination_is_refused_before_the_spawn() {
        let tmp = tempfile::tempdir().unwrap();
        let e = env(tmp.path());
        let items = explained(tmp.path(), &e, "home-share \"Downloads\"\ncommand \"true\"");
        let home = tmp.path().join("data/bubbler/instances/t/home");

        let clean = share_host(tmp.path());
        assert!(crate::service::sweep_destinations(&items, &e, &clean).is_ok());

        let planted = share_host(tmp.path()).link(
            &home.join("Downloads").display().to_string(),
            "/oldroot/home/user/.config",
        );
        let err = crate::service::sweep_destinations(&items, &e, &planted).unwrap_err();
        assert!(
            err.to_string()
                .contains("/home/bubbler/Downloads is a symlink"),
            "{err}"
        );
    }
}
