//! The network sidecars of an isolated run: the `nft` ruleset, pasta and the egress proxy.

use std::ffi::{OsStr, OsString, c_void};
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::fs::{Mode, OFlags};
use rustix::io::{FdFlags, fcntl_setfd};
use rustix::ioctl::{self, Opcode};
use rustix::process::{
    DumpableBehavior, Pid, Signal, kill_process, set_dumpable_behavior,
    set_parent_process_death_signal,
};
use rustix::thread::{
    CapabilitiesSecureBits, CapabilitySet, CapabilitySets, LinkNameSpaceType, capabilities,
    clear_ambient_capability_set, configure_capability_in_ambient_set, move_into_link_name_space,
    set_capabilities, set_capabilities_secure_bits, set_no_new_privs,
};

use crate::config::NetworkConfig;
use crate::env::Env;
use crate::launch_error::{LaunchError, NET_PROXY_READY, NFT_TIMEOUT, NetworkError};
use crate::{cgroup, network, run_log, tty_relay};
use bubbler_plan::plan_error::PlanError;

use super::POLL;
use super::alloc::spawning;
use super::dbus_proxy::{still_running, wait_ready};
use super::runtime_dir::decimal;
use super::spawn::on_path;

const PASTA_READY: Duration = Duration::from_secs(5);

const PASTA_STOP: Duration = Duration::from_secs(1);

const NET_PROXY_STOP: Duration = Duration::from_secs(5);

// The sandbox's namespace is connected to the outside exactly as long as this lives.
#[derive(Debug)]
struct PastaHandle {
    child: Child,
    // Set once reaped: the notice appears once and the pid is never signalled after.
    exited: bool,
    _stderr: run_log::Relay,
}

impl PastaHandle {
    // The sandbox keeps running, unconnected. The relay's warning channel, not `eprintln!`: one
    // blocking terminal write would park the loop answering the exit check and the signals.
    fn check(&mut self, warn: &tty_relay::Warn) {
        if self.exited {
            return;
        }
        let Ok(Some(status)) = self.child.try_wait() else {
            return;
        };
        self.exited = true;
        warn.say(&format!(
            "bubbler: warning: pasta exited ({status}); the sandbox has lost its network\n"
        ));
    }
}

impl Drop for PastaHandle {
    // pasta quits with its namespace (`pasta(1)`; no `--no-netns-quit`), but a sidecar with a
    // route out is not left to a condition bubbler does not control.
    fn drop(&mut self) {
        if self.exited || !still_running(&mut self.child) {
            return;
        }
        if let Some(pid) = i32::try_from(self.child.id()).ok().and_then(Pid::from_raw) {
            let _ = kill_process(pid, Signal::TERM);
        }
        let deadline = Instant::now() + PASTA_STOP;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => {}
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                break;
            }
            std::thread::sleep(POLL);
        }
    }
}

// Compared by nsfs device and inode (`namespaces(7)`), on the descriptor already held:
// resolving `/proc/<pid>/ns/net` again could land on a reused pid's namespace.
fn same_namespace(held: BorrowedFd<'_>, path: &Path) -> Result<bool, LaunchError> {
    let theirs =
        rustix::fs::stat(path).map_err(|e| LaunchError::Io(path.to_path_buf(), e.into()))?;
    let ours = rustix::fs::fstat(held).map_err(|e| LaunchError::Data(e.into()))?;
    Ok((ours.st_dev, ours.st_ino) == (theirs.st_dev, theirs.st_ino))
}

// `_IO(0xb7, 0x1)` from `linux/nsfs.h`: returns a descriptor for the owning user namespace
// (`ioctl_ns(2)`).
const NS_GET_USERNS: Opcode = ioctl::opcode::none(0xb7, 0x1);

// Neither `NoArg` nor `Getter` fits: the descriptor is the return value, which `NoArg` drops
// and `Getter` would read from a buffer the kernel never writes.
struct NsGetUserns;

// SAFETY: `NS_GET_USERNS` takes no argument and writes nothing into
// userspace — hence the null pointer and `IS_MUTATING = false` — and on
// success its return value is a newly opened descriptor, which is what
// `output_from_ptr` makes of it.
unsafe impl ioctl::Ioctl for NsGetUserns {
    type Output = OwnedFd;

    const IS_MUTATING: bool = false;

    fn opcode(&self) -> Opcode {
        NS_GET_USERNS
    }

    fn as_ptr(&mut self) -> *mut c_void {
        std::ptr::null_mut()
    }

    unsafe fn output_from_ptr(
        out: ioctl::IoctlOutput,
        _: *mut c_void,
    ) -> rustix::io::Result<Self::Output> {
        // SAFETY: the caller hands over the return value of an `ioctl`
        // that succeeded, which for this opcode is a descriptor the
        // kernel has just opened and nothing else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(out) })
    }
}

// Asked of the netns, not a pid: bwrap moves the sandbox into a nested user namespace after
// reporting `child-pid`, while a netns's owner is fixed at creation (`ioctl_ns(2)`).
fn owning_userns(netns: BorrowedFd<'_>) -> rustix::io::Result<OwnedFd> {
    // SAFETY: `NsGetUserns` describes what `NS_GET_USERNS` does, and it
    // is made on a descriptor of an nsfs file, which is what `netns` is.
    unsafe { ioctl::ioctl(netns, NsGetUserns) }
}

// Held open across the ruleset and pasta spawns, so the pid cannot be reused under them.
struct SandboxNs {
    net: OwnedFd,
    // Where a process holds the capabilities to configure `net`.
    user: OwnedFd,
    // Joined by the egress proxy, so it resolves through the sandbox's `resolv.conf` and sees only
    // its filesystem; owned like `net`, so the join costs no further capability.
    mnt: OwnedFd,
}

// The pid may have been reused since bwrap reported it: one not in a namespace of its own is
// not the sandbox, and `nft` and pasta would act on the host's network.
fn sandbox_namespaces(child_pid: i32) -> Result<SandboxNs, LaunchError> {
    let net_path = PathBuf::from(format!("/proc/{child_pid}/ns/net"));
    let net = rustix::fs::open(&net_path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|e| LaunchError::Io(net_path.clone(), e.into()))?;
    if same_namespace(net.as_fd(), Path::new("/proc/self/ns/net"))? {
        return Err(NetworkError::PidReusedNet.into());
    }
    let user = owning_userns(net.as_fd()).map_err(|e| LaunchError::Io(net_path, e.into()))?;
    let mnt_path = PathBuf::from(format!("/proc/{child_pid}/ns/mnt"));
    let mnt = rustix::fs::open(&mnt_path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|e| LaunchError::Io(mnt_path, e.into()))?;
    // Checked apart: a pid reused between the two `open`s would join the proxy to a stranger's
    // mount namespace and the sandbox's network namespace.
    if same_namespace(mnt.as_fd(), Path::new("/proc/self/ns/mnt"))? {
        return Err(NetworkError::PidReusedMnt.into());
    }
    Ok(SandboxNs { net, user, mnt })
}

// `nft` is spawned, not linked: a library means `libnftnl` or `bindgen` for a stable text
// format. `cgroup` must exist already: nftables stores the id the path resolves to, so a
// cgroup made after this would be matched by nothing.
fn install_rules(
    cfg: &NetworkConfig,
    ns: &SandboxNs,
    cgroup: Option<&network::Cgroup>,
    stop: &AtomicBool,
) -> Result<(), LaunchError> {
    let Some(text) = network::ruleset(cfg, cgroup) else {
        // Nothing to install where nothing is filtered; a filtered run whose ruleset could not be
        // written must not get the whole network.
        if cfg.outbound == network::Outbound::Deny && cfg.is_isolated() {
            return Err(LaunchError::Plan(PlanError::BadValue {
                service: "network",
                reason: "the ruleset an `allow-host` needs is written around the \
                         egress proxy's own cgroup, and none was made for this run"
                    .to_owned(),
            }));
        }
        return Ok(());
    };
    let (user, net) = (ns.user.as_raw_fd(), ns.net.as_raw_fd());
    let mut cmd = Command::new(network::NFT_BIN);
    cmd.arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        // `nft`'s own diagnostics go where bubbler's do, never to the
        // caller's stdout: that is the argv audit trail.
        .stderr(Stdio::inherit());
    // SAFETY: the closure runs in the forked child between `fork` and
    // `execve`, where only async-signal-safe calls are allowed. Every
    // call in it is one syscall through rustix and allocates nothing:
    // `setns` twice, `capget`/`capset`, and `prctl` twice. The two
    // descriptors are valid there because `fork` copies the descriptor
    // table and the parent holds `ns` open across the spawn, so
    // `borrow_raw` borrows descriptors nothing has closed.
    //
    // User namespace first: entering the netns takes the capabilities it grants (`setns(2)`).
    // Ambient CAP_NET_ADMIN and a locked `SECBIT_NOROOT` leave `nft` that one capability.
    unsafe {
        cmd.pre_exec(move || {
            let user = BorrowedFd::borrow_raw(user);
            let net = BorrowedFd::borrow_raw(net);
            move_into_link_name_space(user, Some(LinkNameSpaceType::User))?;
            move_into_link_name_space(net, Some(LinkNameSpaceType::Network))?;
            let mut caps = capabilities(None)?;
            caps.inheritable |= CapabilitySet::NET_ADMIN;
            set_capabilities(None, caps)?;
            configure_capability_in_ambient_set(CapabilitySet::NET_ADMIN, true)?;
            set_capabilities_secure_bits(
                CapabilitiesSecureBits::NO_ROOT | CapabilitiesSecureBits::NO_ROOT_LOCKED,
            )?;
            Ok(())
        });
    }
    // Nothing above stdio: the namespaces are entered before the exec and
    // the ruleset arrives on a pipe this spawn makes for itself.
    spawning(&[])?;
    let mut child = cmd.spawn().map_err(|e| match e.kind() {
        // Only a really missing `nft` names the package: a failed `pre_exec` is a spawn failure
        // too.
        io::ErrorKind::NotFound if on_path(network::NFT_BIN).is_none() => {
            LaunchError::Plan(PlanError::BadValue {
                service: "network",
                reason: format!(
                    "`{}` is not on PATH; install the `nftables` package, or drop \
                 `outbound \"deny\"` to leave the sandbox network unfiltered",
                    network::NFT_BIN
                ),
            })
        }
        _ => NetworkError::NftStart(e).into(),
    })?;
    let mut stdin = child
        .stdin
        .take()
        .expect("stdin is piped, so the child always has one");
    let written = stdin.write_all(text.as_bytes());
    // Closed before the wait, or `nft` reads forever. The write has no deadline: a hang there
    // leaves the sandbox held at `--block-fd`, never started rather than unfiltered.
    drop(stdin);
    let deadline = Instant::now() + NFT_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Err(e) => return Err(NetworkError::NftWait(e).into()),
            Ok(None) => {}
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(POLL);
    };
    // A sidecar holding CAP_NET_ADMIN over the sandbox's namespaces is
    // not left running because it stopped answering.
    let Some(status) = status else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(NetworkError::NftTimeout.into());
    };
    // A Ctrl-C reaches `nft` too, in bubbler's process group: killed by
    // a signal while a stop is pending, it is the stop's doing.
    if status.signal().is_some() && stop.load(Ordering::SeqCst) {
        return Err(LaunchError::Stopped);
    }
    if !status.success() {
        return Err(NetworkError::NftRefused(status).into());
    }
    written.map_err(NetworkError::NftWrite)?;
    Ok(())
}

// The sandbox must still be held at `--block-fd`. pasta goes non-dumpable while starting, so
// its paths name bubbler's `/proc/self/fd`, and both descriptors stay open across the spawn.
fn start_pasta(
    env: &Env,
    cfg: &NetworkConfig,
    child_pid: i32,
    ns: &SandboxNs,
    stop: &AtomicBool,
) -> Result<PastaHandle, LaunchError> {
    let userns = &ns.user;
    let (ready, done) = rustix::pipe::pipe().map_err(|e| LaunchError::Data(e.into()))?;
    for fd in [&ready, &done] {
        fcntl_setfd(fd, FdFlags::CLOEXEC).map_err(|e| LaunchError::Data(e.into()))?;
    }
    let me = std::process::id();
    let argv = network::pasta_argv(
        cfg,
        network::Attach {
            userns: &OsString::from(format!("/proc/{me}/fd/{}", userns.as_raw_fd())),
            ready: &OsString::from(format!("/proc/{me}/fd/{}", done.as_raw_fd())),
            child: &OsString::from(child_pid.to_string()),
        },
    );
    // Nothing above stdio: pasta opens both descriptors through bubbler's `/proc` entry.
    spawning(&[])?;
    // pasta's stdout and stderr go where bubbler's messages do: never to the caller's stdout (the
    // argv audit trail), nor as the caller's own descriptor.
    let (log, stderr) = run_log::relay()?;
    let log_too = log.try_clone().map_err(LaunchError::Data)?;
    let missing = || {
        LaunchError::Plan(PlanError::BadValue {
            service: "network",
            reason: format!(
                "`{}` is not on PATH; install the `passt` package, or write \
             `network \"host\"` to use the host network namespace",
                network::PASTA_BIN
            ),
        })
    };
    let program = match &env.pasta_override {
        Some(path) => path.clone(),
        // Looked up here, so the forked child `execve`s a path rather than
        // walking `PATH` after `fork`.
        None => on_path(network::PASTA_BIN).ok_or_else(missing)?,
    };
    let mut cmd = Command::new(program);
    cmd.args(&argv)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_too));
    // SAFETY: the closure runs in the forked child between `fork` and
    // `execve`; `setsid` is one syscall that allocates nothing, so it is
    // async-signal-safe. In a session of its own pasta has no controlling
    // terminal, so it cannot open `/dev/tty` and reach the caller's.
    unsafe {
        cmd.pre_exec(|| {
            rustix::process::setsid()?;
            Ok(())
        });
    }
    let child = cmd.spawn().map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => missing(),
        _ => LaunchError::Spawn(e),
    })?;
    let mut handle = PastaHandle {
        child,
        exited: false,
        _stderr: stderr,
    };
    if !wait_ready(
        &ready,
        &mut handle.child,
        Instant::now() + PASTA_READY,
        stop,
    )? {
        return Err(NetworkError::PastaNotReady.into());
    }
    Ok(handle)
}

// Dropped, which stops the proxy, before the run's cgroup guard: a cgroup holding a process
// cannot be removed.
#[derive(Debug)]
struct NetProxyHandle {
    child: Child,
    // Set once reaped: the notice appears once and the pid is never signalled after.
    exited: bool,
    _stderr: run_log::Relay,
}

impl NetProxyHandle {
    // The sandbox keeps running: its filter is unchanged, it only loses its one way out.
    fn check(&mut self, warn: &tty_relay::Warn) {
        if self.exited {
            return;
        }
        let Ok(Some(status)) = self.child.try_wait() else {
            return;
        };
        self.exited = true;
        warn.say(&format!(
            "bubbler: warning: the egress proxy exited ({status}); the sandbox can reach \
             none of its `allow-host` names\n"
        ));
    }
}

impl Drop for NetProxyHandle {
    // `PR_SET_PDEATHSIG` covers only bubbler dying; a normal end must not leave a process in the
    // sandbox's namespaces, and the cgroup cannot be removed while one is there.
    fn drop(&mut self) {
        if self.exited || !still_running(&mut self.child) {
            return;
        }
        if let Some(pid) = i32::try_from(self.child.id()).ok().and_then(Pid::from_raw) {
            let _ = kill_process(pid, Signal::TERM);
        }
        let deadline = Instant::now() + NET_PROXY_STOP;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => {}
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                break;
            }
            std::thread::sleep(POLL);
        }
    }
}

pub(super) struct NetworkSidecars {
    pasta: PastaHandle,
    proxy: Option<NetProxyHandle>,
}

impl NetworkSidecars {
    pub(super) fn check(&mut self, warn: &tty_relay::Warn) {
        self.pasta.check(warn);
        if let Some(proxy) = self.proxy.as_mut() {
            proxy.check(warn);
        }
    }
}

// The order is the safety: cgroup before bwrap, ruleset before pasta, proxy listening before
// the release, so the sandbox is never connected and unfiltered, nor reaching a silent proxy.
pub(super) fn start_network(
    env: &Env,
    cfg: &NetworkConfig,
    child_pid: i32,
    cgroup: Option<&cgroup::SandboxCgroup>,
    stop: &AtomicBool,
) -> Result<NetworkSidecars, LaunchError> {
    let ns = sandbox_namespaces(child_pid)?;
    install_rules(cfg, &ns, cgroup.map(cgroup::SandboxCgroup::spec), stop)?;
    let pasta = start_pasta(env, cfg, child_pid, &ns, stop)?;
    let proxy = cgroup
        .map(|cgroup| start_net_proxy(cfg, &ns, cgroup, env.net_proxy_log, stop))
        .transpose()?;
    Ok(NetworkSidecars { pasta, proxy })
}

// Exec'd from `network::NET_PROXY_INSIDE`: after the mount join a host path resolves to
// nothing. Only refusals are logged unless `log_tunnels`: its lines land on the app's terminal.
fn start_net_proxy(
    cfg: &NetworkConfig,
    ns: &SandboxNs,
    cgroup: &cgroup::SandboxCgroup,
    log_tunnels: bool,
    stop: &AtomicBool,
) -> Result<NetProxyHandle, LaunchError> {
    let (ready, done) = rustix::pipe::pipe().map_err(|e| LaunchError::Data(e.into()))?;
    fcntl_setfd(&ready, FdFlags::CLOEXEC).map_err(|e| LaunchError::Data(e.into()))?;
    // The write end is the one descriptor this spawn hands over, so it
    // is the one exception to the sweep below.
    fcntl_setfd(&done, FdFlags::empty()).map_err(|e| LaunchError::Data(e.into()))?;
    let argv = network::net_proxy_argv(
        cfg,
        network::ProxyFds {
            ready: &OsString::from(done.as_raw_fd().to_string()),
            log: OsStr::new("2"),
        },
        log_tunnels,
    );
    let (log, stderr) = run_log::relay()?;
    let mut cmd = Command::new(network::NET_PROXY_INSIDE);
    cmd.args(&argv)
        // The proxy reads none of the host's environment, and every variable would cross into the
        // sandbox's namespaces.
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log);
    let procs = cgroup.procs().as_raw_fd();
    let (user, net, mnt) = (ns.user.as_raw_fd(), ns.net.as_raw_fd(), ns.mnt.as_raw_fd());
    // SAFETY: the closure runs in the forked child between `fork` and
    // `execve`, where only async-signal-safe calls are allowed. Every
    // call in it is one syscall through rustix and allocates nothing —
    // the pid is formatted into a stack buffer and `chdir` is handed a
    // C string literal. The four descriptors are valid there because
    // `fork` copies the descriptor table and the parent holds the
    // cgroup handle and `ns` open across the spawn, so `borrow_raw`
    // borrows descriptors nothing has closed.
    //
    // The order is the manual's ("The proxy process").
    unsafe {
        cmd.pre_exec(move || {
            rustix::process::setsid()?;
            let procs = BorrowedFd::borrow_raw(procs);
            let mut buf = [0u8; 10];
            rustix::io::write(
                procs,
                decimal(rustix::process::getpid().as_raw_nonzero().get(), &mut buf),
            )?;
            let user = BorrowedFd::borrow_raw(user);
            let net = BorrowedFd::borrow_raw(net);
            let mnt = BorrowedFd::borrow_raw(mnt);
            move_into_link_name_space(user, Some(LinkNameSpaceType::User))?;
            move_into_link_name_space(net, Some(LinkNameSpaceType::Network))?;
            move_into_link_name_space(mnt, Some(LinkNameSpaceType::Mount))?;
            rustix::process::chdir(c"/")?;
            set_capabilities_secure_bits(
                CapabilitiesSecureBits::NO_ROOT | CapabilitiesSecureBits::NO_ROOT_LOCKED,
            )?;
            clear_ambient_capability_set()?;
            set_capabilities(
                None,
                CapabilitySets {
                    effective: CapabilitySet::empty(),
                    permitted: CapabilitySet::empty(),
                    inheritable: CapabilitySet::empty(),
                },
            )?;
            set_no_new_privs(true)?;
            set_parent_process_death_signal(Some(Signal::TERM))?;
            set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
            Ok(())
        });
    }
    spawning(&[done.as_raw_fd()])?;
    // Never `LaunchError::Spawn`, which names bwrap: a failed `pre_exec` step arrives as a failed
    // spawn too, and its `NotFound` is not a missing binary.
    let spawned = cmd.spawn();
    // `cmd` holds bubbler's copy of the relay's write end; the relay only
    // sees the end of the output once that copy is gone.
    drop(cmd);
    let child = spawned.map_err(NetworkError::ProxyStart)?;
    let mut handle = NetProxyHandle {
        child,
        exited: false,
        _stderr: stderr,
    };
    // bubbler's own copy of the write end goes now, so a proxy that dies
    // without writing gives the wait below an EOF instead of a deadline.
    drop(done);
    if !wait_ready(
        &ready,
        &mut handle.child,
        Instant::now() + NET_PROXY_READY,
        stop,
    )? {
        return Err(match handle.child.try_wait() {
            Ok(Some(status)) => NetworkError::ProxyExited(status),
            _ => NetworkError::ProxySilent,
        }
        .into());
    }
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::BufRead;

    /// A namespace is the identity of its nsfs file, and the check is
    /// asked of the descriptor the run already holds rather than of a
    /// path resolved a second time — which is where a reused pid would
    /// slip through.
    #[test]
    fn the_namespace_check_compares_the_held_descriptor_by_identity() {
        let (me, user) = (
            Path::new("/proc/self/ns/net"),
            Path::new("/proc/self/ns/user"),
        );
        if !me.exists() || !user.exists() {
            return;
        }
        let held = rustix::fs::open(me, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).unwrap();
        assert!(same_namespace(held.as_fd(), me).unwrap());
        // Another namespace of the same process: a different inode on the
        // same filesystem, so the device alone would not tell them apart.
        assert!(!same_namespace(held.as_fd(), user).unwrap());
        // A path the run cannot ask about is never a match: a pid it
        // cannot check is one it must not act on either.
        assert!(same_namespace(held.as_fd(), Path::new("/proc/self/ns/nonesuch")).is_err());
    }

    /// A child in the shape bwrap leaves a sandbox in: a network
    /// namespace owned by one user namespace, with the process itself
    /// moved on into a nested user namespace that owns nothing. Comes
    /// back with the link of the owning namespace, which the child
    /// reports before it moves. `None`, with a printed reason, where
    /// this host cannot make one.
    fn nested_child() -> Option<(Child, String)> {
        let child = Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--net",
                "/usr/bin/sh",
                "-c",
                "readlink /proc/self/ns/user; \
                 exec unshare --user /usr/bin/sh -c 'echo ready; exec sleep 30'",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(e) => {
                eprintln!("skipping: unshare(1) could not be started: {e}");
                return None;
            }
        };
        let said: Vec<String> = child
            .stdout
            .take()
            .map(|out| {
                std::io::BufReader::new(out)
                    .lines()
                    .map_while(Result::ok)
                    .take(2)
                    .collect()
            })
            .unwrap_or_default();
        match said.as_slice() {
            [owner, ready] if ready == "ready" => Some((child, owner.clone())),
            _ => {
                eprintln!("skipping: nested user namespaces are unavailable here");
                let _ = child.kill();
                let _ = child.wait();
                None
            }
        }
    }

    #[test]
    fn the_ns_get_userns_opcode_is_the_one_the_header_defines() {
        // `linux/nsfs.h`: `#define NSIO 0xb7` and
        // `#define NS_GET_USERNS _IO(NSIO, 0x1)`.
        assert_eq!(NS_GET_USERNS, 0xb701);
    }

    #[test]
    fn the_user_namespace_comes_from_the_network_namespace_it_owns() {
        let Some((mut child, owner)) = nested_child() else {
            return;
        };
        let netns = rustix::fs::open(
            format!("/proc/{}/ns/net", child.id()),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let userns = owning_userns(netns.as_fd()).unwrap();
        // The kernel opens it close-on-exec (`open_related_ns` in
        // `fs/nsfs.c`), so a namespace descriptor is not something the
        // sidecars bubbler spawns inherit.
        assert!(
            rustix::io::fcntl_getfd(&userns)
                .unwrap()
                .contains(FdFlags::CLOEXEC)
        );
        let link = |p: String| {
            std::fs::read_link(p)
                .unwrap()
                .to_string_lossy()
                .into_owned()
        };
        let got = link(format!("/proc/self/fd/{}", userns.as_raw_fd()));
        // A namespace link reads as `<type>:[<inode>]`, and the inode is
        // the namespace's identity (`namespaces(7)`).
        assert_eq!(got, owner, "not the namespace that owns the netns");
        // The path this replaced, and the reason it was a race: by now
        // the child is in a user namespace of its own, which owns
        // nothing and gives pasta no authority over the netns.
        assert_ne!(got, link(format!("/proc/{}/ns/user", child.id())));
        assert_ne!(got, link("/proc/self/ns/user".to_owned()));
        let _ = child.kill();
        let _ = child.wait();
    }
}
