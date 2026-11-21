//! The run layer's error: what a launch, an exec or a probe of a
//! running instance can fail with, holding the plan layer's and each
//! run module's own errors.

use std::io;
use std::path::PathBuf;
use std::process::ExitStatus;

use rustix::io::Errno;

use thiserror::Error;

use crate::model::error::ConfigError;
use crate::plan::plan_error::PlanError;
use crate::run::dbus_a11y::A11yError;
use crate::run::exec::ControlError;
use crate::run::launcher;
use crate::wayland_context::WaylandError;

/// Failures while turning a config into a running sandbox.
#[derive(Debug, Error)]
pub enum LaunchError {
    /// `bwrap` not on `PATH`.
    #[error("bwrap not found on PATH; install bubblewrap")]
    BwrapMissing,
    /// Filesystem failure at a specific path.
    #[error("{0}")]
    Io(PathBuf, #[source] io::Error),
    /// Creating an fd bwrap must inherit failed: a data file, the control
    /// socket or a sidecar's ready pipe.
    #[error("preparing an fd for bwrap")]
    Data(#[source] io::Error),
    /// Reading this process's own open descriptors, or marking the ones a
    /// child must not inherit close-on-exec, failed. Nothing is spawned
    /// after this.
    #[error("keeping inherited descriptors out of the child")]
    Descriptors(#[source] io::Error),
    /// Spawning `bwrap` failed for a reason other than it being missing.
    #[error("failed to run bwrap")]
    Spawn(#[source] io::Error),
    /// Allocating the sandbox's pseudoterminal, or relaying through it,
    /// failed; the sandbox would have had to use the host's terminal.
    #[error("setting up the sandbox terminal")]
    Pty(#[source] io::Error),
    /// The D-Bus proxy did not report readiness in time, so the sandbox
    /// would have started without the bus socket it expects.
    #[error("the D-Bus proxy did not become ready")]
    ProxyNotReady,
    /// A stop signal arrived while a sidecar was starting, and the start
    /// ended there. `crate::launcher::run` exits with a stopped run's
    /// code in its place.
    #[error("the start was stopped by a signal")]
    Stopped,
    /// Nothing listens on the instance's control socket.
    #[error("instance `{0}` is not running")]
    NotRunning(String),
    /// A fresh start was asked for while the instance is already running.
    #[error("instance `{0}` is already running")]
    AlreadyRunning(String),
    /// Installing the SIGINT/SIGTERM handlers failed, so a signal could
    /// not be forwarded into the sandbox.
    #[error("installing signal handlers")]
    Signal(#[source] io::Error),
    /// What the run was to bind, set or filter could not be resolved.
    #[error(transparent)]
    Plan(#[from] PlanError),
    /// A PipeWire sidecar of the `pipewire` or `pulseaudio` grant did not
    /// come up. The run stops here.
    #[error(transparent)]
    PipeWire(#[from] PipeWireError),
    /// The sandbox's network namespace could not be connected or
    /// filtered. The sandbox is stopped rather than let go.
    #[error(transparent)]
    Network(#[from] NetworkError),
    /// The accessibility bus could not be found.
    #[error(transparent)]
    A11y(#[from] A11yError),
    /// The other end of the exec channel spoke out of protocol or hung up.
    #[error(transparent)]
    Control(#[from] ControlError),
    /// The compositor refused, or could not be asked for, the Wayland
    /// security context the `wayland` grant registers the sandbox as.
    /// The run stops rather than fall back to the session socket.
    #[error(transparent)]
    Wayland(#[from] WaylandError),
    /// Command resolution failed (config had no `command` and none given).
    #[error(transparent)]
    Config(#[from] ConfigError),
}

/// A PipeWire sidecar of the `pipewire` or `pulseaudio` grant did not
/// come up. The run stops here.
#[derive(Debug, Error)]
pub enum PipeWireError {
    /// `pw-container` exited before it reported the security context's socket.
    #[error(
        "pw-container did not create this instance's PipeWire security context: it exited \
         ({0})"
    )]
    ContextExited(ExitStatus),
    /// `pw-container` reported no socket, or another one, in time.
    #[error(
        "pw-container did not create this instance's PipeWire security context: it did not \
         report `{}` within {:?}",
        crate::pipewire::SOCKET_INSIDE,
        launcher::PW_READY
    )]
    ContextSilent,
    /// The private `pipewire-pulse` exited before it made its socket.
    #[error(
        "pipewire-pulse did not serve this instance's private PulseAudio socket: it exited ({0})"
    )]
    PulseExited(ExitStatus),
    /// The private `pipewire-pulse` did not make the socket at this path in time.
    #[error(
        "pipewire-pulse did not serve this instance's private PulseAudio socket: it did not \
         create `{}` within {:?}",
        .0.display(),
        launcher::PULSE_READY
    )]
    PulseSilent(PathBuf),
}

/// The sandbox's network namespace could not be connected or filtered:
/// pasta, `nft`, the egress proxy or the cgroups an `allow-host` needs.
/// The sandbox is stopped rather than let go.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// The sandbox pid shares bubbler's network namespace, so it is no
    /// longer the sandbox.
    #[error(
        "connecting the sandbox network namespace: sandbox pid reused; refusing to configure the \
         host network namespace"
    )]
    PidReusedNet,
    /// The sandbox pid shares bubbler's mount namespace.
    #[error(
        "connecting the sandbox network namespace: sandbox pid reused; refusing to join the host \
         mount namespace"
    )]
    PidReusedMnt,
    /// bwrap reported no pid, so pasta has nothing to attach to.
    #[error(
        "connecting the sandbox network namespace: bwrap reported no sandbox pid for pasta to \
         attach to"
    )]
    NoSandboxPid,
    /// pasta did not report that it configured the namespace.
    #[error("connecting the sandbox network namespace: pasta did not configure the namespace")]
    PastaNotReady,
    /// `nft` could not be started.
    #[error(
        "connecting the sandbox network namespace: starting `{}`: {}",
        crate::network::NFT_BIN,
        .0
    )]
    NftStart(io::Error),
    /// Waiting on `nft` failed.
    #[error("connecting the sandbox network namespace: waiting for `nft`: {0}")]
    NftWait(io::Error),
    /// `nft` did not finish in time and was killed.
    #[error(
        "connecting the sandbox network namespace: `{}` did not install the outbound ruleset \
         within {} seconds",
        crate::network::NFT_BIN,
        launcher::NFT_TIMEOUT.as_secs()
    )]
    NftTimeout,
    /// `nft` exited unsuccessfully.
    #[error(
        "connecting the sandbox network namespace: `{}` refused the outbound ruleset ({})",
        crate::network::NFT_BIN,
        .0
    )]
    NftRefused(ExitStatus),
    /// Writing the ruleset to `nft` failed.
    #[error("connecting the sandbox network namespace: writing the outbound ruleset: {0}")]
    NftWrite(io::Error),
    /// The egress proxy could not be started.
    #[error("connecting the sandbox network namespace: starting the egress proxy: {0}")]
    ProxyStart(io::Error),
    /// The egress proxy exited before it reported its socket.
    #[error(
        "connecting the sandbox network namespace: the egress proxy did not start: it exited \
         ({0})"
    )]
    ProxyExited(ExitStatus),
    /// The egress proxy reported no listening socket in time.
    #[error(
        "connecting the sandbox network namespace: the egress proxy did not start: it did not \
         report a listening socket within {:?}",
        launcher::NET_PROXY_READY
    )]
    ProxySilent,
    /// The cgroup a run would create is no path a ruleset can carry.
    #[error(
        "connecting the sandbox network namespace: the cgroup this run would create is no path \
         a rule could carry ({why}): {base}"
    )]
    CgroupUnrepresentable {
        /// Why the path cannot be carried.
        why: String,
        /// The cgroup, relative to the cgroup2 mount.
        base: String,
    },
    /// The proxy cgroup's `cgroup.procs` could not be opened.
    #[error(
        "connecting the sandbox network namespace: opening {}/cgroup.procs: {errno}",
        .proxy.display()
    )]
    CgroupProcs {
        /// The proxy cgroup.
        proxy: PathBuf,
        /// What the kernel said.
        errno: Errno,
    },
    /// bubbler could not move itself into the sandbox cgroup.
    #[error(
        "connecting the sandbox network namespace: moving bubbler into {}: {err}",
        .sandbox.display()
    )]
    CgroupMove {
        /// The sandbox cgroup.
        sandbox: PathBuf,
        /// What the write failed with.
        err: io::Error,
    },
    /// Creating a cgroup was refused: bubbler's own is not delegated to the user.
    #[error(
        "connecting the sandbox network namespace: allow-host needs a delegated cgroup2 subtree \
         (a systemd user session provides one): creating {}: {errno}",
        .dir.display()
    )]
    CgroupNotDelegated {
        /// The cgroup that could not be made.
        dir: PathBuf,
        /// What the kernel said.
        errno: Errno,
    },
    /// The cgroup exists and holds a process.
    #[error(
        "connecting the sandbox network namespace: {} already exists and is not empty; another \
         process is in it",
        .0.display()
    )]
    CgroupOccupied(PathBuf),
    /// Creating a cgroup failed otherwise.
    #[error("connecting the sandbox network namespace: creating {}: {errno}", .dir.display())]
    CgroupCreate {
        /// The cgroup that could not be made.
        dir: PathBuf,
        /// What the kernel said.
        errno: Errno,
    },
    /// bubbler is in no cgroup2 hierarchy.
    #[error(
        "connecting the sandbox network namespace: this process is in no cgroup2 hierarchy, \
         which is what an `allow-host` ruleset matches on"
    )]
    NoCgroup2,
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;

    use super::*;

    #[test]
    fn a_pipewire_sidecar_that_did_not_come_up_reads_as_before() {
        let exited = || ExitStatus::from_raw(256);
        for (e, text) in [
            (
                PipeWireError::ContextExited(exited()),
                "pw-container did not create this instance's PipeWire security context: it \
                 exited (exit status: 1)",
            ),
            (
                PipeWireError::ContextSilent,
                "pw-container did not create this instance's PipeWire security context: it did \
                 not report `/tmp/pipewire-0` within 5s",
            ),
            (
                PipeWireError::PulseExited(exited()),
                "pipewire-pulse did not serve this instance's private PulseAudio socket: it \
                 exited (exit status: 1)",
            ),
            (
                PipeWireError::PulseSilent(PathBuf::from("/run/user/1000/bubbler/t/pulse/native")),
                "pipewire-pulse did not serve this instance's private PulseAudio socket: it did \
                 not create `/run/user/1000/bubbler/t/pulse/native` within 5s",
            ),
        ] {
            assert_eq!(LaunchError::from(e).to_string(), text);
        }
    }

    #[test]
    fn a_network_that_could_not_be_connected_reads_as_before() {
        const AT: &str = "connecting the sandbox network namespace: ";
        let failed = || io::Error::other("Broken pipe");
        let refused = || ExitStatus::from_raw(256);
        let dir = || PathBuf::from("/sys/fs/cgroup/a/bubbler-t-9");
        let errno = Errno::ACCESS;
        for (e, text) in [
            (
                NetworkError::PidReusedNet,
                "sandbox pid reused; refusing to configure the host network namespace".to_owned(),
            ),
            (
                NetworkError::PidReusedMnt,
                "sandbox pid reused; refusing to join the host mount namespace".to_owned(),
            ),
            (
                NetworkError::NoSandboxPid,
                "bwrap reported no sandbox pid for pasta to attach to".to_owned(),
            ),
            (
                NetworkError::PastaNotReady,
                "pasta did not configure the namespace".to_owned(),
            ),
            (
                NetworkError::NftStart(failed()),
                "starting `nft`: Broken pipe".to_owned(),
            ),
            (
                NetworkError::NftWait(failed()),
                "waiting for `nft`: Broken pipe".to_owned(),
            ),
            (
                NetworkError::NftTimeout,
                "`nft` did not install the outbound ruleset within 5 seconds".to_owned(),
            ),
            (
                NetworkError::NftRefused(refused()),
                "`nft` refused the outbound ruleset (exit status: 1)".to_owned(),
            ),
            (
                NetworkError::NftWrite(failed()),
                "writing the outbound ruleset: Broken pipe".to_owned(),
            ),
            (
                NetworkError::ProxyStart(failed()),
                "starting the egress proxy: Broken pipe".to_owned(),
            ),
            (
                NetworkError::ProxyExited(refused()),
                "the egress proxy did not start: it exited (exit status: 1)".to_owned(),
            ),
            (
                NetworkError::ProxySilent,
                "the egress proxy did not start: it did not report a listening socket within 5s"
                    .to_owned(),
            ),
            (
                NetworkError::CgroupUnrepresentable {
                    why: "a space".to_owned(),
                    base: "a b/bubbler-t-9".to_owned(),
                },
                "the cgroup this run would create is no path a rule could carry (a space): \
                 a b/bubbler-t-9"
                    .to_owned(),
            ),
            (
                NetworkError::CgroupProcs {
                    proxy: dir().join("proxy"),
                    errno,
                },
                format!("opening /sys/fs/cgroup/a/bubbler-t-9/proxy/cgroup.procs: {errno}"),
            ),
            (
                NetworkError::CgroupMove {
                    sandbox: dir().join("sandbox"),
                    err: failed(),
                },
                "moving bubbler into /sys/fs/cgroup/a/bubbler-t-9/sandbox: Broken pipe".to_owned(),
            ),
            (
                NetworkError::CgroupNotDelegated { dir: dir(), errno },
                format!(
                    "allow-host needs a delegated cgroup2 subtree (a systemd user session \
                     provides one): creating /sys/fs/cgroup/a/bubbler-t-9: {errno}"
                ),
            ),
            (
                NetworkError::CgroupOccupied(dir()),
                "/sys/fs/cgroup/a/bubbler-t-9 already exists and is not empty; another process \
                 is in it"
                    .to_owned(),
            ),
            (
                NetworkError::CgroupCreate { dir: dir(), errno },
                format!("creating /sys/fs/cgroup/a/bubbler-t-9: {errno}"),
            ),
            (
                NetworkError::NoCgroup2,
                "this process is in no cgroup2 hierarchy, which is what an `allow-host` ruleset \
                 matches on"
                    .to_owned(),
            ),
        ] {
            assert_eq!(LaunchError::from(e).to_string(), format!("{AT}{text}"));
        }
    }
}
