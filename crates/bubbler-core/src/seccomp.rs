//! The seccomp denylist: which syscalls a sandbox loses by default, the
//! rule set a profile's `seccomp` node produces, and the one multi-ABI
//! BPF program libseccomp compiles it into.

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};

use libseccomp::error::SeccompError;
use libseccomp::{
    ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall,
};
use rustix::fs::MemfdFlags;
use rustix::io::Errno as OsErrno;

use crate::error::LaunchError;

/// Syscalls the default filter answers with `EPERM`: the kernel keyring,
/// NUMA and VM controls, module and kexec loading, accounting, quota, the
/// system clock and the host name, io_uring, and the calls that reach
/// into another process (`pidfd_getfd`, `kcmp`) — each either already
/// unreachable in bubbler's baseline sandbox or unused by desktop apps. The
/// argument-filtered `ioctl` rules are [`DEFAULT_IOCTL_EPERM`] instead:
/// denying `ioctl` outright would break every program.
pub const DEFAULT_EPERM: &[&str] = &[
    "syslog",
    "uselib",
    "acct",
    "quotactl",
    "add_key",
    "keyctl",
    "request_key",
    "move_pages",
    "mbind",
    "get_mempolicy",
    "set_mempolicy",
    "migrate_pages",
    "perf_event_open",
    "bpf",
    "userfaultfd",
    "fanotify_init",
    "lookup_dcookie",
    "name_to_handle_at",
    "open_by_handle_at",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "iopl",
    "ioperm",
    "swapon",
    "swapoff",
    "reboot",
    "vhangup",
    "settimeofday",
    "clock_settime",
    "clock_settime64",
    "adjtimex",
    "clock_adjtime",
    "clock_adjtime64",
    "sethostname",
    "setdomainname",
    "nfsservctl",
    "vm86",
    "vm86old",
    // The kernel surface every recent mitigation bypass was written
    // against, and nothing a desktop application needs through a
    // sandbox: an io_uring ring is a second syscall path that the audit
    // and LSM hooks see differently from the first. `EPERM` and not
    // `ENOSYS`, because the kernel's own `io_uring_disabled=2` answers
    // `EPERM` and every runtime is tested against that answer.
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    // Takes a descriptor out of another process by pidfd. The sandbox
    // shares its pid namespace with `bubbler-init` and with every
    // command run through the exec channel.
    "pidfd_getfd",
    // Compares two processes' kernel objects, which tells a caller
    // whether two descriptors are the same open file — a side channel
    // out of the sandbox's own process tree.
    "kcmp",
];

/// Denied with `EPERM` on top of [`DEFAULT_EPERM`], but only where the
/// filter carries a single ABI. `modify_ldt` writes the local descriptor
/// table, which 16-bit code and several Wine patches need. Every rule
/// here goes in after both architectures, so it holds for both ABIs;
/// keeping this one would break the 32-bit code the second architecture
/// exists to filter rather than kill, which is why flatpak allows it
/// wherever its own filter is multiarch (`flatpak-run.c`). The cost is
/// real and not confined to 32-bit callers: on a multiarch build 64-bit
/// code can call `modify_ldt` too, where a single-architecture filter
/// answered `EPERM` (measured). A profile that wants it back writes
/// `seccomp { deny "modify_ldt" }`.
pub const SINGLE_ARCH_EPERM: &[&str] = &["modify_ldt"];

/// Syscalls the default filter answers with `ENOSYS`, so libc falls back
/// to the older call instead of failing: seccomp cannot inspect `clone3`'s
/// `clone_args`, and the new mount API can rewrite the sandbox's own VFS.
// The mount API hole is CVE-2021-41133.
pub const DEFAULT_ENOSYS: &[&str] = &[
    "clone3",
    "open_tree",
    "move_mount",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "mount_setattr",
];

/// `ioctl` requests denied with `EPERM` by default, matched on the low 32
/// bits of argument 1.
pub const DEFAULT_IOCTL_EPERM: &[u32] = &[TIOCSTI, TIOCLINUX];

/// Pushes bytes into the controlling terminal's input queue, so a sandbox
/// sharing the user's tty could type commands into their shell
/// (CVE-2017-5226). Value from `asm-generic/ioctls.h`.
pub const TIOCSTI: u32 = 0x5412;

/// Virtual console control, including the selection buffer, which is
/// equivalent to [`TIOCSTI`] (CVE-2023-28100). Value from
/// `asm-generic/ioctls.h`.
pub const TIOCLINUX: u32 = 0x541C;

/// Architectures added to the filter beyond the one bubbler was built
/// for. On x86_64 that is i386, so a 32-bit binary in the sandbox is
/// filtered instead of killed by the ABI check; libseccomp translates
/// every rule to it by name, including the `_time64` numbers glibc issues
/// there. x32 is deliberately not among them: it shares x86_64's
/// `AUDIT_ARCH` value, and libseccomp's own guard denies its numbers.
#[cfg(target_arch = "x86_64")]
const EXTRA_ARCHES: &[ScmpArch] = &[ScmpArch::X86];
#[cfg(not(target_arch = "x86_64"))]
const EXTRA_ARCHES: &[ScmpArch] = &[];

/// The architectures one filter answers for, as `--explain` names them.
#[cfg(target_arch = "x86_64")]
pub const ARCHES: &str = "x86_64 + i386";
#[cfg(not(target_arch = "x86_64"))]
pub const ARCHES: &str = std::env::consts::ARCH;

/// What a denied syscall returns to the sandboxed process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Errno {
    /// The call is refused outright.
    #[default]
    Eperm,
    /// The call looks unimplemented, which makes libc use its fallback.
    Enosys,
}

impl Errno {
    /// The name as `errno(3)` writes it, for messages about the rules
    /// that answer with it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Eperm => "EPERM",
            Self::Enosys => "ENOSYS",
        }
    }

    /// The number the syscall returns, as a positive `errno` value.
    fn raw(self) -> i32 {
        match self {
            Self::Eperm => OsErrno::PERM.raw_os_error(),
            Self::Enosys => OsErrno::NOSYS.raw_os_error(),
        }
    }
}

/// One compiled filter and the architectures it answers for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    /// The architectures the rules were translated to, for
    /// [`crate::bwrap::Explained::note`].
    pub arches: &'static str,
    /// cBPF as `struct sock_filter` bytes; bwrap rejects a length that is
    /// not a multiple of eight.
    pub bytes: Vec<u8>,
}

/// A profile's `seccomp` node: holes punched in the default denylist,
/// extra syscalls denied, or no filter at all.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SeccompConfig {
    /// Syscall names removed from the default denylist, in file order.
    pub allow: Vec<String>,
    /// Extra syscalls to deny with the given error, in file order; applied
    /// after `allow`.
    pub deny: Vec<(String, Errno)>,
    /// No filter at all: the sandbox keeps every syscall the kernel has.
    pub disable: bool,
}

/// The syscalls one sandbox is denied, split by the error each returns.
/// Names no architecture in the filter has stay in the lists; dropping
/// them is the compile step's job.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleSet {
    /// Syscall names denied with `EPERM`.
    pub eperm: Vec<String>,
    /// Syscall names denied with `ENOSYS`.
    pub enosys: Vec<String>,
    /// `ioctl` request numbers denied with `EPERM`, matched on the low 32
    /// bits of argument 1.
    pub ioctl_eperm: Vec<u32>,
}

impl RuleSet {
    /// The denylist every sandbox gets unless its profile says otherwise.
    pub fn default_set() -> Self {
        let extra: &[&str] = match EXTRA_ARCHES.is_empty() {
            true => SINGLE_ARCH_EPERM,
            false => &[],
        };
        Self {
            eperm: DEFAULT_EPERM
                .iter()
                .chain(extra)
                .map(|s| (*s).to_owned())
                .collect(),
            enosys: DEFAULT_ENOSYS.iter().map(|s| (*s).to_owned()).collect(),
            ioctl_eperm: DEFAULT_IOCTL_EPERM.to_vec(),
        }
    }

    /// The default set with `cfg`'s allows removed and its denies appended,
    /// or `None` when the profile disabled the filter. Naming `ioctl` in
    /// either list drops the [`DEFAULT_IOCTL_EPERM`] rules.
    pub fn with(cfg: &SeccompConfig) -> Option<Self> {
        if cfg.disable {
            return None;
        }
        let mut set = Self::default_set();
        for name in &cfg.allow {
            set.remove(name);
            if name == "ioctl" {
                set.ioctl_eperm.clear();
            }
        }
        for (name, errno) in &cfg.deny {
            // Removing first keeps one action per syscall, whichever list
            // the name was on, and keeps a repeated `deny` from doubling.
            set.remove(name);
            if name == "ioctl" {
                // A rule matching every request subsumes the two that
                // match one each; keeping both would put `ioctl` in the
                // filter twice with two different actions.
                set.ioctl_eperm.clear();
            }
            match errno {
                Errno::Eperm => set.eperm.push(name.clone()),
                Errno::Enosys => set.enosys.push(name.clone()),
            }
        }
        Some(set)
    }

    fn remove(&mut self, name: &str) {
        self.eperm.retain(|s| s != name);
        self.enosys.retain(|s| s != name);
    }
}

/// Mask applied to `ioctl`'s request argument, so the rule looks at the
/// low 32 bits — the same half the kernel hands the driver, which makes a
/// request of `0x1_0000_5412` TIOCSTI to both.
const REQUEST_MASK: u64 = 0xFFFF_FFFF;

/// Set once a compile has named its skipped rules. Which names those are
/// follows from the build, not from the launch, so an instance that also
/// starts a proxy sidecar would otherwise say it all twice.
static NOTED: AtomicBool = AtomicBool::new(false);

/// Whether this compile is the one that names `skipped` on stderr: the
/// first that has anything to name. A compile that failed, or that
/// skipped nothing, leaves the report to the next one.
fn take_note(skipped: &[String], noted: &AtomicBool) -> bool {
    !skipped.is_empty() && !noted.swap(true, Ordering::Relaxed)
}

/// One build's output: the filter, how many rules reached it, and the
/// names this libseccomp did not know.
struct Built {
    filter: ScmpFilterContext,
    rules: usize,
    skipped: Vec<String>,
}

/// The rule set as one loadable BPF program for `--add-seccomp-fd`, or
/// `None` when no rule went in — an `allow` list that takes every rule
/// back, or names this libseccomp does not know. Everything not named is
/// allowed, and `log` turns matches into audit log entries instead of
/// errors.
pub fn compile(set: &RuleSet, log: bool) -> Result<Option<Program>, LaunchError> {
    let built = build(set, log)?;
    // A skipped name is a rule that is not in the filter, so it is
    // reported whatever the log switch says: the alternative is a
    // silently weaker sandbox on a libseccomp too old for the list.
    if take_note(&built.skipped, &NOTED) {
        for name in &built.skipped {
            eprintln!("bubbler: seccomp: {name} unknown to this libseccomp, rule skipped");
        }
    }
    if built.rules == 0 {
        return Ok(None);
    }
    Ok(Some(Program {
        arches: ARCHES,
        bytes: export(&built.filter)?,
    }))
}

/// `set` as a libseccomp filter over [`ARCHES`], allowing everything it
/// does not name. A syscall appears once even if both lists carry it:
/// libseccomp refuses a second action for the same number, and the first
/// list `RuleSet` puts it on decides.
fn build(set: &RuleSet, log: bool) -> Result<Built, LaunchError> {
    let mut filter = ScmpFilterContext::new(ScmpAction::Allow).map_err(failed)?;
    // A syscall from an ABI the filter does not carry cannot be matched
    // by number — x32 shares x86_64's `AUDIT_ARCH` value and offsets
    // every number by `__X32_SYSCALL_BIT` — so such a caller is killed
    // rather than let through. `man 2 seccomp` requires exactly this of
    // any policy that does not enumerate the x32 numbers as well.
    filter
        .set_act_badarch(ScmpAction::KillProcess)
        .map_err(failed)?;
    // `man 3 seccomp_arch_add`: rules added after an architecture is
    // added reach every architecture in the filter, and rules added
    // before it do not. So the architectures come first.
    for arch in EXTRA_ARCHES {
        filter.add_arch(*arch).map_err(failed)?;
    }
    let mut seen: BTreeSet<i32> = BTreeSet::new();
    let mut skipped = Vec::new();
    for (names, errno) in [(&set.eperm, Errno::Eperm), (&set.enosys, Errno::Enosys)] {
        for name in names {
            let Ok(nr) = ScmpSyscall::from_name(name) else {
                skipped.push(name.clone());
                continue;
            };
            if !seen.insert(nr.into()) {
                continue;
            }
            filter.add_rule(action(log, errno), nr).map_err(failed)?;
        }
    }
    let mut rules = seen.len();
    let Ok(ioctl) = ScmpSyscall::from_name("ioctl") else {
        return Ok(Built {
            filter,
            rules,
            skipped,
        });
    };
    // A blanket deny of `ioctl` already covers every request, so adding
    // the argument-filtered rules to it would only narrow it.
    if !set.ioctl_eperm.is_empty() && !seen.contains(&ioctl.into()) {
        for request in &set.ioctl_eperm {
            let cmp = ScmpArgCompare::new(
                1,
                ScmpCompareOp::MaskedEqual(REQUEST_MASK),
                u64::from(*request),
            );
            filter
                .add_rule_conditional(action(log, Errno::Eperm), ioctl, &[cmp])
                .map_err(failed)?;
            rules += 1;
        }
    }
    Ok(Built {
        filter,
        rules,
        skipped,
    })
}

/// What a matching syscall gets: the error, or an audit log entry and
/// then the syscall it asked for.
fn action(log: bool, errno: Errno) -> ScmpAction {
    match log {
        true => ScmpAction::Log,
        // The errno is what the syscall returns, so it is the raw
        // positive number, not a negated return value.
        false => ScmpAction::Errno(errno.raw()),
    }
}

/// The filter as the bytes bwrap reads. libseccomp writes cBPF to a file
/// descriptor, so it goes through a memfd rather than a temporary file;
/// `export_bpf_mem` would do it in one call but needs libseccomp 2.6.
fn export(filter: &ScmpFilterContext) -> Result<Vec<u8>, LaunchError> {
    let io = |e: std::io::Error| LaunchError::Seccomp(format!("exporting the filter: {e}"));
    let fd = rustix::fs::memfd_create("bubbler-seccomp", MemfdFlags::CLOEXEC)
        .map_err(|e| io(e.into()))?;
    filter.export_bpf(&fd).map_err(failed)?;
    let mut file = std::fs::File::from(fd);
    file.seek(SeekFrom::Start(0)).map_err(io)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(io)?;
    Ok(bytes)
}

fn failed(e: SeccompError) -> LaunchError {
    LaunchError::Seccomp(e.to_string())
}

/// The number libseccomp resolves `name` to on the build architecture, or
/// `None` when this libseccomp does not know the name at all. A syscall
/// the build architecture does not itself have — `clock_adjtime64` on
/// x86_64, say — answers with a negative pseudo-number that still names
/// a real rule on the other architectures in the filter, so only the
/// sign of the answer tells the two apart.
pub fn syscall_number(name: &str) -> Option<i64> {
    ScmpSyscall::from_name(name)
        .ok()
        .map(|nr| i64::from(i32::from(nr)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every name in the default lists is one libseccomp knows, so none
    /// of them is dropped from the filter. This is x86_64-only on
    /// purpose: libseccomp's table is per-architecture but complete, and
    /// resolves a name the native architecture lacks to a negative
    /// pseudo-number rather than an error, so the same assertion on
    /// another architecture would prove nothing about which rules the
    /// filter actually got. A failure here means the linked libseccomp
    /// is older than the floor the README states.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn every_default_name_is_one_this_libseccomp_knows() {
        let missing: Vec<&str> = DEFAULT_EPERM
            .iter()
            .chain(SINGLE_ARCH_EPERM)
            .chain(DEFAULT_ENOSYS)
            .copied()
            .filter(|n| syscall_number(n).is_none())
            .collect();
        assert_eq!(missing, [""; 0]);
    }

    /// The names the second architecture contributes: on x86_64 the
    /// `_time64` clock calls and the vm86 pair are i386-only, and
    /// libseccomp answers for them with a pseudo-number.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn known_x86_64_numbers_and_the_i386_only_names_both_resolve() {
        assert_eq!(syscall_number("read"), Some(0));
        assert_eq!(syscall_number("ioctl"), Some(16));
        assert_eq!(syscall_number("prctl"), Some(157));
        assert_eq!(syscall_number("keyctl"), Some(250));
        assert_eq!(syscall_number("clone3"), Some(435));
        assert!(syscall_number("clock_adjtime64").is_some_and(|n| n < 0));
        assert!(syscall_number("vm86").is_some_and(|n| n < 0));
        assert_eq!(syscall_number("nosuchcall"), None);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn known_aarch64_numbers_match_the_kernel_table() {
        assert_eq!(syscall_number("read"), Some(63));
        assert_eq!(syscall_number("ioctl"), Some(29));
        assert_eq!(syscall_number("keyctl"), Some(219));
        assert_eq!(syscall_number("clone3"), Some(435));
        assert_eq!(syscall_number("nosuchcall"), None);
    }

    /// `modify_ldt` is the one rule the second architecture takes away:
    /// 32-bit code and Wine need it, and where the filter carries only
    /// one ABI nothing in the sandbox can call it usefully anyway.
    #[test]
    fn modify_ldt_is_denied_only_where_the_filter_holds_one_architecture() {
        let denied = RuleSet::default_set()
            .eperm
            .contains(&"modify_ldt".to_owned());
        assert_eq!(denied, EXTRA_ARCHES.is_empty());
        #[cfg(target_arch = "x86_64")]
        assert!(
            !denied,
            "i386 is in the filter, so modify_ldt stays allowed"
        );
        #[cfg(target_arch = "aarch64")]
        assert!(denied, "a single-architecture filter denies it");
    }

    #[test]
    fn the_filter_carries_the_build_architecture_and_i386_on_x86_64() {
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(EXTRA_ARCHES, &[ScmpArch::X86]);
            assert_eq!(ARCHES, "x86_64 + i386");
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            assert!(EXTRA_ARCHES.is_empty());
            assert_eq!(ARCHES, std::env::consts::ARCH);
        }
        // x32 is never added: it shares x86_64's `AUDIT_ARCH` value, and
        // adding it would allow the numbers the bad-arch action kills.
        assert!(!EXTRA_ARCHES.contains(&ScmpArch::X32));
    }

    #[test]
    fn the_default_set_is_the_two_lists_plus_the_ioctl_rules() {
        let set = RuleSet::default_set();
        assert_eq!(set.eperm[..DEFAULT_EPERM.len()], *DEFAULT_EPERM);
        assert_eq!(set.enosys, DEFAULT_ENOSYS);
        assert_eq!(set.ioctl_eperm, vec![0x5412, 0x541C]);
        assert_eq!(RuleSet::with(&SeccompConfig::default()), Some(set));
    }

    /// The kernel's own `io_uring_disabled=2` answers `EPERM`, so every
    /// consumer is already tested against it — libuv falls back to its
    /// thread pool in `uv__iou_init`. `ENOSYS` is not a substitute: a
    /// caller that reads it as "old kernel" may probe by another path,
    /// and a kill action would take down a process for a call its
    /// runtime made on its own.
    #[test]
    fn the_io_uring_family_and_the_process_probes_are_denied_with_eperm() {
        let set = RuleSet::default_set();
        for name in [
            "io_uring_setup",
            "io_uring_enter",
            "io_uring_register",
            "pidfd_getfd",
            "kcmp",
        ] {
            let name = name.to_owned();
            assert!(set.eperm.contains(&name), "{name} is not denied");
            assert!(!set.enosys.contains(&name), "{name} must answer EPERM");
            assert!(
                syscall_number(&name).is_some(),
                "{name} is unknown to this libseccomp"
            );
        }
    }

    #[test]
    fn disable_means_no_rules_at_all() {
        let cfg = SeccompConfig {
            disable: true,
            deny: vec![("unshare".to_owned(), Errno::Eperm)],
            ..SeccompConfig::default()
        };
        assert_eq!(RuleSet::with(&cfg), None);
    }

    #[test]
    fn allow_removes_from_the_default_list_and_keeps_the_order() {
        let cfg = SeccompConfig {
            allow: vec!["keyctl".to_owned(), "clone3".to_owned()],
            ..SeccompConfig::default()
        };
        let set = RuleSet::with(&cfg).unwrap();
        assert!(!set.eperm.contains(&"keyctl".to_owned()));
        assert!(!set.enosys.contains(&"clone3".to_owned()));
        assert_eq!(set.eperm.len(), RuleSet::default_set().eperm.len() - 1);
        assert_eq!(set.enosys.len(), DEFAULT_ENOSYS.len() - 1);
        assert_eq!(set.eperm[0], DEFAULT_EPERM[0]);
        assert_eq!(set.ioctl_eperm, DEFAULT_IOCTL_EPERM);
    }

    #[test]
    fn allowing_ioctl_is_what_takes_back_the_tiocsti_rules() {
        let cfg = SeccompConfig {
            allow: vec!["ioctl".to_owned()],
            ..SeccompConfig::default()
        };
        assert!(RuleSet::with(&cfg).unwrap().ioctl_eperm.is_empty());
    }

    #[test]
    fn deny_appends_in_file_order_and_never_twice() {
        let cfg = SeccompConfig {
            deny: vec![
                ("unshare".to_owned(), Errno::Eperm),
                ("setns".to_owned(), Errno::Eperm),
                ("keyctl".to_owned(), Errno::Eperm),
                ("chroot".to_owned(), Errno::Enosys),
            ],
            ..SeccompConfig::default()
        };
        let set = RuleSet::with(&cfg).unwrap();
        assert_eq!(
            &set.eperm[set.eperm.len() - 3..],
            ["unshare", "setns", "keyctl"]
        );
        assert_eq!(set.eperm.iter().filter(|s| *s == "keyctl").count(), 1);
        assert_eq!(set.eperm.len(), RuleSet::default_set().eperm.len() + 2);
        assert_eq!(set.enosys.last().unwrap(), "chroot");
    }

    #[test]
    fn deny_after_allow_wins_and_moves_a_syscall_between_the_lists() {
        let cfg = SeccompConfig {
            allow: vec!["clone3".to_owned()],
            deny: vec![("clone3".to_owned(), Errno::Eperm)],
            ..SeccompConfig::default()
        };
        let set = RuleSet::with(&cfg).unwrap();
        assert_eq!(set.enosys, DEFAULT_ENOSYS[1..]);
        assert_eq!(set.eperm.last().unwrap(), "clone3");
    }

    /// Instruction fields as libseccomp lays them out, decoded back from
    /// the bytes the program is passed to bwrap as.
    fn instructions(program: &[u8]) -> Vec<(u16, u8, u8, u32)> {
        assert_eq!(program.len() % 8, 0, "a sock_filter is eight bytes");
        program
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| {
                (
                    u16::from_le_bytes([c[0], c[1]]),
                    c[2],
                    c[3],
                    u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
                )
            })
            .collect()
    }

    /// Instructions in the default filter. libseccomp emits a balanced
    /// search tree over the syscall numbers of each architecture, so the
    /// number is a measurement rather than a formula; it is pinned here
    /// so that a rule added by accident, or an architecture dropped from
    /// the filter, is a test failure.
    #[cfg(target_arch = "x86_64")]
    const DEFAULT_LEN: usize = 122;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_default_set_compiles_to_one_program_of_a_known_size() {
        let program = compile(&RuleSet::default_set(), false).unwrap().unwrap();
        assert_eq!(program.arches, "x86_64 + i386");
        assert_eq!(instructions(&program.bytes).len(), DEFAULT_LEN);
    }

    #[test]
    fn a_program_starts_with_the_architecture_check() {
        let program = compile(&RuleSet::default_set(), false).unwrap().unwrap();
        // BPF_LD | BPF_W | BPF_ABS of `seccomp_data.arch`, at offset 4.
        assert_eq!(instructions(&program.bytes)[0], (0x0020, 0, 0, 4));
    }

    /// A caller from an ABI the filter does not carry is killed, so an
    /// x32 syscall — the same `AUDIT_ARCH` value with `__X32_SYSCALL_BIT`
    /// set on every number — cannot walk past rules keyed to x86_64.
    #[test]
    fn an_unknown_abi_is_killed_rather_than_allowed() {
        let program = compile(&RuleSet::default_set(), false).unwrap().unwrap();
        let ks: Vec<u32> = instructions(&program.bytes).iter().map(|i| i.3).collect();
        // SECCOMP_RET_KILL_PROCESS, from `linux/seccomp.h`.
        assert!(ks.contains(&0x8000_0000), "no kill for a foreign ABI");
    }

    #[test]
    fn the_ioctl_rules_compare_the_request_argument_once_per_architecture() {
        let program = compile(&RuleSet::default_set(), false).unwrap().unwrap();
        let insns = instructions(&program.bytes);
        // `seccomp_data.args[1]` starts at offset 16 + 1 * 8 = 24, and it
        // is little-endian, so the low half the kernel hands the driver
        // is the word at 24.
        assert!(
            insns.contains(&(0x0020, 0, 0, 24)),
            "argument 1 is never loaded"
        );
        for value in DEFAULT_IOCTL_EPERM {
            // BPF_JMP | BPF_JEQ | BPF_K. One comparison serves every
            // architecture: libseccomp shares an identical block between
            // the per-architecture branches.
            assert!(
                insns.iter().any(|i| i.0 == 0x0015 && i.3 == *value),
                "no comparison for {value:#x}"
            );
        }
    }

    /// The filter branches on `seccomp_data.arch` once per architecture
    /// it carries, so a rule really did reach both ABIs rather than only
    /// the one bubbler was built for.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_program_branches_on_both_audit_arch_values() {
        let program = compile(&RuleSet::default_set(), false).unwrap().unwrap();
        let ks: Vec<u32> = instructions(&program.bytes).iter().map(|i| i.3).collect();
        // AUDIT_ARCH_X86_64 and AUDIT_ARCH_I386, from `linux/audit.h`.
        assert!(ks.contains(&0xc000_003e), "no x86_64 branch");
        assert!(ks.contains(&0x4000_0003), "no i386 branch");
    }

    #[test]
    fn a_rule_set_that_denies_nothing_produces_no_program() {
        let cfg = SeccompConfig {
            allow: RuleSet::default_set()
                .eperm
                .into_iter()
                .chain(RuleSet::default_set().enosys)
                .chain(["ioctl".to_owned()])
                .collect(),
            ..SeccompConfig::default()
        };
        assert_eq!(compile(&RuleSet::with(&cfg).unwrap(), false).unwrap(), None);
        assert_eq!(compile(&RuleSet::default(), false).unwrap(), None);
        // Names alone are not rules: a set only this architecture's
        // sibling has leaves nothing to load either.
        let absent = RuleSet {
            eperm: vec!["nosuchcall".to_owned()],
            enosys: vec![],
            ioctl_eperm: vec![],
        };
        assert_eq!(compile(&absent, false).unwrap(), None);
    }

    #[test]
    fn allowing_a_syscall_shrinks_the_program() {
        let cfg = SeccompConfig {
            allow: vec!["keyctl".to_owned()],
            ..SeccompConfig::default()
        };
        let full = compile(&RuleSet::default_set(), false).unwrap().unwrap();
        let fewer = compile(&RuleSet::with(&cfg).unwrap(), false)
            .unwrap()
            .unwrap();
        assert!(fewer.bytes.len() < full.bytes.len());
    }

    #[test]
    fn a_blanket_ioctl_deny_leaves_out_the_argument_rules() {
        let set = RuleSet {
            eperm: vec!["ioctl".to_owned()],
            enosys: vec![],
            ioctl_eperm: DEFAULT_IOCTL_EPERM.to_vec(),
        };
        let insns = instructions(&compile(&set, false).unwrap().unwrap().bytes);
        assert!(
            !insns.iter().any(|i| i.3 == TIOCSTI),
            "the blanket rule must subsume the argument comparisons"
        );
    }

    /// One action per syscall, whichever list carried it first:
    /// libseccomp refuses a second rule for the same number, so a set
    /// naming one twice must not reach it twice.
    #[test]
    fn a_name_on_both_lists_is_compiled_once() {
        let set = RuleSet {
            eperm: vec!["keyctl".to_owned()],
            enosys: vec!["keyctl".to_owned()],
            ioctl_eperm: vec![],
        };
        let one = RuleSet {
            eperm: vec!["keyctl".to_owned()],
            enosys: vec![],
            ioctl_eperm: vec![],
        };
        assert_eq!(compile(&set, false).unwrap(), compile(&one, false).unwrap());
    }

    /// A name this libseccomp does not know is left out of the filter
    /// rather than failing the launch — and named on stderr, because the
    /// sandbox is weaker than the profile asked for.
    #[test]
    fn a_name_this_libseccomp_does_not_know_is_skipped_and_reported() {
        let set = RuleSet {
            eperm: vec!["keyctl".to_owned(), "nosuchcall".to_owned()],
            enosys: vec![],
            ioctl_eperm: vec![],
        };
        let built = build(&set, false).unwrap();
        assert_eq!(built.skipped, ["nosuchcall"]);
        assert_eq!(built.rules, 1);
        let one = RuleSet {
            eperm: vec!["keyctl".to_owned()],
            enosys: vec![],
            ioctl_eperm: vec![],
        };
        assert_eq!(compile(&set, false).unwrap(), compile(&one, false).unwrap());
    }

    /// Named once per process however many sandboxes are compiled — an
    /// instance with a D-Bus proxy compiles twice — and a compile with
    /// nothing to skip does not use up the one report.
    #[test]
    fn skipped_names_are_named_once_and_only_by_a_compile_that_has_any() {
        let noted = AtomicBool::new(false);
        let none: [String; 0] = [];
        assert!(!take_note(&none, &noted));
        let some = ["nosuchcall".to_owned()];
        assert!(take_note(&some, &noted));
        assert!(!take_note(&some, &noted));
    }

    #[test]
    fn logging_keeps_the_rules_and_changes_only_the_action() {
        let set = RuleSet::default_set();
        let quiet = compile(&set, false).unwrap().unwrap();
        let logged = compile(&set, true).unwrap().unwrap();
        assert_ne!(quiet, logged, "the match action must differ");
        let ks: Vec<u32> = instructions(&logged.bytes).iter().map(|i| i.3).collect();
        // SECCOMP_RET_LOG, and no SECCOMP_RET_ERRNO with EPERM left.
        assert!(ks.contains(&0x7ffc_0000));
        assert!(!ks.contains(&(0x0005_0000 | 1)));
        // The bad-arch kill is an ABI gate, not one of the rules, so the
        // log switch does not soften it.
        assert!(ks.contains(&0x8000_0000));
    }
}
