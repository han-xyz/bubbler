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

/// Syscalls answered with `ENOSYS` by *number*, because libseccomp 2.6.0
/// has no name for them: the newest of the mount API (`open_tree_attr`),
/// the namespace-listing call (`listns`) and `fchroot`. Numbers from
/// `asm/unistd_64.h`; post-424 numbers are shared with i386, which
/// `asm/unistd_32.h` confirms for 467 and 470. `fchroot` is proposed and
/// not merged, so 472 is allocated to nothing yet and the rule denies a
/// number that already answers `ENOSYS`;
/// `no_numbered_rule_names_a_number_the_headers_give_to_another_call`
/// is what fails the day a kernel gives it to some other call.
///
/// They are added through [`ScmpSyscall::from`] so libseccomp's name
/// table is never consulted, and they go into the filter *before* the
/// architectures of `EXTRA_ARCHES`: libseccomp translates a rule to a
/// second architecture through the syscall's name, and a number the
/// native table cannot name answers `EFAULT` instead (measured with
/// libseccomp 2.6.0 and i386 in the filter). So these three rules hold
/// for the build architecture alone, where the named mount-API rules of
/// [`DEFAULT_ENOSYS`] hold for both. The name is kept beside the number
/// so a profile can `allow` it and so the day libseccomp learns the name
/// is a test failure rather than a duplicate rule.
// The mount-API class this closes is CVE-2021-41133; flatpak carries the
// same numbers in `flatpak-syscalls-private.h`.
pub const DEFAULT_ENOSYS_NUMBERED: &[(&str, i32)] =
    &[("open_tree_attr", 467), ("listns", 470), ("fchroot", 472)];

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
    /// Syscalls denied by number, each with the name a profile names it
    /// by and the errno it currently returns. See
    /// [`DEFAULT_ENOSYS_NUMBERED`]; `deny` of one of these names moves
    /// its errno here rather than pushing the bare name into `eperm` or
    /// `enosys`, since libseccomp cannot resolve it by name either way.
    pub enosys_numbered: Vec<(String, i32, Errno)>,
    /// `ioctl` request numbers denied with `EPERM`, matched on the low 32
    /// bits of argument 1.
    pub ioctl_eperm: Vec<u32>,
    /// Whether the hand-written prefix holds `personality` to
    /// [`PERSONALITY_ALLOWED`]; off when `allow "personality"` is in the
    /// profile.
    pub personality: bool,
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
            enosys_numbered: DEFAULT_ENOSYS_NUMBERED
                .iter()
                .map(|(name, nr)| ((*name).to_owned(), *nr, Errno::Enosys))
                .collect(),
            ioctl_eperm: DEFAULT_IOCTL_EPERM.to_vec(),
            personality: true,
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
            if name == "personality" {
                set.personality = false;
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
            // A numbered name has no name libseccomp resolves, so pushing
            // it into `eperm`/`enosys` like every other `deny` would only
            // leave it unresolvable and skipped — fully allowed instead
            // of denied. It stays in `enosys_numbered` with the errno the
            // profile chose.
            if let Some((_, nr)) = DEFAULT_ENOSYS_NUMBERED.iter().find(|(n, _)| n == name) {
                set.enosys_numbered.push((name.clone(), *nr, *errno));
                continue;
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
        self.enosys_numbered.retain(|(n, _, _)| n != name);
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
    // The prefix goes out only together with libseccomp's program: it
    // ends by falling into libseccomp's first instruction, so on its own
    // it is not a filter the kernel would accept. A rule set that keeps
    // the prefix and no rule at all is therefore no filter either.
    let mut bytes = match set.personality {
        true => personality_prefix(log),
        false => Vec::new(),
    };
    bytes.extend(export(&built.filter)?);
    Ok(Some(Program {
        arches: ARCHES,
        bytes,
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
    let mut seen: BTreeSet<i32> = BTreeSet::new();
    // Before the architectures on purpose: `man 3 seccomp_arch_add` says
    // a rule added before an architecture does not reach it, and that is
    // the only way these three go in at all. libseccomp translates a
    // rule to another architecture through the syscall's *name*, and
    // answers `EFAULT` for a number the native table cannot name
    // (measured with libseccomp 2.6.0 and i386 in the filter). So the
    // choice is a rule on the build architecture or no rule; a 32-bit
    // binary in the sandbox still reaches these three numbers, which is
    // recorded in `docs/threat-model.md`.
    for (_, nr, errno) in &set.enosys_numbered {
        let nr = ScmpSyscall::from(*nr);
        if !seen.insert(nr.into()) {
            continue;
        }
        filter.add_rule(action(log, *errno), nr).map_err(failed)?;
    }
    // `man 3 seccomp_arch_add`: rules added after an architecture is
    // added reach every architecture in the filter, and rules added
    // before it do not. So the architectures come first.
    for arch in EXTRA_ARCHES {
        filter.add_arch(*arch).map_err(failed)?;
    }
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

/// The persona values a sandbox may set: `PER_LINUX`, `PER_LINUX32`,
/// `UNAME26`, both together, and the query. Everything else — the
/// `ADDR_NO_RANDOMIZE`, `READ_IMPLIES_EXEC` and `MMAP_PAGE_ZERO` that
/// turn off an exploit mitigation among them — is `EPERM`. Values from
/// `linux/personality.h`.
pub const PERSONALITY_ALLOWED: [u32; 5] = [0x0, 0x8, 0x2_0000, 0x2_0008, 0xffff_ffff];

/// `AUDIT_ARCH_X86_64` and `AUDIT_ARCH_I386` from `linux/audit.h`.
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const AUDIT_ARCH_I386: u32 = 0x4000_0003;
/// `__NR_personality` from `asm/unistd_64.h` and `asm/unistd_32.h`.
const NR_PERSONALITY_X86_64: u32 = 135;
const NR_PERSONALITY_I386: u32 = 136;
/// Instruction codes from `linux/bpf_common.h`: `BPF_LD | BPF_W |
/// BPF_ABS`, `BPF_JMP | BPF_JEQ | BPF_K`, `BPF_JMP | BPF_JA` and
/// `BPF_RET | BPF_K`.
const BPF_LD_W_ABS: u16 = 0x0020;
const BPF_JEQ_K: u16 = 0x0015;
const BPF_JA: u16 = 0x0005;
const BPF_RET_K: u16 = 0x0006;
/// Filter return values from `linux/seccomp.h`.
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;

/// One `struct sock_filter` as its little-endian bytes.
fn insn(code: u16, jt: u8, jf: u8, k: u32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[..2].copy_from_slice(&code.to_le_bytes());
    b[2] = jt;
    b[3] = jf;
    b[4..].copy_from_slice(&k.to_le_bytes());
    b
}

/// A cBPF block that returns `EPERM` (or logs) for `personality` with an
/// argument outside [`PERSONALITY_ALLOWED`] and otherwise falls off its
/// end, so it can be placed before libseccomp's program: cBPF jumps are
/// relative and forward, so a block whose last instruction jumps to the
/// one after it is a prefix of any program. libseccomp cannot express a
/// per-argument allowlist in a default-allow filter — two comparisons on
/// one argument are `EINVAL` and an `ALLOW` rule is `EACCES` — which is
/// why this is written by hand.
///
/// Offsets are `struct seccomp_data` from `linux/seccomp.h`: `nr` 0,
/// `arch` 4, `args[0]` 16, of which the low word is what the kernel
/// reads, `personality` taking an `unsigned int`. The comment on each
/// line is its index, and a jump from index `i` lands at `i + 1 + jt`.
/// Where the filter carries no i386 the second branch never matches and
/// the main program kills the foreign ABI after the prefix falls
/// through.
pub(crate) fn personality_prefix(log: bool) -> Vec<u8> {
    let deny = match log {
        true => SECCOMP_RET_LOG,
        false => SECCOMP_RET_ERRNO | Errno::Eperm.raw() as u32,
    };
    let block = [
        insn(BPF_LD_W_ABS, 0, 0, 4),                   // 0
        insn(BPF_JEQ_K, 0, 2, AUDIT_ARCH_X86_64),      // 1 -> 2 | 4
        insn(BPF_LD_W_ABS, 0, 0, 0),                   // 2
        insn(BPF_JEQ_K, 3, 9, NR_PERSONALITY_X86_64),  // 3 -> 7 | 13
        insn(BPF_JEQ_K, 0, 8, AUDIT_ARCH_I386),        // 4 -> 5 | 13
        insn(BPF_LD_W_ABS, 0, 0, 0),                   // 5
        insn(BPF_JEQ_K, 0, 6, NR_PERSONALITY_I386),    // 6 -> 7 | 13
        insn(BPF_LD_W_ABS, 0, 0, 16),                  // 7
        insn(BPF_JEQ_K, 4, 0, PERSONALITY_ALLOWED[0]), // 8 -> 13
        insn(BPF_JEQ_K, 3, 0, PERSONALITY_ALLOWED[1]), // 9 -> 13
        insn(BPF_JEQ_K, 2, 0, PERSONALITY_ALLOWED[2]), // 10 -> 13
        insn(BPF_JEQ_K, 1, 0, PERSONALITY_ALLOWED[3]), // 11 -> 13
        insn(BPF_JEQ_K, 0, 1, PERSONALITY_ALLOWED[4]), // 12 -> 13 | 14
        insn(BPF_JA, 0, 0, 1),                         // 13 -> 15, libseccomp's first
        insn(BPF_RET_K, 0, 0, deny),                   // 14
    ];
    block.concat()
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

    /// The three numbered rules exist because this libseccomp has no
    /// name for them. When a later libseccomp learns the names, this
    /// test is what says so: move the entry to [`DEFAULT_ENOSYS`], where
    /// it reaches i386 as well, and drop it from here.
    #[test]
    fn the_numbered_rules_are_the_ones_this_libseccomp_cannot_name() {
        for (name, _) in DEFAULT_ENOSYS_NUMBERED {
            assert_eq!(
                syscall_number(name),
                None,
                "{name} has a name now: move it to DEFAULT_ENOSYS"
            );
        }
        let set = RuleSet::default_set();
        assert_eq!(set.enosys_numbered.len(), DEFAULT_ENOSYS_NUMBERED.len());
        assert_eq!(
            set.enosys_numbered[0],
            ("open_tree_attr".to_owned(), 467, Errno::Enosys)
        );
    }

    /// A rule written as a number denies whatever the kernel puts on that
    /// number, and a profile can only take it back by a name nobody would
    /// know to type. So each number is measured against this host's own
    /// `asm/unistd_64.h`: a number the headers give to another call fails
    /// here, and the entry has to go.
    #[test]
    fn no_numbered_rule_names_a_number_the_headers_give_to_another_call() {
        // A build host without kernel headers has nothing to measure
        // against, the way a host without `bwrap` has no sandbox to test.
        let Ok(header) = std::fs::read_to_string("/usr/include/asm/unistd_64.h") else {
            println!("no /usr/include/asm/unistd_64.h on this host; nothing to check");
            return;
        };
        let allocated: Vec<(&str, i32)> = header
            .lines()
            .filter_map(|line| line.trim().strip_prefix("#define __NR_"))
            .filter_map(|rest| rest.split_once(char::is_whitespace))
            .filter_map(|(name, number)| Some((name, number.trim().parse().ok()?)))
            .collect();
        for (name, number) in DEFAULT_ENOSYS_NUMBERED {
            let Some((allocated_to, _)) = allocated.iter().find(|(_, n)| n == number) else {
                continue;
            };
            assert_eq!(
                allocated_to, name,
                "syscall {number} is `{allocated_to}` in this host's headers, \
                 not `{name}`: the rule denies `{allocated_to}` in every sandbox"
            );
        }
    }

    /// A profile that names one takes its rule back, exactly as it does
    /// for a name on either of the two lists.
    #[test]
    fn allowing_a_numbered_syscall_by_name_takes_its_rule_back() {
        let cfg = SeccompConfig {
            allow: vec!["open_tree_attr".to_owned()],
            ..SeccompConfig::default()
        };
        let set = RuleSet::with(&cfg).unwrap();
        assert!(
            !set.enosys_numbered
                .iter()
                .any(|(n, _, _)| n == "open_tree_attr")
        );
        assert_eq!(set.enosys_numbered.len(), DEFAULT_ENOSYS_NUMBERED.len() - 1);
    }

    /// A `deny` of a numbered syscall must never go through the name
    /// path: libseccomp cannot resolve `open_tree_attr`, `listns` or
    /// `fchroot` by name, so pushing the bare name into `eperm`/`enosys`
    /// — what `deny` does for every other syscall — leaves it
    /// unresolvable, `skipped` by `build`, and therefore fully allowed.
    /// A profile author who denies one of these three must get the
    /// errno they asked for, never the opposite of what they wrote.
    #[test]
    fn denying_a_numbered_syscall_keeps_it_numbered_with_the_chosen_errno() {
        let cfg = SeccompConfig {
            deny: vec![
                ("open_tree_attr".to_owned(), Errno::Eperm),
                ("listns".to_owned(), Errno::Enosys),
            ],
            ..SeccompConfig::default()
        };
        let set = RuleSet::with(&cfg).unwrap();
        for name in ["open_tree_attr", "listns"] {
            let name = name.to_owned();
            assert!(!set.eperm.contains(&name), "{name} leaked into eperm");
            assert!(!set.enosys.contains(&name), "{name} leaked into enosys");
        }
        assert!(
            set.enosys_numbered
                .contains(&("open_tree_attr".to_owned(), 467, Errno::Eperm))
        );
        assert!(
            set.enosys_numbered
                .contains(&("listns".to_owned(), 470, Errno::Enosys))
        );
        let built = build(&set, false).unwrap();
        assert!(built.skipped.is_empty(), "{:?}", built.skipped);
    }

    /// The numbers really reach the program. They go in before the
    /// second architecture is added: libseccomp translates a rule to
    /// another architecture through the syscall's name, and answers
    /// `EFAULT` for a number the native table cannot name (measured with
    /// libseccomp 2.6.0 and i386 in the filter), so the wrong order is a
    /// failed compile rather than a quietly weaker filter.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_numbered_rules_are_compiled_into_the_program() {
        let program = compile(&RuleSet::default_set(), false).unwrap().unwrap();
        let insns = instructions(&program.bytes);
        for (name, nr) in DEFAULT_ENOSYS_NUMBERED {
            let k = u32::try_from(*nr).expect("a syscall number is positive");
            assert!(
                insns.iter().any(|i| i.3 == k),
                "no comparison for {name} ({nr})"
            );
        }
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

    /// Instructions in the default filter: the fifteen of
    /// [`personality_prefix`] and libseccomp's 125. libseccomp emits a
    /// balanced search tree over the syscall numbers of each
    /// architecture, so its share is a measurement rather than a
    /// formula; the total is pinned here so that a rule added by
    /// accident, or an architecture dropped from the filter, is a test
    /// failure.
    #[cfg(target_arch = "x86_64")]
    const DEFAULT_LEN: usize = 140;

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
        assert_eq!(
            instructions(&program.bytes)[personality_prefix(false).len() / 8],
            (0x0020, 0, 0, 4)
        );
    }

    /// The prefix is a closed block: every jump lands inside it or on
    /// its end, it loads arch, nr and args[0], names the five allowed
    /// personas and returns EPERM for anything else.
    #[test]
    fn the_personality_prefix_allows_five_values_and_falls_through() {
        let insns = instructions(&personality_prefix(false));
        let n = insns.len();
        for (i, (code, jt, jf, _)) in insns.iter().enumerate() {
            if code & 0x07 == 0x05 && *code != 0x0005 {
                // BPF_JMP conditional: both targets inside or at the end.
                assert!(
                    i + 1 + *jt as usize <= n && i + 1 + *jf as usize <= n,
                    "jump {i} leaves the block"
                );
            }
        }
        assert_eq!(insns[0], (0x0020, 0, 0, 4), "arch first");
        assert!(insns.contains(&(0x0020, 0, 0, 0)), "nr loaded");
        assert!(insns.contains(&(0x0020, 0, 0, 16)), "args[0] loaded");
        for value in PERSONALITY_ALLOWED {
            assert!(
                insns.iter().any(|i| i.0 == 0x0015 && i.3 == value),
                "no allow for {value:#x}"
            );
        }
        // BPF_RET | BPF_K with SECCOMP_RET_ERRNO | EPERM.
        assert!(insns.contains(&(0x0006, 0, 0, 0x0005_0001)));
        assert!(
            !insns.iter().any(|i| i.3 == 0x8000_0000),
            "the prefix never kills"
        );
    }

    #[test]
    fn the_prefix_logs_instead_of_failing_when_asked() {
        let insns = instructions(&personality_prefix(true));
        assert!(insns.contains(&(0x0006, 0, 0, 0x7ffc_0000)));
    }

    /// The prefix run over a synthetic `struct seccomp_data`, answering
    /// with the filter return value or `None` when the block fell
    /// through to the instruction after it — which is where
    /// libseccomp's program starts. This is what catches a miscounted
    /// jump: the offsets are written out by hand, so nothing but
    /// executing them proves they land where the comments say.
    fn run_prefix(arch: u32, nr: u32, arg0: u64) -> Option<u32> {
        let insns = instructions(&personality_prefix(false));
        let mut data = [0u8; 64];
        data[..4].copy_from_slice(&nr.to_le_bytes());
        data[4..8].copy_from_slice(&arch.to_le_bytes());
        data[16..24].copy_from_slice(&arg0.to_le_bytes());
        let (mut pc, mut acc) = (0usize, 0u32);
        while pc < insns.len() {
            let (code, jt, jf, k) = insns[pc];
            pc += 1;
            match code {
                0x0020 => {
                    let at = k as usize;
                    acc = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
                }
                0x0015 => pc += usize::from(if acc == k { jt } else { jf }),
                0x0005 => pc += k as usize,
                0x0006 => return Some(k),
                other => panic!("{other:#06x} is not one of the four the prefix uses"),
            }
        }
        assert_eq!(pc, insns.len(), "a jump left the block");
        None
    }

    /// Only `personality` is answered, and only the five allowed values
    /// reach libseccomp's program. The kernel reads the argument as an
    /// `unsigned int`, so a set high half is not a way past the
    /// comparisons.
    #[test]
    fn the_prefix_denies_every_persona_outside_the_allowlist() {
        for (arch, nr) in [(0xc000_003eu32, 135u32), (0x4000_0003, 136)] {
            for value in PERSONALITY_ALLOWED {
                assert_eq!(run_prefix(arch, nr, u64::from(value)), None, "{value:#x}");
            }
            // ADDR_NO_RANDOMIZE, READ_IMPLIES_EXEC, MMAP_PAGE_ZERO and an
            // allowed persona with one more bit set.
            for value in [0x4_0000u32, 0x40_0000, 0x10_0000, 0x9] {
                assert_eq!(
                    run_prefix(arch, nr, u64::from(value)),
                    Some(0x0005_0001),
                    "{value:#x}"
                );
            }
            assert_eq!(
                run_prefix(arch, nr, 0xdead_0000_0004_0000),
                Some(0x0005_0001)
            );
            // Every other syscall falls through untouched.
            assert_eq!(run_prefix(arch, 39, 0x4_0000), None);
        }
        // An architecture the block does not name is left to the main
        // program, which kills a foreign ABI. AUDIT_ARCH_AARCH64.
        assert_eq!(run_prefix(0xc000_00b7, 92, 0x4_0000), None);
    }

    /// The default program is the prefix followed by libseccomp's output.
    #[test]
    fn the_default_program_starts_with_the_personality_prefix() {
        let program = compile(&RuleSet::default_set(), false).unwrap().unwrap();
        let prefix = personality_prefix(false);
        assert!(program.bytes.starts_with(&prefix));
        assert_eq!(
            instructions(&program.bytes)[prefix.len() / 8],
            (0x0020, 0, 0, 4)
        );
    }

    #[test]
    fn allowing_personality_drops_the_prefix() {
        let cfg = SeccompConfig {
            allow: vec!["personality".to_owned()],
            ..SeccompConfig::default()
        };
        let set = RuleSet::with(&cfg).unwrap();
        assert!(!set.personality);
        let program = compile(&set, false).unwrap().unwrap();
        assert_eq!(instructions(&program.bytes)[0], (0x0020, 0, 0, 4));
        assert!(!program.bytes.starts_with(&personality_prefix(false)));
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
                .chain(
                    RuleSet::default_set()
                        .enosys_numbered
                        .into_iter()
                        .map(|(n, _, _)| n),
                )
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
            enosys_numbered: Vec::new(),
            ioctl_eperm: vec![],
            personality: false,
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
            enosys_numbered: Vec::new(),
            ioctl_eperm: DEFAULT_IOCTL_EPERM.to_vec(),
            personality: false,
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
            enosys_numbered: Vec::new(),
            ioctl_eperm: vec![],
            personality: false,
        };
        let one = RuleSet {
            eperm: vec!["keyctl".to_owned()],
            enosys: vec![],
            enosys_numbered: Vec::new(),
            ioctl_eperm: vec![],
            personality: false,
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
            enosys_numbered: Vec::new(),
            ioctl_eperm: vec![],
            personality: false,
        };
        let built = build(&set, false).unwrap();
        assert_eq!(built.skipped, ["nosuchcall"]);
        assert_eq!(built.rules, 1);
        let one = RuleSet {
            eperm: vec!["keyctl".to_owned()],
            enosys: vec![],
            enosys_numbered: Vec::new(),
            ioctl_eperm: vec![],
            personality: false,
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
