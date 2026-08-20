//! The seccomp denylist: which syscalls a sandbox loses by default, the
//! per-architecture syscall name table, the rule set a profile's
//! `seccomp` node produces, and the BPF programs it compiles into.

use std::collections::BTreeMap;

use rustix::io::Errno as OsErrno;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::error::LaunchError;

/// Syscalls the default filter answers with `EPERM`: the kernel keyring,
/// NUMA and VM controls, module and kexec loading, accounting, quota, the
/// system clock and the host name — each either already unreachable in
/// bubbler's baseline sandbox or unused by desktop apps. The
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
    "sethostname",
    "setdomainname",
    "nfsservctl",
    "vm86",
    "vm86old",
    "modify_ldt",
];

/// Syscalls the default filter answers with `ENOSYS`, so libc falls back
/// to the older call instead of failing: seccomp cannot inspect `clone3`'s
/// `clone_args` struct, and the new mount API can rewrite the sandbox's
/// own VFS (CVE-2021-41133).
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

/// What a denied syscall returns to the sandboxed process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Errno {
    /// The call is refused outright.
    #[default]
    Eperm,
    /// The call looks unimplemented, which makes libc use its fallback.
    Enosys,
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
/// Names absent on the build architecture stay in the lists; dropping them
/// is the compile step's job.
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
        Self {
            eperm: DEFAULT_EPERM.iter().map(|s| (*s).to_owned()).collect(),
            enosys: DEFAULT_ENOSYS.iter().map(|s| (*s).to_owned()).collect(),
            ioctl_eperm: DEFAULT_IOCTL_EPERM.to_vec(),
        }
    }

    /// The default set with `cfg`'s allows removed and its denies appended,
    /// or `None` when the profile disabled the filter. `allow "ioctl"` is
    /// the only way to take back the [`DEFAULT_IOCTL_EPERM`] rules, and
    /// `deny "ioctl"` replaces them with a rule matching every request.
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

/// The architecture the filter is compiled for. seccompiler embeds a check
/// for it and kills a caller from any other ABI, so a 32-bit binary in the
/// sandbox dies rather than slipping past the rules.
#[cfg(target_arch = "x86_64")]
const TARGET: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const TARGET: TargetArch = TargetArch::aarch64;
#[cfg(target_arch = "riscv64")]
const TARGET: TargetArch = TargetArch::riscv64;

/// Mask applied to `ioctl`'s request argument: the kernel passes it as 64
/// bits, so without it a request of `0x1_0000_5412` would not be TIOCSTI
/// to the filter but still is to the driver.
const REQUEST_MASK: u64 = 0xFFFF_FFFF;

/// The rule set as loadable BPF, one program per error it uses (`EPERM`
/// first, then `ENOSYS`), each ready to be handed to `--add-seccomp-fd`.
/// Everything not named is allowed. `log` turns matches into audit log
/// entries instead of errors, for finding over-denies while writing a
/// profile. Names this architecture never had are skipped.
pub fn compile(set: &RuleSet, log: bool) -> Result<Vec<Vec<u8>>, LaunchError> {
    let groups = [
        (&set.eperm, OsErrno::PERM, set.ioctl_eperm.as_slice()),
        (&set.enosys, OsErrno::NOSYS, &[][..]),
    ];
    let mut out = Vec::new();
    for (names, errno, ioctl) in groups {
        let rules = rules_for(names, ioctl, log)?;
        if rules.is_empty() {
            continue;
        }
        let action = match log {
            true => SeccompAction::Log,
            // The errno is what the syscall returns, so it is the raw
            // positive number, not a negated return value.
            false => SeccompAction::Errno(errno.raw_os_error() as u32),
        };
        let filter = SeccompFilter::new(rules, SeccompAction::Allow, action, TARGET)
            .map_err(|e| LaunchError::Seccomp(e.to_string()))?;
        let program: BpfProgram = filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| LaunchError::Seccomp(e.to_string()))?;
        out.push(program_bytes(&program));
    }
    Ok(out)
}

/// One error's rules keyed by syscall number: an empty rule chain matches
/// the syscall whatever its arguments are, and the `ioctl` requests in
/// `ioctl_eperm` become one argument-filtered rule each. `note` reports
/// skipped names on stderr; it is the same switch that turns the filter
/// into an audit log, since both exist to explain what a profile got.
fn rules_for(
    names: &[String],
    ioctl_eperm: &[u32],
    note: bool,
) -> Result<BTreeMap<i64, Vec<SeccompRule>>, LaunchError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for name in names {
        match syscall_number(name) {
            Some(nr) => {
                rules.insert(nr, Vec::new());
            }
            // Not an error: the default list is written for every
            // architecture, and a syscall this one never had cannot be
            // called on it.
            None => {
                if note {
                    eprintln!("bubbler: seccomp: no `{name}` on this architecture; skipping");
                }
            }
        }
    }
    let Some(ioctl) = syscall_number("ioctl") else {
        return Ok(rules);
    };
    // A blanket deny of `ioctl` already covers every request, so adding
    // the argument-filtered rules to it would only narrow it.
    if ioctl_eperm.is_empty() || rules.contains_key(&ioctl) {
        return Ok(rules);
    }
    let mut chain = Vec::with_capacity(ioctl_eperm.len());
    for request in ioctl_eperm {
        let cond = SeccompCondition::new(
            1,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(REQUEST_MASK),
            u64::from(*request),
        )
        .map_err(|e| LaunchError::Seccomp(e.to_string()))?;
        chain.push(SeccompRule::new(vec![cond]).map_err(|e| LaunchError::Seccomp(e.to_string()))?);
    }
    rules.insert(ioctl, chain);
    Ok(rules)
}

/// A compiled program as the bytes bwrap reads: `struct sock_filter` is
/// `code` `jt` `jf` `k` in native order, eight bytes per instruction, and
/// seccompiler only builds for little-endian targets.
fn program_bytes(program: &BpfProgram) -> Vec<u8> {
    let mut out = Vec::with_capacity(program.len() * 8);
    for i in program {
        out.extend_from_slice(&i.code.to_le_bytes());
        out.push(i.jt);
        out.push(i.jf);
        out.extend_from_slice(&i.k.to_le_bytes());
    }
    out
}

// Syscall numbers for the architecture bubbler is built for, sorted by
// name so `syscall_number` can binary-search it.
// Source: Linux 7.1 `arch/x86/entry/syscalls/syscall_64.tbl`, ABI columns
// `common` and `64`. The x32 ABI is left out: seccompiler's architecture
// check kills an x32 caller before any rule runs.
#[cfg(target_arch = "x86_64")]
static SYSCALLS: &[(&str, i64)] = &[
    ("_sysctl", 156),
    ("accept", 43),
    ("accept4", 288),
    ("access", 21),
    ("acct", 163),
    ("add_key", 248),
    ("adjtimex", 159),
    ("afs_syscall", 183),
    ("alarm", 37),
    ("arch_prctl", 158),
    ("bind", 49),
    ("bpf", 321),
    ("brk", 12),
    ("cachestat", 451),
    ("capget", 125),
    ("capset", 126),
    ("chdir", 80),
    ("chmod", 90),
    ("chown", 92),
    ("chroot", 161),
    ("clock_adjtime", 305),
    ("clock_getres", 229),
    ("clock_gettime", 228),
    ("clock_nanosleep", 230),
    ("clock_settime", 227),
    ("clone", 56),
    ("clone3", 435),
    ("close", 3),
    ("close_range", 436),
    ("connect", 42),
    ("copy_file_range", 326),
    ("creat", 85),
    ("create_module", 174),
    ("delete_module", 176),
    ("dup", 32),
    ("dup2", 33),
    ("dup3", 292),
    ("epoll_create", 213),
    ("epoll_create1", 291),
    ("epoll_ctl", 233),
    ("epoll_ctl_old", 214),
    ("epoll_pwait", 281),
    ("epoll_pwait2", 441),
    ("epoll_wait", 232),
    ("epoll_wait_old", 215),
    ("eventfd", 284),
    ("eventfd2", 290),
    ("execve", 59),
    ("execveat", 322),
    ("exit", 60),
    ("exit_group", 231),
    ("faccessat", 269),
    ("faccessat2", 439),
    ("fadvise64", 221),
    ("fallocate", 285),
    ("fanotify_init", 300),
    ("fanotify_mark", 301),
    ("fchdir", 81),
    ("fchmod", 91),
    ("fchmodat", 268),
    ("fchmodat2", 452),
    ("fchown", 93),
    ("fchownat", 260),
    ("fcntl", 72),
    ("fdatasync", 75),
    ("fgetxattr", 193),
    ("file_getattr", 468),
    ("file_setattr", 469),
    ("finit_module", 313),
    ("flistxattr", 196),
    ("flock", 73),
    ("fork", 57),
    ("fremovexattr", 199),
    ("fsconfig", 431),
    ("fsetxattr", 190),
    ("fsmount", 432),
    ("fsopen", 430),
    ("fspick", 433),
    ("fstat", 5),
    ("fstatfs", 138),
    ("fsync", 74),
    ("ftruncate", 77),
    ("futex", 202),
    ("futex_requeue", 456),
    ("futex_wait", 455),
    ("futex_waitv", 449),
    ("futex_wake", 454),
    ("futimesat", 261),
    ("get_kernel_syms", 177),
    ("get_mempolicy", 239),
    ("get_robust_list", 274),
    ("get_thread_area", 211),
    ("getcpu", 309),
    ("getcwd", 79),
    ("getdents", 78),
    ("getdents64", 217),
    ("getegid", 108),
    ("geteuid", 107),
    ("getgid", 104),
    ("getgroups", 115),
    ("getitimer", 36),
    ("getpeername", 52),
    ("getpgid", 121),
    ("getpgrp", 111),
    ("getpid", 39),
    ("getpmsg", 181),
    ("getppid", 110),
    ("getpriority", 140),
    ("getrandom", 318),
    ("getresgid", 120),
    ("getresuid", 118),
    ("getrlimit", 97),
    ("getrusage", 98),
    ("getsid", 124),
    ("getsockname", 51),
    ("getsockopt", 55),
    ("gettid", 186),
    ("gettimeofday", 96),
    ("getuid", 102),
    ("getxattr", 191),
    ("getxattrat", 464),
    ("init_module", 175),
    ("inotify_add_watch", 254),
    ("inotify_init", 253),
    ("inotify_init1", 294),
    ("inotify_rm_watch", 255),
    ("io_cancel", 210),
    ("io_destroy", 207),
    ("io_getevents", 208),
    ("io_pgetevents", 333),
    ("io_setup", 206),
    ("io_submit", 209),
    ("io_uring_enter", 426),
    ("io_uring_register", 427),
    ("io_uring_setup", 425),
    ("ioctl", 16),
    ("ioperm", 173),
    ("iopl", 172),
    ("ioprio_get", 252),
    ("ioprio_set", 251),
    ("kcmp", 312),
    ("kexec_file_load", 320),
    ("kexec_load", 246),
    ("keyctl", 250),
    ("kill", 62),
    ("landlock_add_rule", 445),
    ("landlock_create_ruleset", 444),
    ("landlock_restrict_self", 446),
    ("lchown", 94),
    ("lgetxattr", 192),
    ("link", 86),
    ("linkat", 265),
    ("listen", 50),
    ("listmount", 458),
    ("listns", 470),
    ("listxattr", 194),
    ("listxattrat", 465),
    ("llistxattr", 195),
    ("lookup_dcookie", 212),
    ("lremovexattr", 198),
    ("lseek", 8),
    ("lsetxattr", 189),
    ("lsm_get_self_attr", 459),
    ("lsm_list_modules", 461),
    ("lsm_set_self_attr", 460),
    ("lstat", 6),
    ("madvise", 28),
    ("map_shadow_stack", 453),
    ("mbind", 237),
    ("membarrier", 324),
    ("memfd_create", 319),
    ("memfd_secret", 447),
    ("migrate_pages", 256),
    ("mincore", 27),
    ("mkdir", 83),
    ("mkdirat", 258),
    ("mknod", 133),
    ("mknodat", 259),
    ("mlock", 149),
    ("mlock2", 325),
    ("mlockall", 151),
    ("mmap", 9),
    ("modify_ldt", 154),
    ("mount", 165),
    ("mount_setattr", 442),
    ("move_mount", 429),
    ("move_pages", 279),
    ("mprotect", 10),
    ("mq_getsetattr", 245),
    ("mq_notify", 244),
    ("mq_open", 240),
    ("mq_timedreceive", 243),
    ("mq_timedsend", 242),
    ("mq_unlink", 241),
    ("mremap", 25),
    ("mseal", 462),
    ("msgctl", 71),
    ("msgget", 68),
    ("msgrcv", 70),
    ("msgsnd", 69),
    ("msync", 26),
    ("munlock", 150),
    ("munlockall", 152),
    ("munmap", 11),
    ("name_to_handle_at", 303),
    ("nanosleep", 35),
    ("newfstatat", 262),
    ("nfsservctl", 180),
    ("open", 2),
    ("open_by_handle_at", 304),
    ("open_tree", 428),
    ("open_tree_attr", 467),
    ("openat", 257),
    ("openat2", 437),
    ("pause", 34),
    ("perf_event_open", 298),
    ("personality", 135),
    ("pidfd_getfd", 438),
    ("pidfd_open", 434),
    ("pidfd_send_signal", 424),
    ("pipe", 22),
    ("pipe2", 293),
    ("pivot_root", 155),
    ("pkey_alloc", 330),
    ("pkey_free", 331),
    ("pkey_mprotect", 329),
    ("poll", 7),
    ("ppoll", 271),
    ("prctl", 157),
    ("pread64", 17),
    ("preadv", 295),
    ("preadv2", 327),
    ("prlimit64", 302),
    ("process_madvise", 440),
    ("process_mrelease", 448),
    ("process_vm_readv", 310),
    ("process_vm_writev", 311),
    ("pselect6", 270),
    ("ptrace", 101),
    ("putpmsg", 182),
    ("pwrite64", 18),
    ("pwritev", 296),
    ("pwritev2", 328),
    ("query_module", 178),
    ("quotactl", 179),
    ("quotactl_fd", 443),
    ("read", 0),
    ("readahead", 187),
    ("readlink", 89),
    ("readlinkat", 267),
    ("readv", 19),
    ("reboot", 169),
    ("recvfrom", 45),
    ("recvmmsg", 299),
    ("recvmsg", 47),
    ("remap_file_pages", 216),
    ("removexattr", 197),
    ("removexattrat", 466),
    ("rename", 82),
    ("renameat", 264),
    ("renameat2", 316),
    ("request_key", 249),
    ("restart_syscall", 219),
    ("rmdir", 84),
    ("rseq", 334),
    ("rseq_slice_yield", 471),
    ("rt_sigaction", 13),
    ("rt_sigpending", 127),
    ("rt_sigprocmask", 14),
    ("rt_sigqueueinfo", 129),
    ("rt_sigreturn", 15),
    ("rt_sigsuspend", 130),
    ("rt_sigtimedwait", 128),
    ("rt_tgsigqueueinfo", 297),
    ("sched_get_priority_max", 146),
    ("sched_get_priority_min", 147),
    ("sched_getaffinity", 204),
    ("sched_getattr", 315),
    ("sched_getparam", 143),
    ("sched_getscheduler", 145),
    ("sched_rr_get_interval", 148),
    ("sched_setaffinity", 203),
    ("sched_setattr", 314),
    ("sched_setparam", 142),
    ("sched_setscheduler", 144),
    ("sched_yield", 24),
    ("seccomp", 317),
    ("security", 185),
    ("select", 23),
    ("semctl", 66),
    ("semget", 64),
    ("semop", 65),
    ("semtimedop", 220),
    ("sendfile", 40),
    ("sendmmsg", 307),
    ("sendmsg", 46),
    ("sendto", 44),
    ("set_mempolicy", 238),
    ("set_mempolicy_home_node", 450),
    ("set_robust_list", 273),
    ("set_thread_area", 205),
    ("set_tid_address", 218),
    ("setdomainname", 171),
    ("setfsgid", 123),
    ("setfsuid", 122),
    ("setgid", 106),
    ("setgroups", 116),
    ("sethostname", 170),
    ("setitimer", 38),
    ("setns", 308),
    ("setpgid", 109),
    ("setpriority", 141),
    ("setregid", 114),
    ("setresgid", 119),
    ("setresuid", 117),
    ("setreuid", 113),
    ("setrlimit", 160),
    ("setsid", 112),
    ("setsockopt", 54),
    ("settimeofday", 164),
    ("setuid", 105),
    ("setxattr", 188),
    ("setxattrat", 463),
    ("shmat", 30),
    ("shmctl", 31),
    ("shmdt", 67),
    ("shmget", 29),
    ("shutdown", 48),
    ("sigaltstack", 131),
    ("signalfd", 282),
    ("signalfd4", 289),
    ("socket", 41),
    ("socketpair", 53),
    ("splice", 275),
    ("stat", 4),
    ("statfs", 137),
    ("statmount", 457),
    ("statx", 332),
    ("swapoff", 168),
    ("swapon", 167),
    ("symlink", 88),
    ("symlinkat", 266),
    ("sync", 162),
    ("sync_file_range", 277),
    ("syncfs", 306),
    ("sysfs", 139),
    ("sysinfo", 99),
    ("syslog", 103),
    ("tee", 276),
    ("tgkill", 234),
    ("time", 201),
    ("timer_create", 222),
    ("timer_delete", 226),
    ("timer_getoverrun", 225),
    ("timer_gettime", 224),
    ("timer_settime", 223),
    ("timerfd_create", 283),
    ("timerfd_gettime", 287),
    ("timerfd_settime", 286),
    ("times", 100),
    ("tkill", 200),
    ("truncate", 76),
    ("tuxcall", 184),
    ("umask", 95),
    ("umount2", 166),
    ("uname", 63),
    ("unlink", 87),
    ("unlinkat", 263),
    ("unshare", 272),
    ("uprobe", 336),
    ("uretprobe", 335),
    ("uselib", 134),
    ("userfaultfd", 323),
    ("ustat", 136),
    ("utime", 132),
    ("utimensat", 280),
    ("utimes", 235),
    ("vfork", 58),
    ("vhangup", 153),
    ("vmsplice", 278),
    ("vserver", 236),
    ("wait4", 61),
    ("waitid", 247),
    ("write", 1),
    ("writev", 20),
];

// Source: Linux 7.1 `include/uapi/asm-generic/unistd.h`, 64-bit branch,
// equivalently `scripts/syscall.tbl` with the ABI set arm64 asks for in
// `arch/arm64/kernel/Makefile.syscalls`: common, 64, renameat, rlimit,
// memfd_secret.
#[cfg(target_arch = "aarch64")]
static SYSCALLS: &[(&str, i64)] = &[
    ("accept", 202),
    ("accept4", 242),
    ("acct", 89),
    ("add_key", 217),
    ("adjtimex", 171),
    ("bind", 200),
    ("bpf", 280),
    ("brk", 214),
    ("cachestat", 451),
    ("capget", 90),
    ("capset", 91),
    ("chdir", 49),
    ("chroot", 51),
    ("clock_adjtime", 266),
    ("clock_getres", 114),
    ("clock_gettime", 113),
    ("clock_nanosleep", 115),
    ("clock_settime", 112),
    ("clone", 220),
    ("clone3", 435),
    ("close", 57),
    ("close_range", 436),
    ("connect", 203),
    ("copy_file_range", 285),
    ("delete_module", 106),
    ("dup", 23),
    ("dup3", 24),
    ("epoll_create1", 20),
    ("epoll_ctl", 21),
    ("epoll_pwait", 22),
    ("epoll_pwait2", 441),
    ("eventfd2", 19),
    ("execve", 221),
    ("execveat", 281),
    ("exit", 93),
    ("exit_group", 94),
    ("faccessat", 48),
    ("faccessat2", 439),
    ("fadvise64", 223),
    ("fallocate", 47),
    ("fanotify_init", 262),
    ("fanotify_mark", 263),
    ("fchdir", 50),
    ("fchmod", 52),
    ("fchmodat", 53),
    ("fchmodat2", 452),
    ("fchown", 55),
    ("fchownat", 54),
    ("fcntl", 25),
    ("fdatasync", 83),
    ("fgetxattr", 10),
    ("file_getattr", 468),
    ("file_setattr", 469),
    ("finit_module", 273),
    ("flistxattr", 13),
    ("flock", 32),
    ("fremovexattr", 16),
    ("fsconfig", 431),
    ("fsetxattr", 7),
    ("fsmount", 432),
    ("fsopen", 430),
    ("fspick", 433),
    ("fstat", 80),
    ("fstatfs", 44),
    ("fsync", 82),
    ("ftruncate", 46),
    ("futex", 98),
    ("futex_requeue", 456),
    ("futex_wait", 455),
    ("futex_waitv", 449),
    ("futex_wake", 454),
    ("get_mempolicy", 236),
    ("get_robust_list", 100),
    ("getcpu", 168),
    ("getcwd", 17),
    ("getdents64", 61),
    ("getegid", 177),
    ("geteuid", 175),
    ("getgid", 176),
    ("getgroups", 158),
    ("getitimer", 102),
    ("getpeername", 205),
    ("getpgid", 155),
    ("getpid", 172),
    ("getppid", 173),
    ("getpriority", 141),
    ("getrandom", 278),
    ("getresgid", 150),
    ("getresuid", 148),
    ("getrlimit", 163),
    ("getrusage", 165),
    ("getsid", 156),
    ("getsockname", 204),
    ("getsockopt", 209),
    ("gettid", 178),
    ("gettimeofday", 169),
    ("getuid", 174),
    ("getxattr", 8),
    ("getxattrat", 464),
    ("init_module", 105),
    ("inotify_add_watch", 27),
    ("inotify_init1", 26),
    ("inotify_rm_watch", 28),
    ("io_cancel", 3),
    ("io_destroy", 1),
    ("io_getevents", 4),
    ("io_pgetevents", 292),
    ("io_setup", 0),
    ("io_submit", 2),
    ("io_uring_enter", 426),
    ("io_uring_register", 427),
    ("io_uring_setup", 425),
    ("ioctl", 29),
    ("ioprio_get", 31),
    ("ioprio_set", 30),
    ("kcmp", 272),
    ("kexec_file_load", 294),
    ("kexec_load", 104),
    ("keyctl", 219),
    ("kill", 129),
    ("landlock_add_rule", 445),
    ("landlock_create_ruleset", 444),
    ("landlock_restrict_self", 446),
    ("lgetxattr", 9),
    ("linkat", 37),
    ("listen", 201),
    ("listmount", 458),
    ("listns", 470),
    ("listxattr", 11),
    ("listxattrat", 465),
    ("llistxattr", 12),
    ("lookup_dcookie", 18),
    ("lremovexattr", 15),
    ("lseek", 62),
    ("lsetxattr", 6),
    ("lsm_get_self_attr", 459),
    ("lsm_list_modules", 461),
    ("lsm_set_self_attr", 460),
    ("madvise", 233),
    ("map_shadow_stack", 453),
    ("mbind", 235),
    ("membarrier", 283),
    ("memfd_create", 279),
    ("memfd_secret", 447),
    ("migrate_pages", 238),
    ("mincore", 232),
    ("mkdirat", 34),
    ("mknodat", 33),
    ("mlock", 228),
    ("mlock2", 284),
    ("mlockall", 230),
    ("mmap", 222),
    ("mount", 40),
    ("mount_setattr", 442),
    ("move_mount", 429),
    ("move_pages", 239),
    ("mprotect", 226),
    ("mq_getsetattr", 185),
    ("mq_notify", 184),
    ("mq_open", 180),
    ("mq_timedreceive", 183),
    ("mq_timedsend", 182),
    ("mq_unlink", 181),
    ("mremap", 216),
    ("mseal", 462),
    ("msgctl", 187),
    ("msgget", 186),
    ("msgrcv", 188),
    ("msgsnd", 189),
    ("msync", 227),
    ("munlock", 229),
    ("munlockall", 231),
    ("munmap", 215),
    ("name_to_handle_at", 264),
    ("nanosleep", 101),
    ("newfstatat", 79),
    ("nfsservctl", 42),
    ("open_by_handle_at", 265),
    ("open_tree", 428),
    ("open_tree_attr", 467),
    ("openat", 56),
    ("openat2", 437),
    ("perf_event_open", 241),
    ("personality", 92),
    ("pidfd_getfd", 438),
    ("pidfd_open", 434),
    ("pidfd_send_signal", 424),
    ("pipe2", 59),
    ("pivot_root", 41),
    ("pkey_alloc", 289),
    ("pkey_free", 290),
    ("pkey_mprotect", 288),
    ("ppoll", 73),
    ("prctl", 167),
    ("pread64", 67),
    ("preadv", 69),
    ("preadv2", 286),
    ("prlimit64", 261),
    ("process_madvise", 440),
    ("process_mrelease", 448),
    ("process_vm_readv", 270),
    ("process_vm_writev", 271),
    ("pselect6", 72),
    ("ptrace", 117),
    ("pwrite64", 68),
    ("pwritev", 70),
    ("pwritev2", 287),
    ("quotactl", 60),
    ("quotactl_fd", 443),
    ("read", 63),
    ("readahead", 213),
    ("readlinkat", 78),
    ("readv", 65),
    ("reboot", 142),
    ("recvfrom", 207),
    ("recvmmsg", 243),
    ("recvmsg", 212),
    ("remap_file_pages", 234),
    ("removexattr", 14),
    ("removexattrat", 466),
    ("renameat", 38),
    ("renameat2", 276),
    ("request_key", 218),
    ("restart_syscall", 128),
    ("rseq", 293),
    ("rseq_slice_yield", 471),
    ("rt_sigaction", 134),
    ("rt_sigpending", 136),
    ("rt_sigprocmask", 135),
    ("rt_sigqueueinfo", 138),
    ("rt_sigreturn", 139),
    ("rt_sigsuspend", 133),
    ("rt_sigtimedwait", 137),
    ("rt_tgsigqueueinfo", 240),
    ("sched_get_priority_max", 125),
    ("sched_get_priority_min", 126),
    ("sched_getaffinity", 123),
    ("sched_getattr", 275),
    ("sched_getparam", 121),
    ("sched_getscheduler", 120),
    ("sched_rr_get_interval", 127),
    ("sched_setaffinity", 122),
    ("sched_setattr", 274),
    ("sched_setparam", 118),
    ("sched_setscheduler", 119),
    ("sched_yield", 124),
    ("seccomp", 277),
    ("semctl", 191),
    ("semget", 190),
    ("semop", 193),
    ("semtimedop", 192),
    ("sendfile", 71),
    ("sendmmsg", 269),
    ("sendmsg", 211),
    ("sendto", 206),
    ("set_mempolicy", 237),
    ("set_mempolicy_home_node", 450),
    ("set_robust_list", 99),
    ("set_tid_address", 96),
    ("setdomainname", 162),
    ("setfsgid", 152),
    ("setfsuid", 151),
    ("setgid", 144),
    ("setgroups", 159),
    ("sethostname", 161),
    ("setitimer", 103),
    ("setns", 268),
    ("setpgid", 154),
    ("setpriority", 140),
    ("setregid", 143),
    ("setresgid", 149),
    ("setresuid", 147),
    ("setreuid", 145),
    ("setrlimit", 164),
    ("setsid", 157),
    ("setsockopt", 208),
    ("settimeofday", 170),
    ("setuid", 146),
    ("setxattr", 5),
    ("setxattrat", 463),
    ("shmat", 196),
    ("shmctl", 195),
    ("shmdt", 197),
    ("shmget", 194),
    ("shutdown", 210),
    ("sigaltstack", 132),
    ("signalfd4", 74),
    ("socket", 198),
    ("socketpair", 199),
    ("splice", 76),
    ("statfs", 43),
    ("statmount", 457),
    ("statx", 291),
    ("swapoff", 225),
    ("swapon", 224),
    ("symlinkat", 36),
    ("sync", 81),
    ("sync_file_range", 84),
    ("syncfs", 267),
    ("sysinfo", 179),
    ("syslog", 116),
    ("tee", 77),
    ("tgkill", 131),
    ("timer_create", 107),
    ("timer_delete", 111),
    ("timer_getoverrun", 109),
    ("timer_gettime", 108),
    ("timer_settime", 110),
    ("timerfd_create", 85),
    ("timerfd_gettime", 87),
    ("timerfd_settime", 86),
    ("times", 153),
    ("tkill", 130),
    ("truncate", 45),
    ("umask", 166),
    ("umount2", 39),
    ("uname", 160),
    ("unlinkat", 35),
    ("unshare", 97),
    ("userfaultfd", 282),
    ("utimensat", 88),
    ("vhangup", 58),
    ("vmsplice", 75),
    ("wait4", 260),
    ("waitid", 95),
    ("write", 64),
    ("writev", 66),
];

// Source: Linux 7.1 `include/uapi/asm-generic/unistd.h`, 64-bit branch,
// plus the two riscv-specific calls; equivalently `scripts/syscall.tbl`
// with the ABI set from `arch/riscv/kernel/Makefile.syscalls`: common, 64,
// riscv, rlimit, memfd_secret. riscv64 has no `renameat`, only `renameat2`.
#[cfg(target_arch = "riscv64")]
static SYSCALLS: &[(&str, i64)] = &[
    ("accept", 202),
    ("accept4", 242),
    ("acct", 89),
    ("add_key", 217),
    ("adjtimex", 171),
    ("bind", 200),
    ("bpf", 280),
    ("brk", 214),
    ("cachestat", 451),
    ("capget", 90),
    ("capset", 91),
    ("chdir", 49),
    ("chroot", 51),
    ("clock_adjtime", 266),
    ("clock_getres", 114),
    ("clock_gettime", 113),
    ("clock_nanosleep", 115),
    ("clock_settime", 112),
    ("clone", 220),
    ("clone3", 435),
    ("close", 57),
    ("close_range", 436),
    ("connect", 203),
    ("copy_file_range", 285),
    ("delete_module", 106),
    ("dup", 23),
    ("dup3", 24),
    ("epoll_create1", 20),
    ("epoll_ctl", 21),
    ("epoll_pwait", 22),
    ("epoll_pwait2", 441),
    ("eventfd2", 19),
    ("execve", 221),
    ("execveat", 281),
    ("exit", 93),
    ("exit_group", 94),
    ("faccessat", 48),
    ("faccessat2", 439),
    ("fadvise64", 223),
    ("fallocate", 47),
    ("fanotify_init", 262),
    ("fanotify_mark", 263),
    ("fchdir", 50),
    ("fchmod", 52),
    ("fchmodat", 53),
    ("fchmodat2", 452),
    ("fchown", 55),
    ("fchownat", 54),
    ("fcntl", 25),
    ("fdatasync", 83),
    ("fgetxattr", 10),
    ("file_getattr", 468),
    ("file_setattr", 469),
    ("finit_module", 273),
    ("flistxattr", 13),
    ("flock", 32),
    ("fremovexattr", 16),
    ("fsconfig", 431),
    ("fsetxattr", 7),
    ("fsmount", 432),
    ("fsopen", 430),
    ("fspick", 433),
    ("fstat", 80),
    ("fstatfs", 44),
    ("fsync", 82),
    ("ftruncate", 46),
    ("futex", 98),
    ("futex_requeue", 456),
    ("futex_wait", 455),
    ("futex_waitv", 449),
    ("futex_wake", 454),
    ("get_mempolicy", 236),
    ("get_robust_list", 100),
    ("getcpu", 168),
    ("getcwd", 17),
    ("getdents64", 61),
    ("getegid", 177),
    ("geteuid", 175),
    ("getgid", 176),
    ("getgroups", 158),
    ("getitimer", 102),
    ("getpeername", 205),
    ("getpgid", 155),
    ("getpid", 172),
    ("getppid", 173),
    ("getpriority", 141),
    ("getrandom", 278),
    ("getresgid", 150),
    ("getresuid", 148),
    ("getrlimit", 163),
    ("getrusage", 165),
    ("getsid", 156),
    ("getsockname", 204),
    ("getsockopt", 209),
    ("gettid", 178),
    ("gettimeofday", 169),
    ("getuid", 174),
    ("getxattr", 8),
    ("getxattrat", 464),
    ("init_module", 105),
    ("inotify_add_watch", 27),
    ("inotify_init1", 26),
    ("inotify_rm_watch", 28),
    ("io_cancel", 3),
    ("io_destroy", 1),
    ("io_getevents", 4),
    ("io_pgetevents", 292),
    ("io_setup", 0),
    ("io_submit", 2),
    ("io_uring_enter", 426),
    ("io_uring_register", 427),
    ("io_uring_setup", 425),
    ("ioctl", 29),
    ("ioprio_get", 31),
    ("ioprio_set", 30),
    ("kcmp", 272),
    ("kexec_file_load", 294),
    ("kexec_load", 104),
    ("keyctl", 219),
    ("kill", 129),
    ("landlock_add_rule", 445),
    ("landlock_create_ruleset", 444),
    ("landlock_restrict_self", 446),
    ("lgetxattr", 9),
    ("linkat", 37),
    ("listen", 201),
    ("listmount", 458),
    ("listns", 470),
    ("listxattr", 11),
    ("listxattrat", 465),
    ("llistxattr", 12),
    ("lookup_dcookie", 18),
    ("lremovexattr", 15),
    ("lseek", 62),
    ("lsetxattr", 6),
    ("lsm_get_self_attr", 459),
    ("lsm_list_modules", 461),
    ("lsm_set_self_attr", 460),
    ("madvise", 233),
    ("map_shadow_stack", 453),
    ("mbind", 235),
    ("membarrier", 283),
    ("memfd_create", 279),
    ("memfd_secret", 447),
    ("migrate_pages", 238),
    ("mincore", 232),
    ("mkdirat", 34),
    ("mknodat", 33),
    ("mlock", 228),
    ("mlock2", 284),
    ("mlockall", 230),
    ("mmap", 222),
    ("mount", 40),
    ("mount_setattr", 442),
    ("move_mount", 429),
    ("move_pages", 239),
    ("mprotect", 226),
    ("mq_getsetattr", 185),
    ("mq_notify", 184),
    ("mq_open", 180),
    ("mq_timedreceive", 183),
    ("mq_timedsend", 182),
    ("mq_unlink", 181),
    ("mremap", 216),
    ("mseal", 462),
    ("msgctl", 187),
    ("msgget", 186),
    ("msgrcv", 188),
    ("msgsnd", 189),
    ("msync", 227),
    ("munlock", 229),
    ("munlockall", 231),
    ("munmap", 215),
    ("name_to_handle_at", 264),
    ("nanosleep", 101),
    ("newfstatat", 79),
    ("nfsservctl", 42),
    ("open_by_handle_at", 265),
    ("open_tree", 428),
    ("open_tree_attr", 467),
    ("openat", 56),
    ("openat2", 437),
    ("perf_event_open", 241),
    ("personality", 92),
    ("pidfd_getfd", 438),
    ("pidfd_open", 434),
    ("pidfd_send_signal", 424),
    ("pipe2", 59),
    ("pivot_root", 41),
    ("pkey_alloc", 289),
    ("pkey_free", 290),
    ("pkey_mprotect", 288),
    ("ppoll", 73),
    ("prctl", 167),
    ("pread64", 67),
    ("preadv", 69),
    ("preadv2", 286),
    ("prlimit64", 261),
    ("process_madvise", 440),
    ("process_mrelease", 448),
    ("process_vm_readv", 270),
    ("process_vm_writev", 271),
    ("pselect6", 72),
    ("ptrace", 117),
    ("pwrite64", 68),
    ("pwritev", 70),
    ("pwritev2", 287),
    ("quotactl", 60),
    ("quotactl_fd", 443),
    ("read", 63),
    ("readahead", 213),
    ("readlinkat", 78),
    ("readv", 65),
    ("reboot", 142),
    ("recvfrom", 207),
    ("recvmmsg", 243),
    ("recvmsg", 212),
    ("remap_file_pages", 234),
    ("removexattr", 14),
    ("removexattrat", 466),
    ("renameat2", 276),
    ("request_key", 218),
    ("restart_syscall", 128),
    ("riscv_flush_icache", 259),
    ("riscv_hwprobe", 258),
    ("rseq", 293),
    ("rseq_slice_yield", 471),
    ("rt_sigaction", 134),
    ("rt_sigpending", 136),
    ("rt_sigprocmask", 135),
    ("rt_sigqueueinfo", 138),
    ("rt_sigreturn", 139),
    ("rt_sigsuspend", 133),
    ("rt_sigtimedwait", 137),
    ("rt_tgsigqueueinfo", 240),
    ("sched_get_priority_max", 125),
    ("sched_get_priority_min", 126),
    ("sched_getaffinity", 123),
    ("sched_getattr", 275),
    ("sched_getparam", 121),
    ("sched_getscheduler", 120),
    ("sched_rr_get_interval", 127),
    ("sched_setaffinity", 122),
    ("sched_setattr", 274),
    ("sched_setparam", 118),
    ("sched_setscheduler", 119),
    ("sched_yield", 124),
    ("seccomp", 277),
    ("semctl", 191),
    ("semget", 190),
    ("semop", 193),
    ("semtimedop", 192),
    ("sendfile", 71),
    ("sendmmsg", 269),
    ("sendmsg", 211),
    ("sendto", 206),
    ("set_mempolicy", 237),
    ("set_mempolicy_home_node", 450),
    ("set_robust_list", 99),
    ("set_tid_address", 96),
    ("setdomainname", 162),
    ("setfsgid", 152),
    ("setfsuid", 151),
    ("setgid", 144),
    ("setgroups", 159),
    ("sethostname", 161),
    ("setitimer", 103),
    ("setns", 268),
    ("setpgid", 154),
    ("setpriority", 140),
    ("setregid", 143),
    ("setresgid", 149),
    ("setresuid", 147),
    ("setreuid", 145),
    ("setrlimit", 164),
    ("setsid", 157),
    ("setsockopt", 208),
    ("settimeofday", 170),
    ("setuid", 146),
    ("setxattr", 5),
    ("setxattrat", 463),
    ("shmat", 196),
    ("shmctl", 195),
    ("shmdt", 197),
    ("shmget", 194),
    ("shutdown", 210),
    ("sigaltstack", 132),
    ("signalfd4", 74),
    ("socket", 198),
    ("socketpair", 199),
    ("splice", 76),
    ("statfs", 43),
    ("statmount", 457),
    ("statx", 291),
    ("swapoff", 225),
    ("swapon", 224),
    ("symlinkat", 36),
    ("sync", 81),
    ("sync_file_range", 84),
    ("syncfs", 267),
    ("sysinfo", 179),
    ("syslog", 116),
    ("tee", 77),
    ("tgkill", 131),
    ("timer_create", 107),
    ("timer_delete", 111),
    ("timer_getoverrun", 109),
    ("timer_gettime", 108),
    ("timer_settime", 110),
    ("timerfd_create", 85),
    ("timerfd_gettime", 87),
    ("timerfd_settime", 86),
    ("times", 153),
    ("tkill", 130),
    ("truncate", 45),
    ("umask", 166),
    ("umount2", 39),
    ("uname", 160),
    ("unlinkat", 35),
    ("unshare", 97),
    ("userfaultfd", 282),
    ("utimensat", 88),
    ("vhangup", 58),
    ("vmsplice", 75),
    ("wait4", 260),
    ("waitid", 95),
    ("write", 64),
    ("writev", 66),
];

// Any other architecture would get an empty table, which reads as "deny
// nothing"; seccompiler compiles filters for these three only.
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
compile_error!("bubbler has no syscall table for this target architecture");

/// The kernel's number for `name` on the architecture bubbler is built
/// for, or `None` when this architecture never had that syscall.
pub fn syscall_number(name: &str) -> Option<i64> {
    let i = SYSCALLS.binary_search_by(|(n, _)| (*n).cmp(name)).ok()?;
    Some(SYSCALLS[i].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Default names the build architecture never had. Denying them is
    /// harmless, but the set must not grow by accident.
    #[cfg(target_arch = "x86_64")]
    const ABSENT_HERE: &[&str] = &["clock_settime64", "vm86", "vm86old"];
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    const ABSENT_HERE: &[&str] = &[
        "uselib",
        "iopl",
        "ioperm",
        "clock_settime64",
        "vm86",
        "vm86old",
        "modify_ldt",
    ];

    #[test]
    fn the_table_is_sorted_and_names_each_syscall_once() {
        assert!(!SYSCALLS.is_empty());
        assert!(
            SYSCALLS.windows(2).all(|w| w[0].0 < w[1].0),
            "table is not sorted by name"
        );
    }

    #[test]
    fn every_default_name_the_architecture_has_resolves() {
        let missing: Vec<&str> = DEFAULT_EPERM
            .iter()
            .chain(DEFAULT_ENOSYS)
            .copied()
            .filter(|n| syscall_number(n).is_none())
            .collect();
        assert_eq!(missing, ABSENT_HERE);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn known_x86_64_numbers_match_the_kernel_table() {
        assert_eq!(syscall_number("read"), Some(0));
        assert_eq!(syscall_number("write"), Some(1));
        assert_eq!(syscall_number("ioctl"), Some(16));
        assert_eq!(syscall_number("prctl"), Some(157));
        assert_eq!(syscall_number("keyctl"), Some(250));
        assert_eq!(syscall_number("clone3"), Some(435));
        assert_eq!(syscall_number("modify_ldt"), Some(154));
        assert_eq!(syscall_number("nosuchcall"), None);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn known_aarch64_numbers_match_the_kernel_table() {
        assert_eq!(syscall_number("read"), Some(63));
        assert_eq!(syscall_number("write"), Some(64));
        assert_eq!(syscall_number("ioctl"), Some(29));
        assert_eq!(syscall_number("keyctl"), Some(219));
        assert_eq!(syscall_number("clone3"), Some(435));
        assert_eq!(syscall_number("renameat"), Some(38));
        assert_eq!(syscall_number("nosuchcall"), None);
    }

    #[cfg(target_arch = "riscv64")]
    #[test]
    fn known_riscv64_numbers_match_the_kernel_table() {
        assert_eq!(syscall_number("read"), Some(63));
        assert_eq!(syscall_number("write"), Some(64));
        assert_eq!(syscall_number("ioctl"), Some(29));
        assert_eq!(syscall_number("keyctl"), Some(219));
        assert_eq!(syscall_number("clone3"), Some(435));
        assert_eq!(syscall_number("riscv_hwprobe"), Some(258));
        // riscv64 has renameat2 only; the abi list in
        // arch/riscv/kernel/Makefile.syscalls leaves out `renameat`.
        assert_eq!(syscall_number("renameat"), None);
        assert_eq!(syscall_number("nosuchcall"), None);
    }

    #[test]
    fn the_default_set_is_the_two_lists_plus_the_ioctl_rules() {
        let set = RuleSet::default_set();
        assert_eq!(set.eperm, DEFAULT_EPERM);
        assert_eq!(set.enosys, DEFAULT_ENOSYS);
        assert_eq!(set.ioctl_eperm, vec![0x5412, 0x541C]);
        assert_eq!(RuleSet::with(&SeccompConfig::default()), Some(set));
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
        assert_eq!(set.eperm.len(), DEFAULT_EPERM.len() - 1);
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
        assert_eq!(set.eperm.len(), DEFAULT_EPERM.len() + 2);
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

    /// Instruction fields as seccompiler lays them out, decoded back from
    /// the bytes a program is passed to bwrap as.
    fn instructions(program: &[u8]) -> Vec<(u16, u8, u8, u32)> {
        assert_eq!(program.len() % 8, 0, "a sock_filter is eight bytes");
        program
            .chunks_exact(8)
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

    /// Instructions in the EPERM program of the default set. seccompiler
    /// emits 3 for the architecture check, 1 to load the syscall number
    /// and 1 closing mismatch action; then 5 for every syscall denied
    /// whatever its arguments (compare, two jumps, match action, mismatch
    /// action) and 2 + 6 per rule for an argument-filtered one (compare
    /// and mismatch action around rules of two jumps, load, mask, compare
    /// and match action). x86_64 resolves 38 of the 41 `DEFAULT_EPERM`
    /// names (`ABSENT_HERE`) and adds the two `ioctl` rules:
    /// 5 + 38 * 5 + 2 + 2 * 6 = 209.
    #[cfg(target_arch = "x86_64")]
    const EPERM_LEN: usize = 209;
    /// As above with 34 of the names: 5 + 34 * 5 + 2 + 2 * 6 = 189.
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    const EPERM_LEN: usize = 189;
    /// All eight `DEFAULT_ENOSYS` names resolve everywhere, and none of
    /// them filters on an argument: 5 + 8 * 5 = 45.
    const ENOSYS_LEN: usize = 45;

    #[test]
    fn the_default_set_compiles_to_two_programs_of_a_known_size() {
        let programs = compile(&RuleSet::default_set(), false).unwrap();
        assert_eq!(programs.len(), 2);
        assert_eq!(instructions(&programs[0]).len(), EPERM_LEN);
        assert_eq!(instructions(&programs[1]).len(), ENOSYS_LEN);
    }

    #[test]
    fn a_program_starts_with_the_architecture_check() {
        let programs = compile(&RuleSet::default_set(), false).unwrap();
        let first = instructions(&programs[0])[0];
        // BPF_LD | BPF_W | BPF_ABS of `seccomp_data.arch`, at offset 4.
        assert_eq!(first, (0x0020, 0, 0, 4));
    }

    #[test]
    fn the_ioctl_rules_compare_the_low_word_of_argument_one() {
        let programs = compile(&RuleSet::default_set(), false).unwrap();
        let eperm = instructions(&programs[0]);
        // `seccomp_data.args[1]` starts at offset 16 + 1 * 8 = 24; the
        // mask is loaded against its low half.
        for value in DEFAULT_IOCTL_EPERM {
            assert!(
                eperm.windows(3).any(|w| w[0] == (0x0020, 0, 0, 24)
                    && w[1] == (0x0054, 0, 0, 0xFFFF_FFFF)
                    && w[2].3 == *value),
                "no masked comparison for {value:#x}"
            );
        }
    }

    #[test]
    fn allowing_a_syscall_costs_the_program_one_rule() {
        let cfg = SeccompConfig {
            allow: vec!["keyctl".to_owned()],
            ..SeccompConfig::default()
        };
        let programs = compile(&RuleSet::with(&cfg).unwrap(), false).unwrap();
        assert_eq!(instructions(&programs[0]).len(), EPERM_LEN - 5);
        assert_eq!(instructions(&programs[1]).len(), ENOSYS_LEN);
    }

    #[test]
    fn allowing_ioctl_drops_the_two_argument_rules() {
        let cfg = SeccompConfig {
            allow: vec!["ioctl".to_owned()],
            ..SeccompConfig::default()
        };
        let programs = compile(&RuleSet::with(&cfg).unwrap(), false).unwrap();
        assert_eq!(instructions(&programs[0]).len(), EPERM_LEN - 14);
    }

    #[test]
    fn denying_ioctl_outright_replaces_the_argument_rules() {
        let cfg = SeccompConfig {
            deny: vec![("ioctl".to_owned(), Errno::Eperm)],
            ..SeccompConfig::default()
        };
        let set = RuleSet::with(&cfg).unwrap();
        assert!(set.ioctl_eperm.is_empty(), "a blanket deny subsumes them");
        let programs = compile(&set, false).unwrap();
        // The blanket rule replaces the argument-filtered pair, and the
        // syscall appears once: -14 for the pair, +5 for the name.
        assert_eq!(instructions(&programs[0]).len(), EPERM_LEN - 14 + 5);
    }

    #[test]
    fn a_hand_built_set_never_weakens_a_blanket_ioctl_deny() {
        let set = RuleSet {
            eperm: vec!["ioctl".to_owned()],
            enosys: vec![],
            ioctl_eperm: DEFAULT_IOCTL_EPERM.to_vec(),
        };
        let programs = compile(&set, false).unwrap();
        // 5 + 1 * 5: the blanket rule only, no argument comparison.
        assert_eq!(instructions(&programs[0]).len(), 10);
    }

    #[test]
    fn a_group_with_nothing_left_in_it_produces_no_program() {
        let cfg = SeccompConfig {
            allow: DEFAULT_ENOSYS.iter().map(|s| (*s).to_owned()).collect(),
            ..SeccompConfig::default()
        };
        let programs = compile(&RuleSet::with(&cfg).unwrap(), false).unwrap();
        assert_eq!(programs.len(), 1);
        assert_eq!(instructions(&programs[0]).len(), EPERM_LEN);
        assert!(compile(&RuleSet::default(), false).unwrap().is_empty());
    }

    #[test]
    fn names_this_architecture_never_had_are_skipped_not_an_error() {
        let set = RuleSet {
            eperm: vec!["keyctl".to_owned(), "vm86old".to_owned()],
            enosys: vec![],
            ioctl_eperm: vec![],
        };
        let programs = compile(&set, false).unwrap();
        let names = ABSENT_HERE.iter().filter(|n| **n == "vm86old").count();
        assert_eq!(instructions(&programs[0]).len(), 5 + (2 - names) * 5);
    }

    #[test]
    fn logging_keeps_the_shape_and_changes_only_the_action() {
        let set = RuleSet::default_set();
        let quiet = compile(&set, false).unwrap();
        let logged = compile(&set, true).unwrap();
        assert_eq!(quiet.len(), logged.len());
        for (q, l) in quiet.iter().zip(&logged) {
            assert_eq!(q.len(), l.len());
            assert_ne!(q, l, "the match action must differ");
        }
        // SECCOMP_RET_LOG, and no SECCOMP_RET_ERRNO with EPERM in it.
        let ks: Vec<u32> = instructions(&logged[0]).iter().map(|i| i.3).collect();
        assert!(ks.contains(&0x7ffc_0000));
        assert!(!ks.contains(&(0x0005_0000 | 1)));
    }
}
