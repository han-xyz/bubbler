//! The `seccomp` node's values and the default denylist they edit,
//! with the syscall names libseccomp resolves for them.

use libseccomp::ScmpSyscall;
use rustix::io::Errno as OsErrno;

/// Syscalls the default filter answers with `EPERM` — each either already
/// unreachable in bubbler's baseline sandbox or unused by desktop apps.
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
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "pidfd_getfd",
    "kcmp",
];

/// Syscalls the default filter answers with `ENOSYS`, so libc falls back
/// to the older call instead of failing. An application whose user
/// namespaces are not disabled gets the mount API back ([`MOUNT_API`]);
/// sidecars never do.
pub const DEFAULT_ENOSYS: &[&str] = &[
    "clone3",
    "open_tree",
    "move_mount",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
];

/// Syscalls answered with `ENOSYS` by *number*, because libseccomp 2.6.0
/// has no name for them. Numbers from `asm/unistd_64.h`. These three
/// rules hold for the build architecture alone.
// The mount-API class this closes is CVE-2021-41133; flatpak carries the
// same numbers in `flatpak-syscalls-private.h`.
pub const DEFAULT_ENOSYS_NUMBERED: &[(&str, i32)] =
    &[("open_tree_attr", 467), ("listns", 470), ("fchroot", 472)];

/// The mount-API rules of [`DEFAULT_ENOSYS`] and
/// [`DEFAULT_ENOSYS_NUMBERED`] that an application which may start a
/// sandbox of its own is spared.
pub const MOUNT_API: &[&str] = &[
    "open_tree",
    "move_mount",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "open_tree_attr",
];

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

    pub(crate) fn raw(self) -> i32 {
        match self {
            Self::Eperm => OsErrno::PERM.raw_os_error(),
            Self::Enosys => OsErrno::NOSYS.raw_os_error(),
        }
    }
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

/// The number libseccomp resolves `name` to on the build architecture, or
/// `None` when this libseccomp does not know the name at all. A syscall
/// the build architecture does not itself have answers with a negative
/// pseudo-number that still names a real rule on the other architectures
/// in the filter, so only the sign of the answer tells the two apart.
pub fn syscall_number(name: &str) -> Option<i64> {
    ScmpSyscall::from_name(name)
        .ok()
        .map(|nr| i64::from(i32::from(nr)))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
