//! Whether a host process is alive.

use rustix::io::Errno;
use rustix::process::{Pid, test_kill_process};

/// Whether a process has `pid`. `kill(pid, 0)` fails with ESRCH only
/// when none has; EPERM means it is alive and owned by someone else.
pub(crate) fn pid_alive(pid: Pid) -> bool {
    test_kill_process(pid) != Err(Errno::SRCH)
}
