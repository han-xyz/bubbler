//! Where the proxy says what it refused, and how often it is allowed to say
//! it.
//!
//! Every line is about one message the sandbox sent or was sent, so a client
//! that hammers the clipboard could otherwise write the log for us. One line
//! per second gets through; the rest are counted and the count rides on the
//! next line, so a burst is visible without being able to fill a disk.

use std::fmt;
use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

/// Shortest gap between two audit lines. Anything closer is counted instead.
pub const RATE: Duration = Duration::from_secs(1);

/// The proxy's audit log: one sink, plus the rate limiter in front of it.
pub struct Audit {
    out: Box<dyn Write>,
    last: Option<Instant>,
    suppressed: u64,
}

impl fmt::Debug for Audit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Audit")
            .field("last", &self.last)
            .field("suppressed", &self.suppressed)
            .finish_non_exhaustive()
    }
}

impl Audit {
    /// Write the log to `out`.
    pub fn new(out: Box<dyn Write>) -> Self {
        Self {
            out,
            last: None,
            suppressed: 0,
        }
    }

    /// Write the log to the inherited descriptor `--log-fd` named, which the
    /// launcher points at the instance's own log.
    pub fn to_fd(fd: OwnedFd) -> Self {
        Self::new(Box::new(File::from(fd)))
    }

    /// Write the log to this process's stderr, which is where it goes when
    /// the launcher named no descriptor.
    pub fn to_stderr() -> Self {
        Self::new(Box::new(std::io::stderr()))
    }

    /// Record one line, unless another went out less than [`RATE`] ago — in
    /// which case it is counted and the count is appended to the next line
    /// that does go out.
    ///
    /// A log that cannot be written is not a reason to stop proxying: the
    /// sandbox keeps its display either way, and the descriptor belongs to
    /// the launcher, not to the client.
    pub fn line(&mut self, now: Instant, text: &str) {
        if let Some(last) = self.last
            && now.saturating_duration_since(last) < RATE
        {
            self.suppressed = self.suppressed.saturating_add(1);
            return;
        }
        let line = match self.suppressed {
            0 => format!("{text}\n"),
            n => format!("{text} (+{n} more)\n"),
        };
        self.suppressed = 0;
        self.last = Some(now);
        let _ = self.out.write_all(line.as_bytes());
        let _ = self.out.flush();
    }

    /// How many lines the limiter has swallowed since the last one it wrote.
    pub fn suppressed(&self) -> u64 {
        self.suppressed
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    /// A sink the test can read back, since the real ones are descriptors.
    #[derive(Clone, Default)]
    struct Buf(Rc<RefCell<Vec<u8>>>);

    impl Write for Buf {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Buf {
        fn text(&self) -> String {
            String::from_utf8(self.0.borrow().clone()).expect("the log is UTF-8")
        }
    }

    fn audit() -> (Audit, Buf) {
        let buf = Buf::default();
        (Audit::new(Box::new(buf.clone())), buf)
    }

    #[test]
    fn the_first_line_always_goes_out() {
        let (mut audit, buf) = audit();
        audit.line(Instant::now(), "one");
        assert_eq!(buf.text(), "one\n");
    }

    #[test]
    fn a_second_line_within_the_window_is_counted_not_written() {
        let (mut audit, buf) = audit();
        let start = Instant::now();
        audit.line(start, "one");
        audit.line(start + Duration::from_millis(999), "two");
        assert_eq!(buf.text(), "one\n");
        assert_eq!(audit.suppressed(), 1);
    }

    #[test]
    fn the_next_line_carries_the_count_of_what_was_swallowed() {
        let (mut audit, buf) = audit();
        let start = Instant::now();
        audit.line(start, "one");
        for n in 0..5 {
            audit.line(start + Duration::from_millis(100 * n), "swallowed");
        }
        audit.line(start + RATE, "two");
        assert_eq!(buf.text(), "one\ntwo (+5 more)\n");
        assert_eq!(audit.suppressed(), 0);
    }

    #[test]
    fn the_count_starts_again_after_a_line_that_carried_it() {
        let (mut audit, buf) = audit();
        let start = Instant::now();
        audit.line(start, "one");
        audit.line(start, "swallowed");
        audit.line(start + RATE, "two");
        audit.line(start + RATE * 2, "three");
        assert_eq!(buf.text(), "one\ntwo (+1 more)\nthree\n");
    }

    #[test]
    fn a_clock_that_goes_backwards_does_not_panic() {
        let (mut audit, buf) = audit();
        let start = Instant::now() + RATE * 10;
        audit.line(start, "one");
        audit.line(start - RATE * 5, "two");
        assert_eq!(buf.text(), "one\n");
    }
}
