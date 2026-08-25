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

/// Shortest gap between two audit lines of one kind. Anything closer is
/// counted instead.
pub const RATE: Duration = Duration::from_secs(1);

/// What a line is about, and so which budget it comes out of.
///
/// The two are counted apart on purpose. A client that asks for the clipboard
/// in a tight loop must not be able to spend the log's whole budget and push
/// the one line that says why its connection ended out of the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A clipboard read was allowed or denied.
    Gate,
    /// A connection ended, and why.
    Close,
}

/// One kind's share of the log: when it last wrote, and what it swallowed.
#[derive(Debug, Default, Clone, Copy)]
struct Budget {
    last: Option<Instant>,
    suppressed: u64,
}

/// The proxy's audit log: one sink, plus a rate limiter per kind of line.
pub struct Audit {
    out: Box<dyn Write>,
    gate: Budget,
    close: Budget,
}

impl fmt::Debug for Audit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Audit")
            .field("gate", &self.gate)
            .field("close", &self.close)
            .finish_non_exhaustive()
    }
}

impl Audit {
    /// Write the log to `out`.
    pub fn new(out: Box<dyn Write>) -> Self {
        Self {
            out,
            gate: Budget::default(),
            close: Budget::default(),
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

    /// Record one line, unless another of its kind went out less than
    /// [`RATE`] ago — in which case it is counted and the count is appended
    /// to the next line of that kind that does go out.
    ///
    /// A log that cannot be written is not a reason to stop proxying: the
    /// sandbox keeps its display either way, and the descriptor belongs to
    /// the launcher, not to the client.
    pub fn line(&mut self, kind: Kind, now: Instant, text: &str) {
        let budget = match kind {
            Kind::Gate => &mut self.gate,
            Kind::Close => &mut self.close,
        };
        if let Some(last) = budget.last
            && now.saturating_duration_since(last) < RATE
        {
            budget.suppressed = budget.suppressed.saturating_add(1);
            return;
        }
        let line = match budget.suppressed {
            0 => format!("{text}\n"),
            n => format!("{text} (+{n} more)\n"),
        };
        budget.suppressed = 0;
        budget.last = Some(now);
        let _ = self.out.write_all(line.as_bytes());
        let _ = self.out.flush();
    }

    /// How many lines of this kind the limiter has swallowed since the last
    /// one of that kind it wrote.
    pub fn suppressed(&self, kind: Kind) -> u64 {
        match kind {
            Kind::Gate => self.gate.suppressed,
            Kind::Close => self.close.suppressed,
        }
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
        audit.line(Kind::Gate, Instant::now(), "one");
        assert_eq!(buf.text(), "one\n");
    }

    #[test]
    fn a_second_line_within_the_window_is_counted_not_written() {
        let (mut audit, buf) = audit();
        let start = Instant::now();
        audit.line(Kind::Gate, start, "one");
        audit.line(Kind::Gate, start + Duration::from_millis(999), "two");
        assert_eq!(buf.text(), "one\n");
        assert_eq!(audit.suppressed(Kind::Gate), 1);
    }

    #[test]
    fn the_next_line_carries_the_count_of_what_was_swallowed() {
        let (mut audit, buf) = audit();
        let start = Instant::now();
        audit.line(Kind::Gate, start, "one");
        for n in 0..5 {
            audit.line(
                Kind::Gate,
                start + Duration::from_millis(100 * n),
                "swallowed",
            );
        }
        audit.line(Kind::Gate, start + RATE, "two");
        assert_eq!(buf.text(), "one\ntwo (+5 more)\n");
        assert_eq!(audit.suppressed(Kind::Gate), 0);
    }

    #[test]
    fn the_count_starts_again_after_a_line_that_carried_it() {
        let (mut audit, buf) = audit();
        let start = Instant::now();
        audit.line(Kind::Gate, start, "one");
        audit.line(Kind::Gate, start, "swallowed");
        audit.line(Kind::Gate, start + RATE, "two");
        audit.line(Kind::Gate, start + RATE * 2, "three");
        assert_eq!(buf.text(), "one\ntwo (+1 more)\nthree\n");
    }

    #[test]
    fn a_clock_that_goes_backwards_does_not_panic() {
        let (mut audit, buf) = audit();
        let start = Instant::now() + RATE * 10;
        audit.line(Kind::Gate, start, "one");
        audit.line(Kind::Gate, start - RATE * 5, "two");
        assert_eq!(buf.text(), "one\n");
    }

    #[test]
    fn a_flood_of_gate_lines_cannot_swallow_the_one_that_says_why_it_ended() {
        let (mut audit, buf) = audit();
        let start = Instant::now();
        for n in 0..1000 {
            audit.line(
                Kind::Gate,
                start + Duration::from_micros(n),
                "clipboard read denied",
            );
        }
        audit.line(Kind::Close, start, "connection closed: the reason");
        assert_eq!(
            buf.text(),
            "clipboard read denied\nconnection closed: the reason\n"
        );
        assert_eq!(audit.suppressed(Kind::Gate), 999);
        assert_eq!(audit.suppressed(Kind::Close), 0);
    }

    #[test]
    fn each_kind_counts_its_own_arrears() {
        let (mut audit, buf) = audit();
        let start = Instant::now();
        audit.line(Kind::Gate, start, "gate one");
        audit.line(Kind::Gate, start, "gate swallowed");
        audit.line(Kind::Close, start, "close one");
        audit.line(Kind::Close, start, "close swallowed");
        audit.line(Kind::Close, start, "close swallowed");
        audit.line(Kind::Gate, start + RATE, "gate two");
        audit.line(Kind::Close, start + RATE, "close two");
        assert_eq!(
            buf.text(),
            "gate one\nclose one\ngate two (+1 more)\nclose two (+2 more)\n"
        );
    }
}
