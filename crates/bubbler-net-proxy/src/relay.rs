//! The blind half of the proxy: once a tunnel is up, bytes go across
//! unread.
//!
//! RFC 9110 §9.3.6 asks for exactly this — a proxy that has answered
//! `200` treats the connection "as a tunnel, simply forwarding octets
//! in both directions without attempting to parse or modify" them. The
//! payload is TLS the proxy has no key for in any case; what this loop
//! owes the sandbox is not inspection but bounds.
//!
//! Each direction carries one buffer, and a side is read only while its
//! buffer is empty, so neither peer can make the proxy hold more than
//! two buffers however fast it writes. A direction whose source is done
//! shuts the sink's write end down rather than closing the whole
//! socket, because a client that has sent its last byte may still be
//! waiting for the answer to it.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::AsFd;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};

/// Bytes one direction holds at a time.
pub const CHUNK: usize = 32 << 10;

/// How long a tunnel may carry nothing before it is closed.
pub const IDLE: Duration = Duration::from_secs(60);

/// Carry bytes between `client` and `upstream` until both directions
/// are done or `idle` passes with nothing moving.
///
/// Returns when the tunnel is over, which is not an error: a peer
/// hanging up and an idle timeout are both ordinary ends. Only a
/// failure to set the sockets up is reported.
pub fn run(client: TcpStream, upstream: TcpStream, idle: Duration) -> io::Result<()> {
    client.set_nonblocking(true)?;
    upstream.set_nonblocking(true)?;
    // One direction each, named for where the bytes come from.
    let mut out = Dir::default();
    let mut back = Dir::default();
    let mut moved_at = Instant::now();
    loop {
        out.close_sink(&upstream);
        back.close_sink(&client);
        if out.done() && back.done() {
            return Ok(());
        }
        let mut on_client = PollFlags::empty();
        let mut on_upstream = PollFlags::empty();
        if out.wants_read() {
            on_client |= PollFlags::IN;
        }
        if back.wants_write() {
            on_client |= PollFlags::OUT;
        }
        if back.wants_read() {
            on_upstream |= PollFlags::IN;
        }
        if out.wants_write() {
            on_upstream |= PollFlags::OUT;
        }
        // A side with nothing to wait for is left out of the set
        // entirely: `poll` reports a hangup whatever was asked for, and
        // an entry nobody acts on would spin the loop.
        let mut fds = Vec::with_capacity(2);
        let client_at = (!on_client.is_empty()).then(|| {
            fds.push(PollFd::from_borrowed_fd(client.as_fd(), on_client));
            fds.len() - 1
        });
        let upstream_at = (!on_upstream.is_empty()).then(|| {
            fds.push(PollFd::from_borrowed_fd(upstream.as_fd(), on_upstream));
            fds.len() - 1
        });
        if fds.is_empty() {
            return Ok(());
        }
        let left = idle.saturating_sub(moved_at.elapsed());
        if left.is_zero() {
            return Ok(());
        }
        let timeout = Timespec {
            tv_sec: left.as_secs().try_into().unwrap_or(i64::MAX),
            tv_nsec: left.subsec_nanos().into(),
        };
        if rustix::io::retry_on_intr(|| poll(&mut fds, Some(&timeout)))? == 0 {
            return Ok(());
        }
        let from_client = client_at.map_or(PollFlags::empty(), |at| fds[at].revents());
        let from_upstream = upstream_at.map_or(PollFlags::empty(), |at| fds[at].revents());
        let mut moved = false;
        if ready(on_client, from_client, PollFlags::IN) {
            moved |= out.read_from(&client);
        }
        if ready(on_upstream, from_upstream, PollFlags::OUT) {
            moved |= out.write_to(&upstream);
        }
        if ready(on_upstream, from_upstream, PollFlags::IN) {
            moved |= back.read_from(&upstream);
        }
        if ready(on_client, from_client, PollFlags::OUT) {
            moved |= back.write_to(&client);
        }
        if moved {
            moved_at = Instant::now();
        }
    }
}

/// Whether a side is worth acting on for `want`.
///
/// A hangup or an error answers every wait, and the read or write that
/// follows is what turns it into an end of stream or a broken pipe —
/// so the caller acts on it exactly where it asked for something.
fn ready(asked: PollFlags, got: PollFlags, want: PollFlags) -> bool {
    asked.contains(want) && got.intersects(want | PollFlags::HUP | PollFlags::ERR)
}

/// One direction of the tunnel: the bytes in flight, and whether either
/// end of it is finished.
struct Dir {
    /// What has been read and not yet written.
    buf: Box<[u8; CHUNK]>,
    /// How much of `buf` holds bytes.
    len: usize,
    /// How much of that has been written.
    off: usize,
    /// The source will send nothing more, or cannot be read at all.
    source_done: bool,
    /// The sink's write end is shut, or writing to it failed.
    sink_done: bool,
}

impl Default for Dir {
    fn default() -> Self {
        Self {
            buf: Box::new([0; CHUNK]),
            len: 0,
            off: 0,
            source_done: false,
            sink_done: false,
        }
    }
}

impl Dir {
    /// Whether bytes are waiting for the sink.
    fn pending(&self) -> bool {
        self.off < self.len
    }

    /// Whether this direction is over.
    fn done(&self) -> bool {
        self.sink_done
    }

    /// Read only while nothing is waiting: a peer that does not read
    /// must not make the proxy hold more than one buffer for it.
    fn wants_read(&self) -> bool {
        !self.source_done && !self.pending() && !self.sink_done
    }

    /// Write while anything is waiting.
    fn wants_write(&self) -> bool {
        self.pending() && !self.sink_done
    }

    /// Shut the sink's write end once the source is done and the last
    /// byte has gone out.
    ///
    /// Only that half: the other direction may still be carrying an
    /// answer, and closing the socket would take it with it.
    fn close_sink(&mut self, sink: &TcpStream) {
        if self.sink_done || !self.source_done || self.pending() {
            return;
        }
        // A peer that has already gone answers `ENOTCONN`, which says
        // the write end is shut as surely as success does.
        let _ = sink.shutdown(Shutdown::Write);
        self.sink_done = true;
    }

    /// Take a buffer's worth from the source. Called only while the
    /// buffer is empty.
    fn read_from(&mut self, source: &TcpStream) -> bool {
        let mut source = source;
        match source.read(&mut self.buf[..]) {
            Ok(0) => {
                self.source_done = true;
                false
            }
            Ok(n) => {
                self.len = n;
                self.off = 0;
                true
            }
            Err(err) if would_wait(&err) => false,
            // A reset connection is an end of stream with a worse name;
            // the other direction is finished on its own terms.
            Err(_) => {
                self.source_done = true;
                false
            }
        }
    }

    /// Hand the sink what is waiting.
    fn write_to(&mut self, sink: &TcpStream) -> bool {
        let mut sink = sink;
        match sink.write(&self.buf[self.off..self.len]) {
            Ok(0) => {
                self.give_up();
                false
            }
            Ok(n) => {
                self.off += n;
                true
            }
            Err(err) if would_wait(&err) => false,
            Err(_) => {
                self.give_up();
                false
            }
        }
    }

    /// A sink that cannot be written to ends this direction: the bytes
    /// in hand have nowhere to go, and there is no shutdown left to
    /// send.
    fn give_up(&mut self) {
        self.source_done = true;
        self.off = self.len;
        self.sink_done = true;
    }
}

/// Whether an error means "not now" rather than "not at all".
fn would_wait(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::thread;

    /// One connected pair on loopback: what the proxy holds, and what
    /// the peer on the other end of it holds.
    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("a loopback listener");
        let addr = listener.local_addr().expect("the bound address");
        let near = TcpStream::connect(addr).expect("a connection");
        let (far, _) = listener.accept().expect("the other end");
        (near, far)
    }

    /// The proxy's two sockets and the two peers they talk to.
    fn tunnel() -> (TcpStream, TcpStream, thread::JoinHandle<()>) {
        tunnel_with(Duration::from_secs(5))
    }

    fn tunnel_with(idle: Duration) -> (TcpStream, TcpStream, thread::JoinHandle<()>) {
        let (app, client) = pair();
        let (upstream, server) = pair();
        let joined = thread::spawn(move || run(client, upstream, idle).expect("the relay runs"));
        (app, server, joined)
    }

    #[test]
    fn bytes_flow_both_ways() {
        let (mut app, mut server, joined) = tunnel();
        app.write_all(b"hello").expect("the request goes out");
        let mut got = [0u8; 5];
        server.read_exact(&mut got).expect("the server reads it");
        assert_eq!(&got, b"hello");

        server.write_all(b"world").expect("the answer goes back");
        let mut got = [0u8; 5];
        app.read_exact(&mut got).expect("the client reads it");
        assert_eq!(&got, b"world");

        drop(app);
        drop(server);
        joined.join().expect("the relay ends");
    }

    #[test]
    fn a_half_close_reaches_the_other_side() {
        let (mut app, mut server, joined) = tunnel();
        app.write_all(b"done").expect("the last bytes go out");
        app.shutdown(Shutdown::Write)
            .expect("the client is done writing");

        let mut got = Vec::new();
        server
            .read_to_end(&mut got)
            .expect("the server sees the end of the request");
        assert_eq!(got, b"done");

        // The other direction is still open: an upstream may answer
        // long after the request's last byte.
        server.write_all(b"answer").expect("the answer goes back");
        drop(server);
        let mut got = Vec::new();
        app.read_to_end(&mut got).expect("the client reads it all");
        assert_eq!(got, b"answer");
        joined.join().expect("the relay ends");
    }

    #[test]
    fn a_tunnel_that_carries_nothing_is_closed() {
        let idle = Duration::from_millis(200);
        let (mut app, _server, joined) = tunnel_with(idle);
        let start = Instant::now();
        joined.join().expect("the relay ends");
        assert!(
            start.elapsed() >= idle,
            "gave up after {:?}",
            start.elapsed()
        );
        assert!(
            start.elapsed() < idle * 20,
            "held on for {:?}",
            start.elapsed()
        );
        let mut got = Vec::new();
        app.read_to_end(&mut got).expect("the socket is closed");
        assert!(got.is_empty());
    }

    #[test]
    fn a_slow_reader_does_not_stop_the_other_direction() {
        let (mut app, mut server, joined) = tunnel();
        // More than one buffer's worth in one direction, read back in
        // full while the other direction stays quiet.
        let payload = vec![0x5au8; CHUNK * 3];
        let sent = payload.clone();
        let writer = thread::spawn(move || {
            app.write_all(&sent).expect("the whole payload goes out");
            app.shutdown(Shutdown::Write).expect("done writing");
            app
        });
        let mut got = Vec::new();
        server
            .read_to_end(&mut got)
            .expect("the server reads it all");
        assert_eq!(got.len(), payload.len());
        assert_eq!(got, payload);
        let app = writer.join().expect("the writer ends");
        drop(server);
        drop(app);
        joined.join().expect("the relay ends");
    }
}
