//! The policy revision the running WirePlumber has loaded, asked of
//! `pw-dump` on a thread with a deadline.

use std::cell::OnceCell;
use std::io::{ErrorKind, Read};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::audio_policy::{DUMP_CAP, LoadedRevision, PW_DUMP, parse_loaded_revision};
use crate::env::Env;

const READ_TIMEOUT: Duration = Duration::from_secs(2);

// WirePlumber accepts clients a moment before the hook publishes the revision (measured in the
// bed), so a run just after a restart can find none.
const ABSENT_AGAIN_AFTER: Duration = Duration::from_millis(500);

/// The revision loaded by the WirePlumber on `env`'s runtime directory, asked with nothing else of
/// bubbler's environment; no answer within two seconds is [`LoadedRevision::Unknown`].
pub fn loaded_revision(env: &Env) -> LoadedRevision {
    let program = env
        .pw_dump_override
        .as_deref()
        .unwrap_or(Path::new(PW_DUMP));
    loaded_revision_asking(program, &env.runtime_dir)
}

/// [`loaded_revision`] asked on the first [`get`](Self::get) only, so that everything one caller
/// lints or runs pays for one `pw-dump` at most.
#[derive(Default)]
pub struct AskedOnce(OnceCell<LoadedRevision>);

impl AskedOnce {
    /// The answer for `env`, asked of it on the first call and kept.
    pub fn get(&self, env: &Env) -> LoadedRevision {
        self.0.get_or_init(|| loaded_revision(env)).clone()
    }
}

/// [`loaded_revision`] of the WirePlumber serving `runtime_dir`, asked of `program`; an
/// [`Absent`](LoadedRevision::Absent) answer is asked again once, a moment later.
pub fn loaded_revision_asking(program: &Path, runtime_dir: &Path) -> LoadedRevision {
    match ask(program, runtime_dir) {
        LoadedRevision::Absent => {
            std::thread::sleep(ABSENT_AGAIN_AFTER);
            ask(program, runtime_dir)
        }
        answer => answer,
    }
}

fn ask(program: &Path, runtime_dir: &Path) -> LoadedRevision {
    let spawned = Command::new(program)
        .env_clear()
        .env("XDG_RUNTIME_DIR", runtime_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => return LoadedRevision::Unknown(format!("{}: {e}", program.display())),
    };
    let deadline = Instant::now() + READ_TIMEOUT;
    let stdout = chunks(child.stdout.take().expect("stdout was piped"));
    let stderr = chunks(child.stderr.take().expect("stderr was piped"));
    let mut dump = Vec::new();
    loop {
        match stdout.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Piped::Chunk(chunk)) => {
                dump.extend_from_slice(&chunk);
                if dump.len() > DUMP_CAP {
                    stop(&mut child);
                    return LoadedRevision::Unreadable(format!(
                        "{} printed more than {DUMP_CAP} bytes",
                        program.display()
                    ));
                }
            }
            Ok(Piped::End) | Err(RecvTimeoutError::Disconnected) => break,
            Ok(Piped::Failed(e)) => {
                stop(&mut child);
                return LoadedRevision::Unknown(format!("{}: {e}", program.display()));
            }
            Err(RecvTimeoutError::Timeout) => {
                stop(&mut child);
                let seconds = READ_TIMEOUT.as_secs();
                return if dump.is_empty() {
                    LoadedRevision::Unknown(format!(
                        "{} did not answer within {seconds} s",
                        program.display()
                    ))
                } else {
                    LoadedRevision::Unreadable(format!(
                        "{} did not finish within {seconds} s",
                        program.display()
                    ))
                };
            }
        }
    }
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                stop(&mut child);
                return LoadedRevision::Unknown(format!(
                    "{} did not exit within {} s",
                    program.display(),
                    READ_TIMEOUT.as_secs()
                ));
            }
            Err(e) => {
                stop(&mut child);
                return LoadedRevision::Unknown(format!("{}: {e}", program.display()));
            }
        }
    };
    if !status.success() {
        let said = collected(&stderr, deadline);
        return LoadedRevision::Unknown(format!(
            "{} {}: {}",
            program.display(),
            status,
            String::from_utf8_lossy(&said).trim()
        ));
    }
    parse_loaded_revision(&dump)
}

enum Piped {
    Chunk(Vec<u8>),
    End,
    Failed(std::io::Error),
}

// Read on a thread while the program runs: one blocked on a full pipe would never exit.
fn chunks(mut pipe: impl Read + Send + 'static) -> Receiver<Piped> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buffer = vec![0; 64 * 1024];
        loop {
            let piped = match pipe.read(&mut buffer) {
                Ok(0) => Piped::End,
                Ok(n) => Piped::Chunk(buffer[..n].to_vec()),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => Piped::Failed(e),
            };
            let last = !matches!(piped, Piped::Chunk(_));
            if sender.send(piped).is_err() || last {
                return;
            }
        }
    });
    receiver
}

fn collected(receiver: &Receiver<Piped>, deadline: Instant) -> Vec<u8> {
    let mut said = Vec::new();
    while let Ok(Piped::Chunk(chunk)) =
        receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()))
    {
        said.extend_from_slice(&chunk);
        if said.len() > DUMP_CAP {
            break;
        }
    }
    said
}

// Killed and reaped; an error here is a child already gone, which the wait collects.
fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audio_policy::revision;
    use crate::audio_policy::tests::stating;
    use std::path::PathBuf;

    #[test]
    fn a_dump_larger_than_the_cap_is_unreadable_and_cut_off_at_once() {
        let tmp = tempfile::tempdir().expect("a temp dir");
        let tool = stand_in(
            tmp.path(),
            &format!(
                "head -c {} /dev/zero | tr '\\0' ' '; exec sleep 30",
                DUMP_CAP + 1
            ),
        );
        let started = Instant::now();
        let answer = asking_past_a_busy_exec(&tool, tmp.path());
        assert!(started.elapsed() < READ_TIMEOUT, "{:?}", started.elapsed());
        let LoadedRevision::Unreadable(reason) = answer else {
            panic!("{answer:?}");
        };
        assert!(reason.contains("more than"), "{reason}");
    }

    #[test]
    fn a_dump_cut_short_by_the_timeout_is_unreadable() {
        let tmp = tempfile::tempdir().expect("a temp dir");
        let tool = stand_in(tmp.path(), "echo '['; exec sleep 30");
        let answer = asking_past_a_busy_exec(&tool, tmp.path());
        let LoadedRevision::Unreadable(reason) = answer else {
            panic!("{answer:?}");
        };
        assert!(reason.contains("did not finish within"), "{reason}");
    }

    fn answering(dir: &Path, first: &str, then: &str) -> (PathBuf, PathBuf) {
        let asked = dir.join("asked");
        std::fs::write(dir.join("first"), first).expect("the first answer");
        std::fs::write(dir.join("then"), then).expect("the later answer");
        let d = dir.display();
        let tool = stand_in(
            dir,
            &format!(
                "if [ -e '{d}/asked' ]; then cat '{d}/then'; else cat '{d}/first'; fi\n\
                 echo asked >> '{d}/asked'"
            ),
        );
        (tool, asked)
    }

    fn asks(asked: &Path) -> usize {
        std::fs::read_to_string(asked)
            .expect("the stand-in was asked")
            .lines()
            .count()
    }

    #[test]
    fn an_absent_revision_is_asked_once_more_before_it_is_answered() {
        let current = stating(revision());
        for (first, then, expected, times) in [
            ("[]", current.as_str(), LoadedRevision::Current, 2),
            ("[]", "[]", LoadedRevision::Absent, 2),
            (current.as_str(), "[]", LoadedRevision::Current, 1),
        ] {
            let tmp = tempfile::tempdir().expect("a temp dir");
            let (tool, asked) = answering(tmp.path(), first, then);
            assert_eq!(asking_past_a_busy_exec(&tool, tmp.path()), expected);
            assert_eq!(asks(&asked), times, "{expected:?}");
        }
    }

    fn stand_in(dir: &Path, script: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("pw-dump");
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).expect("the stand-in");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("the stand-in made executable");
        path
    }

    // A thread of this binary that forked while the stand-in was open for writing makes its exec
    // fail with ETXTBSY until that child execs, within a scheduling turn.
    fn asking_past_a_busy_exec(tool: &Path, runtime_dir: &Path) -> LoadedRevision {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let answer = loaded_revision_asking(tool, runtime_dir);
            match &answer {
                LoadedRevision::Unknown(reason)
                    if reason.contains("os error 26") && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => return answer,
            }
        }
    }

    #[test]
    fn a_missing_tool_is_unknown() {
        let tmp = tempfile::tempdir().expect("a temp dir");
        let answer = loaded_revision_asking(&tmp.path().join("pw-dump"), tmp.path());
        assert!(matches!(answer, LoadedRevision::Unknown(_)), "{answer:?}");
    }

    #[test]
    fn an_unreachable_daemon_is_unknown_and_says_why() {
        // No daemon answering: `pw-dump` exits 255, the reason on stderr (PipeWire 1.6.9).
        let tmp = tempfile::tempdir().expect("a temp dir");
        let tool = stand_in(
            tmp.path(),
            "echo \"can't connect: Host is down\" >&2; exit 255",
        );
        let answer = asking_past_a_busy_exec(&tool, tmp.path());
        let LoadedRevision::Unknown(reason) = answer else {
            panic!("{answer:?}");
        };
        assert!(reason.contains("can't connect: Host is down"), "{reason}");
    }

    #[test]
    fn a_tool_that_does_not_answer_in_time_is_unknown() {
        let tmp = tempfile::tempdir().expect("a temp dir");
        let tool = stand_in(tmp.path(), "exec sleep 30");
        let started = Instant::now();
        let answer = asking_past_a_busy_exec(&tool, tmp.path());
        let elapsed = started.elapsed();
        let LoadedRevision::Unknown(reason) = answer else {
            panic!("{answer:?}");
        };
        assert!(reason.contains("did not answer within"), "{reason}");
        assert!(
            (READ_TIMEOUT..READ_TIMEOUT * 2).contains(&elapsed),
            "{elapsed:?}"
        );
    }
}
