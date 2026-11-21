//! The document-portal call that hands the sandbox the files
//! [`crate::forward::plan`] picked: one `AddFull` per permission set.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};

use crate::dbus_session::Session;
use crate::dbus_wire::{Value, WireError};
use crate::env::Env;
use crate::forward::{Candidate, DOC_DIR, Forward, REFUSED_ROOTS, permission_sets, permissions};

const PORTAL_NAME: &str = "org.freedesktop.portal.Documents";
const PORTAL_PATH: &str = "/org/freedesktop/portal/documents";
const PORTAL_IFACE: &str = "org.freedesktop.portal.Documents";

// Bit 2 (`persistent`) is deliberately not set — a grant lasts the session.
const FLAG_REUSE_EXISTING: u32 = 1;

// `sysfs`, as `statfs(2)` lists it. rustix names `PROC_SUPER_MAGIC`
// but not this one.
const SYSFS_MAGIC: rustix::fs::FsWord = 0x6265_6572;

/// What kept one file from reaching the sandbox. Every variant leaves
/// the argument as it was; forwarding is never a hard failure.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    /// The file could not be opened to hand the portal a descriptor.
    #[error("opening {}", .path.display())]
    Open {
        /// File the open was attempted on.
        path: PathBuf,
        /// What the kernel said.
        #[source]
        source: io::Error,
    },
    /// The opened descriptor is not a regular file. The type is checked
    /// again on the descriptor, so a path that changed under us between
    /// [`plan`](crate::forward::plan) and the open cannot smuggle a directory to the portal.
    #[error("{} is not a regular file", .0.display())]
    NotAFile(PathBuf),
    /// The descriptor turned out to name a path under `/proc`, `/sys`
    /// or `/dev`. Those `fstat` as regular files, so the check that
    /// [`plan`](crate::forward::plan) made on the path is made again on what was opened.
    #[error("{} names {} now, which is under /proc, /sys or /dev", .path.display(), .real.display())]
    Refused {
        /// File the argument named.
        path: PathBuf,
        /// What the descriptor turned out to be open on.
        real: PathBuf,
    },
    /// The portal refused the call: its D-Bus error name and message.
    #[error("{name}: {message}")]
    Portal {
        /// D-Bus error name, e.g. `org.freedesktop.portal.Error.NotAllowed`.
        name: String,
        /// Text the portal attached, empty if it sent none.
        message: String,
    },
    /// The call did not reach the portal, or the connection failed
    /// under it.
    #[error("the document portal call failed: {0}")]
    Bus(String),
    /// The portal answered with something `AddFull` is not specified to
    /// answer with, which is not a reply to guess at.
    #[error("the document portal answered with {0}")]
    Answer(&'static str),
}

/// Ask the portal for every candidate and say where each file landed, one answer per
/// candidate in the order given. Any [`WireError`] other than a refusal leaves the
/// connection half-read, so a caller that means to reuse it drops it instead.
pub fn register(
    env: &Env,
    instance: &str,
    candidates: &[Candidate],
    session: &mut Session,
) -> Vec<Result<Forward, ForwardError>> {
    let mut done: Vec<Option<Result<Forward, ForwardError>>> =
        candidates.iter().map(|_| None).collect();
    let mut open: Vec<Opened> = Vec::with_capacity(candidates.len());
    for (index, candidate) in candidates.iter().enumerate() {
        match open_path(&candidate.host) {
            Ok((fd, name)) => open.push(Opened { index, fd, name }),
            Err(e) => done[index] = Some(Err(e)),
        }
    }

    let app_id = crate::dbus::app_id(instance);
    // Anything but a refusal or a call that never left this process leaves the connection
    // half-read, so the remaining groups are failed with the same reason.
    let mut broken: Option<String> = None;
    for write in permission_sets(candidates) {
        let group: Vec<&Opened> = open
            .iter()
            .filter(|opened| candidates[opened.index].write == write)
            .collect();
        if group.is_empty() {
            continue;
        }
        let fds: Vec<BorrowedFd<'_>> = group.iter().map(|opened| opened.fd.as_fd()).collect();
        // A `h` on the wire is an index into the descriptors beside the
        // message, in the order they are sent.
        let indices: Vec<Value> = (0u32..).zip(&group).map(|(n, _)| Value::Fd(n)).collect();
        let body = [
            Value::Array(indices),
            Value::Uint32(FLAG_REUSE_EXISTING),
            Value::Str(app_id.clone()),
            Value::Array(permissions(write)),
        ];
        let answer = match &broken {
            Some(reason) => Err(ForwardError::Bus(reason.clone())),
            None => match session.call(
                PORTAL_NAME,
                PORTAL_PATH,
                PORTAL_IFACE,
                "AddFull",
                "ahusas",
                &body,
                &fds,
            ) {
                Ok(values) => document_ids(&values, group.len()),
                Err(e) => {
                    if !matches!(e, WireError::Remote { .. }) && !before_sending(&e) {
                        broken = Some(e.to_string());
                    }
                    Err(wire_reason(&e))
                }
            },
        };
        match &answer {
            Ok(ids) => {
                for (opened, id) in group.iter().zip(ids) {
                    let candidate = &candidates[opened.index];
                    done[opened.index] = Some(Ok(Forward {
                        arg_index: candidate.arg_index,
                        host: candidate.host.clone(),
                        // The name the descriptor has, not the one the plan saw: a file
                        // renamed since cannot leave a document path that opens nothing.
                        inside: env.runtime_dir.join(DOC_DIR).join(id).join(&opened.name),
                        write: candidate.write,
                    }));
                }
            }
            Err(reason) => {
                for opened in &group {
                    done[opened.index] = Some(Err(reason.again()));
                }
            }
        }
    }

    done.into_iter()
        .map(|answer| {
            answer.expect("every candidate is opened into a group or refused before this point")
        })
        .collect()
}

// `O_PATH` is what Flatpak passes and all the portal needs: bubbler never
// holds an open handle to the user's document.
fn open_path(path: &Path) -> Result<(OwnedFd, OsString), ForwardError> {
    let failed = |source: rustix::io::Errno| ForwardError::Open {
        path: path.to_path_buf(),
        source: source.into(),
    };
    let fd =
        rustix::fs::open(path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).map_err(failed)?;
    let stat = rustix::fs::fstat(&fd).map_err(failed)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(ForwardError::NotAFile(path.to_path_buf()));
    }
    // Everything under `/proc` and `/sys` `fstat`s as a regular file, so
    // the type says nothing about it.
    let real = opened_path(fd.as_fd()).map_err(failed)?;
    let magic = rustix::fs::fstatfs(&fd).map_err(failed)?.f_type;
    if magic == rustix::fs::PROC_SUPER_MAGIC
        || magic == SYSFS_MAGIC
        || REFUSED_ROOTS.iter().any(|root| real.starts_with(root))
    {
        return Err(ForwardError::Refused {
            path: path.to_path_buf(),
            real,
        });
    }
    // A descriptor whose path has no name is not one this could export, so
    // the candidate's own name is left to the portal to disagree with.
    let name = real.file_name().map_or_else(
        || OsString::from(path.file_name().unwrap_or_default()),
        OsStr::to_os_string,
    );
    Ok((fd, name))
}

struct Opened {
    index: usize,
    fd: OwnedFd,
    name: OsString,
}

// A file unlinked meanwhile reads as its old path with ` (deleted)` after it,
// which is under no root either way.
fn opened_path(fd: BorrowedFd<'_>) -> Result<PathBuf, rustix::io::Errno> {
    use std::os::fd::AsRawFd;
    let link = Path::new("/proc/self/fd").join(fd.as_raw_fd().to_string());
    let target = rustix::fs::readlink(&link, Vec::new())?;
    Ok(PathBuf::from(OsString::from_vec(target.into_bytes())))
}

// The portal is another process on the bus, so an id that is not a single
// path component is refused rather than joined into a path.
fn document_ids(values: &[Value], expected: usize) -> Result<Vec<String>, ForwardError> {
    let [Value::Array(ids), Value::Dict(_)] = values else {
        return Err(ForwardError::Answer("a reply that is not (as, a{sv})"));
    };
    if ids.len() != expected {
        return Err(ForwardError::Answer(
            "a different number of document ids than files",
        ));
    }
    ids.iter()
        .map(|id| match id {
            Value::Str(id) if is_document_id(id) => Ok(id.clone()),
            _ => Err(ForwardError::Answer("a document id that is not a name")),
        })
        .collect()
}

fn is_document_id(id: &str) -> bool {
    !id.is_empty() && id != "." && id != ".." && !id.contains('/') && !id.contains('\0')
}

// Only failures the decoder cannot also raise, all of which `Session::call` checks
// before it sends anything. The marshalling errors a reply can produce as easily as a body —
// `BadSignature` and `Unsupported` from a variant or a dict entry inside an answer, `BadString`,
// `ArrayTooLong`, `MessageTooLong`, `Depth` — count as breaking: the values bubbler encodes here
// cannot raise them, and reading a reply that far means the connection is past a point this
// client can account for.
fn before_sending(e: &WireError) -> bool {
    matches!(
        e,
        WireError::NoDestination
            | WireError::NoFdPassing
            | WireError::TooManyFds(_)
            | WireError::FdIndex(_)
            | WireError::Arity { .. }
            | WireError::TypeMismatch { .. }
    )
}

fn wire_reason(e: &WireError) -> ForwardError {
    match e {
        WireError::Remote { name, message } => ForwardError::Portal {
            name: name.clone(),
            message: message.clone(),
        },
        other => ForwardError::Bus(other.to_string()),
    }
}

impl ForwardError {
    // `io::Error` is not `Clone`, so an open failure — which is never shared —
    // keeps only its text here.
    fn again(&self) -> Self {
        match self {
            ForwardError::Open { path, source } => ForwardError::Open {
                path: path.clone(),
                source: io::Error::new(source.kind(), source.to_string()),
            },
            ForwardError::NotAFile(path) => ForwardError::NotAFile(path.clone()),
            ForwardError::Refused { path, real } => ForwardError::Refused {
                path: path.clone(),
                real: real.clone(),
            },
            ForwardError::Portal { name, message } => ForwardError::Portal {
                name: name.clone(),
                message: message.clone(),
            },
            ForwardError::Bus(text) => ForwardError::Bus(text.clone()),
            ForwardError::Answer(text) => ForwardError::Answer(text),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    use super::*;
    use crate::dbus_session::testing::*;

    fn env() -> Env {
        Env {
            home: "/home/user".into(),
            data_home: "/home/user/.local/share".into(),
            config_home: "/home/user/.config".into(),
            config_dirs: Vec::new(),
            data_dirs: crate::env::DEFAULT_DATA_DIRS
                .iter()
                .map(PathBuf::from)
                .collect(),
            runtime_dir: "/run/user/1000".into(),
            uid: 1000,
            gid: 1000,
            wayland_display: None,
            display: None,
            xauthority: None,
            passthrough: vec![],
            init_override: None,
            dbus_address: None,
            dbus_system_address: None,
            at_spi_bus_address: None,
            dbus_log: false,
            net_proxy_log: false,
            seccomp_log: false,
            test_allow_path: None,
            profile_dir_override: None,
            proxy_override: None,
            pasta_override: None,
            pw_dump_override: None,
            wl_proxy_override: None,
            net_proxy_override: None,
        }
    }

    /// The unique name the fake bus says the portal holds. Every reply
    /// carries the `SENDER` a real bus stamps on it.
    const PORTAL_OWNER: &str = ":1.77";

    /// The next `AddFull` the client makes, with the lookup of who owns
    /// the portal name answered on the way.
    fn server_addfull(stream: &UnixStream) -> Call {
        server_awaiting(stream, "AddFull", PORTAL_OWNER)
    }

    /// The `(as, a{sv})` an `AddFull` answers with.
    fn server_ids(stream: &UnixStream, call: &Call, ids: &[&str]) {
        server_reply(
            stream,
            2,
            call.serial,
            PORTAL_OWNER,
            "asa{sv}",
            &[
                Value::Array(ids.iter().map(|id| Value::Str((*id).to_owned())).collect()),
                Value::Dict(Vec::new()),
            ],
        );
    }

    /// Nothing more from the client: the connection ends where it is.
    /// A client that stopped mid-message closes with bytes unread, which
    /// the kernel reports here as a reset once nothing it sent is left.
    fn server_end(stream: &UnixStream) {
        let mut byte = [0u8; 1];
        match (&*stream).read(&mut byte) {
            Ok(got) => assert_eq!(got, 0, "the client sent a message it had no reason to send"),
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset),
        }
    }

    /// An `AddFull` answer whose `a{sv}` holds a variant claiming a type
    /// code that is not one. The reply is well framed, so the client
    /// reads it before refusing it — which is what puts the connection
    /// past the point it can account for.
    fn server_bad_variant(stream: &UnixStream, call: &Call) {
        let mut message = reply_bytes(
            9,
            call.serial,
            PORTAL_OWNER,
            "asa{sv}",
            &[
                Value::Array(vec![Value::Str("one".to_owned())]),
                Value::Dict(vec![(
                    "k".to_owned(),
                    Value::Variant(Box::new(Value::Str("v".to_owned()))),
                )]),
            ],
        );
        // The one `<len> s <nul>` in the message is that variant's own
        // signature; `r` is reserved and names no type.
        let at = message
            .windows(3)
            .position(|w| w == [1, b's', 0])
            .expect("the variant signature is in the reply");
        message[at + 1] = b'r';
        (&*stream).write_all(&message).unwrap();
    }

    /// A reply whose byte-order flag is flipped to big-endian: its
    /// header-field length, read that way, is past 2^26, so the frame
    /// cannot be measured and the connection is left half-read.
    fn server_unusable_frame(stream: &UnixStream, call: &Call) {
        let mut message = reply_bytes(9, call.serial, PORTAL_OWNER, "", &[]);
        message[0] = b'B';
        (&*stream).write_all(&message).unwrap();
    }

    fn candidate(arg_index: usize, path: &Path, write: bool) -> Candidate {
        Candidate {
            arg_index,
            given: path.to_path_buf(),
            host: path.to_path_buf(),
            name: path.file_name().unwrap().to_os_string(),
            write,
        }
    }

    fn file(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, name.as_bytes()).unwrap();
        path
    }

    #[test]
    fn one_call_carries_the_descriptor_the_flags_and_the_app_id() {
        let tmp = tempfile::tempdir().unwrap();
        let doc = file(tmp.path(), "a.pdf");
        let want = std::fs::metadata(&doc).unwrap();
        let (bus, server) = fake_bus(tmp.path(), move |stream| {
            server_start(&stream);
            let call = server_addfull(&stream);
            // The unique name the lookup gave, so the call and its
            // reply are bound to the one connection that answered.
            assert_eq!(call.text(FIELD_DESTINATION), PORTAL_OWNER);
            assert_eq!(call.text(FIELD_PATH), PORTAL_PATH);
            assert_eq!(call.text(FIELD_INTERFACE), PORTAL_IFACE);
            assert_eq!(call.text(FIELD_MEMBER), "AddFull");
            assert_eq!(call.signature, "ahusas");
            assert_eq!(
                call.body,
                vec![
                    Value::Array(vec![Value::Fd(0)]),
                    Value::Uint32(1),
                    Value::Str("org.bubbler.pdf".to_owned()),
                    Value::Array(vec![Value::Str("read".to_owned())]),
                ]
            );
            // The descriptor is the file itself, not its name.
            assert_eq!(call.fds.len(), 1);
            let got = rustix::fs::fstat(&call.fds[0]).unwrap();
            use std::os::unix::fs::MetadataExt;
            assert_eq!((got.st_ino, got.st_dev), (want.ino(), want.dev()));
            server_ids(&stream, &call, &["a1b2"]);
        });
        let mut session = Session::connect(&bus).unwrap();
        let out = register(&env(), "pdf", &[candidate(3, &doc, false)], &mut session);
        drop(session);
        server.join().unwrap();
        assert_eq!(
            out.into_iter().map(Result::unwrap).collect::<Vec<_>>(),
            vec![Forward {
                arg_index: 3,
                host: doc,
                inside: "/run/user/1000/doc/a1b2/a.pdf".into(),
                write: false,
            }]
        );
    }

    #[test]
    fn a_permission_set_is_one_call_and_the_ids_come_back_in_order() {
        let tmp = tempfile::tempdir().unwrap();
        let a = file(tmp.path(), "a.pdf");
        let b = file(tmp.path(), "b.pdf");
        let c = file(tmp.path(), "c.pdf");
        let (bus, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            // The writable files come first: they are what the first
            // candidate asked for.
            let first = server_addfull(&stream);
            assert_eq!(
                first.body[3],
                Value::Array(vec![
                    Value::Str("read".to_owned()),
                    Value::Str("write".to_owned()),
                ])
            );
            assert_eq!(first.fds.len(), 2);
            server_ids(&stream, &first, &["ida", "idc"]);
            let second = server_addfull(&stream);
            assert_eq!(
                second.body[3],
                Value::Array(vec![Value::Str("read".to_owned())])
            );
            assert_eq!(second.fds.len(), 1);
            server_ids(&stream, &second, &["idb"]);
        });
        let mut session = Session::connect(&bus).unwrap();
        let out = register(
            &env(),
            "pdf",
            &[
                candidate(0, &a, true),
                candidate(1, &b, false),
                candidate(2, &c, true),
            ],
            &mut session,
        );
        drop(session);
        server.join().unwrap();
        let inside: Vec<PathBuf> = out
            .into_iter()
            .map(|forward| forward.unwrap().inside)
            .collect();
        assert_eq!(
            inside,
            vec![
                PathBuf::from("/run/user/1000/doc/ida/a.pdf"),
                PathBuf::from("/run/user/1000/doc/idb/b.pdf"),
                PathBuf::from("/run/user/1000/doc/idc/c.pdf"),
            ]
        );
    }

    #[test]
    fn a_refusal_leaves_every_file_of_that_call_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let a = file(tmp.path(), "a.pdf");
        let b = file(tmp.path(), "b.pdf");
        let (bus, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            let call = server_addfull(&stream);
            server_error(
                &stream,
                call.serial,
                PORTAL_OWNER,
                "org.freedesktop.portal.Error.NotAllowed",
                "no",
            );
        });
        let mut session = Session::connect(&bus).unwrap();
        let out = register(
            &env(),
            "pdf",
            &[candidate(0, &a, false), candidate(1, &b, false)],
            &mut session,
        );
        drop(session);
        server.join().unwrap();
        assert_eq!(out.len(), 2);
        for answer in out {
            let e = answer.unwrap_err();
            assert!(
                matches!(&e, ForwardError::Portal { name, message }
                    if name == "org.freedesktop.portal.Error.NotAllowed" && message == "no"),
                "{e:?}"
            );
            assert_eq!(e.to_string(), "org.freedesktop.portal.Error.NotAllowed: no");
        }
    }

    #[test]
    fn a_file_that_is_not_one_when_it_is_opened_is_dropped_from_the_call() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("pics");
        std::fs::create_dir(&dir).unwrap();
        let gone = tmp.path().join("gone.pdf");
        let doc = file(tmp.path(), "a.pdf");
        let (bus, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            let call = server_addfull(&stream);
            // Only the one file that is still a file is asked for.
            assert_eq!(call.fds.len(), 1);
            assert_eq!(call.body[0], Value::Array(vec![Value::Fd(0)]));
            server_ids(&stream, &call, &["only"]);
        });
        let mut session = Session::connect(&bus).unwrap();
        let out = register(
            &env(),
            "pdf",
            &[
                candidate(0, &dir, false),
                candidate(1, &gone, false),
                candidate(2, &doc, false),
            ],
            &mut session,
        );
        drop(session);
        server.join().unwrap();
        assert!(matches!(&out[0], Err(ForwardError::NotAFile(p)) if *p == dir));
        assert!(matches!(&out[1], Err(ForwardError::Open { path, .. }) if *path == gone));
        assert_eq!(
            out[2].as_ref().unwrap().inside,
            PathBuf::from("/run/user/1000/doc/only/a.pdf")
        );
    }

    #[test]
    fn a_document_id_that_is_not_a_name_is_refused_rather_than_joined() {
        let tmp = tempfile::tempdir().unwrap();
        let doc = file(tmp.path(), "a.pdf");
        let (bus, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            let call = server_addfull(&stream);
            server_ids(&stream, &call, &["../../../etc"]);
        });
        let mut session = Session::connect(&bus).unwrap();
        let out = register(&env(), "pdf", &[candidate(0, &doc, false)], &mut session);
        drop(session);
        server.join().unwrap();
        assert!(matches!(
            out[0].as_ref().unwrap_err(),
            ForwardError::Answer("a document id that is not a name")
        ));
    }

    #[test]
    fn an_answer_of_the_wrong_shape_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let doc = file(tmp.path(), "a.pdf");
        let (bus, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            let call = server_addfull(&stream);
            server_ids(&stream, &call, &["one", "two"]);
            let call = server_addfull(&stream);
            server_reply(
                &stream,
                3,
                call.serial,
                PORTAL_OWNER,
                "s",
                &[Value::Str("what".to_owned())],
            );
        });
        let mut session = Session::connect(&bus).unwrap();
        let one = register(&env(), "pdf", &[candidate(0, &doc, false)], &mut session);
        assert!(matches!(
            one[0].as_ref().unwrap_err(),
            ForwardError::Answer("a different number of document ids than files")
        ));
        let two = register(&env(), "pdf", &[candidate(0, &doc, false)], &mut session);
        assert!(matches!(
            two[0].as_ref().unwrap_err(),
            ForwardError::Answer("a reply that is not (as, a{sv})")
        ));
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn nothing_to_register_makes_no_call_at_all() {
        let tmp = tempfile::tempdir().unwrap();
        let (bus, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            server_end(&stream);
        });
        let mut session = Session::connect(&bus).unwrap();
        assert!(register(&env(), "pdf", &[], &mut session).is_empty());
        drop(session);
        server.join().unwrap();
    }

    #[test]
    fn a_descriptor_that_lands_in_proc_is_refused_after_the_open() {
        let tmp = tempfile::tempdir().unwrap();
        // What a swap between the plan and the open looks like: the
        // name is still there, the file behind it is a procfs entry,
        // which `fstat`s as a regular file.
        let link = tmp.path().join("a.pdf");
        std::os::unix::fs::symlink("/proc/self/environ", &link).unwrap();
        let (bus, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            server_end(&stream);
        });
        let mut session = Session::connect(&bus).unwrap();
        let out = register(&env(), "pdf", &[candidate(0, &link, false)], &mut session);
        drop(session);
        server.join().unwrap();
        let e = out[0].as_ref().unwrap_err();
        assert!(
            matches!(e, ForwardError::Refused { path, real }
                if *path == link && real.starts_with("/proc")),
            "{e:?}"
        );
    }

    #[test]
    fn a_call_that_never_left_does_not_fail_the_other_files() {
        let tmp = tempfile::tempdir().unwrap();
        // One descriptor past what a message may carry, so the call is
        // refused here rather than on the bus; the writable file is a
        // second group and must still go out.
        let many: Vec<PathBuf> = (0..254)
            .map(|n| file(tmp.path(), &format!("r{n}.pdf")))
            .collect();
        let writable = file(tmp.path(), "w.pdf");
        let (bus, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            let call = server_addfull(&stream);
            assert_eq!(call.fds.len(), 1);
            assert_eq!(
                call.body[3],
                Value::Array(vec![
                    Value::Str("read".to_owned()),
                    Value::Str("write".to_owned()),
                ])
            );
            server_ids(&stream, &call, &["only"]);
            server_end(&stream);
        });
        let mut candidates: Vec<Candidate> = many
            .iter()
            .enumerate()
            .map(|(n, path)| candidate(n, path, false))
            .collect();
        candidates.push(candidate(many.len(), &writable, true));
        let mut session = Session::connect(&bus).unwrap();
        let out = register(&env(), "pdf", &candidates, &mut session);
        drop(session);
        server.join().unwrap();
        for answer in &out[..many.len()] {
            assert!(
                matches!(answer.as_ref().unwrap_err(), ForwardError::Bus(_)),
                "{answer:?}"
            );
        }
        assert_eq!(
            out[many.len()].as_ref().unwrap().inside,
            PathBuf::from("/run/user/1000/doc/only/w.pdf")
        );
    }

    #[test]
    fn the_document_path_uses_the_name_the_descriptor_has() {
        let tmp = tempfile::tempdir().unwrap();
        // A rename between the plan and the call: what the plan saw is
        // now a link to the name the file has, and the portal reads the
        // new name off the descriptor as this does.
        let stale = tmp.path().join("old.pdf");
        let renamed = file(tmp.path(), "new.pdf");
        std::os::unix::fs::symlink(&renamed, &stale).unwrap();
        let (bus, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            let call = server_addfull(&stream);
            server_ids(&stream, &call, &["a1b2"]);
        });
        let mut session = Session::connect(&bus).unwrap();
        let out = register(&env(), "pdf", &[candidate(0, &stale, false)], &mut session);
        drop(session);
        server.join().unwrap();
        assert_eq!(
            out[0].as_ref().unwrap().inside,
            PathBuf::from("/run/user/1000/doc/a1b2/new.pdf")
        );
    }

    #[test]
    fn a_reply_the_client_cannot_read_ends_the_session() {
        let tmp = tempfile::tempdir().unwrap();
        let a = file(tmp.path(), "a.pdf");
        let b = file(tmp.path(), "b.pdf");
        let (bus, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            let call = server_addfull(&stream);
            server_bad_variant(&stream, &call);
            server_end(&stream);
        });
        let mut session = Session::connect(&bus).unwrap();
        let out = register(
            &env(),
            "pdf",
            &[candidate(0, &a, true), candidate(1, &b, false)],
            &mut session,
        );
        drop(session);
        server.join().unwrap();
        for answer in &out {
            assert!(
                matches!(answer.as_ref().unwrap_err(), ForwardError::Bus(_)),
                "{answer:?}"
            );
        }
    }

    #[test]
    fn a_session_that_broke_is_not_called_again() {
        let tmp = tempfile::tempdir().unwrap();
        let a = file(tmp.path(), "a.pdf");
        let b = file(tmp.path(), "b.pdf");
        let (bus, server) = fake_bus(tmp.path(), |stream| {
            server_start(&stream);
            let call = server_addfull(&stream);
            // A frame whose length cannot be read leaves the connection
            // half-read, which is the case the second group must not be
            // sent down.
            server_unusable_frame(&stream, &call);
            server_end(&stream);
        });
        let mut session = Session::connect(&bus).unwrap();
        let out = register(
            &env(),
            "pdf",
            &[candidate(0, &a, true), candidate(1, &b, false)],
            &mut session,
        );
        drop(session);
        server.join().unwrap();
        for answer in &out {
            assert!(
                matches!(answer.as_ref().unwrap_err(), ForwardError::Bus(_)),
                "{answer:?}"
            );
        }
        assert_eq!(
            out[0].as_ref().unwrap_err().to_string(),
            out[1].as_ref().unwrap_err().to_string()
        );
    }
}
