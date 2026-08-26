//! Handing the sandbox one host file at a time through the document
//! portal.
//!
//! A file manager's "open with" expands to a host path the sandbox
//! cannot see: the instance home is private and nothing else of the
//! user's home is bound. `org.freedesktop.portal.Documents.AddFull`
//! takes an `O_PATH` descriptor of the file and returns a document id;
//! the file then appears inside at `$XDG_RUNTIME_DIR/doc/<id>/<name>`,
//! which the `portals` service binds as this instance's by-app view.
//!
//! Nothing here widens a sandbox on its own: [`plan`] only classifies
//! arguments, [`register`] grants one file per call with `read`, or
//! `read`+`write` where the user could write it anyway, and every
//! failure leaves the argument as it was.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};

use crate::config::{InstanceConfig, Service};
use crate::dbus_wire::{Session, Value, WireError};
use crate::env::Env;
use crate::host::Host;

/// The document portal: bus name, object and interface.
const PORTAL_NAME: &str = "org.freedesktop.portal.Documents";
const PORTAL_PATH: &str = "/org/freedesktop/portal/documents";
const PORTAL_IFACE: &str = "org.freedesktop.portal.Documents";

/// `AddFull` flag 1, `reuse_existing`: a file already exported to this
/// app id keeps the id it has instead of collecting one per open. Bit 2
/// (`persistent`) is deliberately not set — a grant lasts the session.
const FLAG_REUSE_EXISTING: u32 = 1;

/// Directory of the by-app document view, under `$XDG_RUNTIME_DIR` both
/// on the host and inside the sandbox.
const DOC_DIR: &str = "doc";

/// Path prefixes never forwarded: they name kernel interfaces and the
/// sandbox's own devices, not documents, and the sandbox has its own
/// `/proc` and `/dev` already.
const REFUSED_ROOTS: [&str; 3] = ["/proc", "/sys", "/dev"];

/// A host file an argument names, worth asking the portal for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Position in the argument list this was found at.
    pub arg_index: usize,
    /// The file on the host, absolute and with any `file://` decoded.
    pub host: PathBuf,
    /// Basename the file keeps inside the document view.
    pub name: OsString,
    /// Whether `write` is asked for as well as `read`: true only where
    /// the user may already write the file.
    pub write: bool,
}

/// Why an argument that named a path is not forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// Not an absolute path. What it resolves against is the caller's
    /// working directory, which the sandbox does not share.
    Relative,
    /// Not a regular file: a socket, a device, or nothing at all.
    NotAFile,
    /// A directory. The portal can export one, but a directory handed
    /// over wholesale is what `path-share` and `home-share` are for.
    Directory,
    /// Under `/proc`, `/sys` or `/dev`: a kernel interface, not a
    /// document, and one the sandbox has its own of already.
    Refused,
    /// Already reachable inside through a share or the instance home,
    /// so it costs the sandbox nothing to leave the argument alone.
    AlreadyVisible,
}

/// What [`plan`] decided about one argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Planned {
    /// A host file to ask the portal for.
    Forward(Candidate),
    /// An argument that named a path bubbler will not forward, with the
    /// path as it was decoded and the reason.
    Skip(usize, PathBuf, Skip),
    /// Not a path at all: a flag, a bare word, another URI scheme.
    Untouched,
}

/// One file the portal exported, and where the sandbox will find it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    /// Position of the argument to replace.
    pub arg_index: usize,
    /// The file on the host.
    pub host: PathBuf,
    /// `$XDG_RUNTIME_DIR/doc/<id>/<name>`, the path inside the sandbox.
    pub inside: PathBuf,
    /// Whether the sandbox was granted `write` as well as `read`.
    pub write: bool,
}

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
    /// [`plan`] and the open cannot smuggle a directory to the portal.
    #[error("{} is not a regular file", .0.display())]
    NotAFile(PathBuf),
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

/// Classify every argument: which name a host file worth forwarding,
/// which name one bubbler will not forward and why, which are not paths.
///
/// `args` are the *arguments* of the sandboxed command, never the
/// program itself — a program is a path inside the sandbox, and
/// replacing it with a document path would swap the binary that runs.
///
/// Nothing is registered and nothing is opened here, so the result is
/// what `--dry-run` and `--explain` print.
pub fn plan(
    env: &Env,
    cfg: &InstanceConfig,
    instance_home: &Path,
    args: &[OsString],
    host: &dyn Host,
) -> Vec<Planned> {
    let visible = visible_roots(env, cfg, instance_home);
    args.iter()
        .enumerate()
        .map(|(index, arg)| classify(index, arg, &visible, host))
        .collect()
}

/// Ask the portal for every candidate and say where each file landed.
///
/// One answer per candidate, in the order given: an entry that failed
/// leaves that argument alone rather than the whole launch. `AddFull`
/// takes one permission set for all of its descriptors, so the
/// candidates are grouped by permission and one call is made per group.
///
/// The session is the caller's: any [`WireError`] other than a refusal
/// leaves the connection half-read, so a caller that means to reuse it
/// drops it instead.
pub fn register(
    env: &Env,
    instance: &str,
    candidates: &[Candidate],
    session: &mut Session,
) -> Vec<Result<Forward, ForwardError>> {
    let mut done: Vec<Option<Result<Forward, ForwardError>>> =
        candidates.iter().map(|_| None).collect();
    let mut open: Vec<(usize, OwnedFd)> = Vec::with_capacity(candidates.len());
    for (index, candidate) in candidates.iter().enumerate() {
        match open_path(&candidate.host) {
            Ok(fd) => open.push((index, fd)),
            Err(e) => done[index] = Some(Err(e)),
        }
    }

    let app_id = crate::dbus::app_id(instance);
    for write in permission_sets(candidates) {
        let group: Vec<&(usize, OwnedFd)> = open
            .iter()
            .filter(|(index, _)| candidates[*index].write == write)
            .collect();
        if group.is_empty() {
            continue;
        }
        let fds: Vec<BorrowedFd<'_>> = group.iter().map(|(_, fd)| fd.as_fd()).collect();
        // A `h` on the wire is an index into the descriptors beside the
        // message, in the order they are sent.
        let indices: Vec<Value> = (0u32..).zip(&group).map(|(n, _)| Value::Fd(n)).collect();
        let body = [
            Value::Array(indices),
            Value::Uint32(FLAG_REUSE_EXISTING),
            Value::Str(app_id.clone()),
            Value::Array(permissions(write)),
        ];
        let answer = session
            .call(
                PORTAL_NAME,
                PORTAL_PATH,
                PORTAL_IFACE,
                "AddFull",
                "ahusas",
                &body,
                &fds,
            )
            .map_err(|e| wire_reason(&e))
            .and_then(|values| document_ids(&values, group.len()));
        match &answer {
            Ok(ids) => {
                for ((index, _), id) in group.iter().zip(ids) {
                    let candidate = &candidates[*index];
                    done[*index] = Some(Ok(Forward {
                        arg_index: candidate.arg_index,
                        host: candidate.host.clone(),
                        inside: env.runtime_dir.join(DOC_DIR).join(id).join(&candidate.name),
                        write: candidate.write,
                    }));
                }
            }
            Err(reason) => {
                for (index, _) in &group {
                    done[*index] = Some(Err(reason.again()));
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

/// The argument list with each forwarded file replaced by its path
/// inside the sandbox. Arguments nothing was registered for are copied
/// as they were, `file://` URIs included.
pub fn rewrite(args: &[OsString], forwards: &[Forward]) -> Vec<OsString> {
    let mut out = args.to_vec();
    for forward in forwards {
        if let Some(arg) = out.get_mut(forward.arg_index) {
            *arg = forward.inside.clone().into_os_string();
        }
    }
    out
}

/// One line per file that would be forwarded, for `--explain` and
/// `--dry-run`. The document id is a literal `<id>`: it exists only
/// once the portal has been called, which neither of those does.
pub fn explain_lines(planned: &[Planned]) -> Vec<String> {
    planned
        .iter()
        .filter_map(|entry| match entry {
            Planned::Forward(candidate) => Some(format!(
                "forward: {} → $XDG_RUNTIME_DIR/{DOC_DIR}/<id>/{} ({})",
                candidate.host.display(),
                Path::new(&candidate.name).display(),
                permission_text(candidate.write),
            )),
            _ => None,
        })
        .collect()
}

/// One line per argument that named a path bubbler will not forward,
/// for the caller to print as a warning. A path that is already visible
/// inside, or that is not a path at all, says nothing.
pub fn warning_lines(planned: &[Planned]) -> Vec<String> {
    planned
        .iter()
        .filter_map(|entry| match entry {
            Planned::Skip(_, path, Skip::Directory) => Some(format!(
                "{} is a directory; grant path-share or home-share to expose it",
                path.display()
            )),
            Planned::Skip(_, path, Skip::NotAFile) => Some(format!(
                "{} is not a regular file, not forwarded",
                path.display()
            )),
            Planned::Skip(_, path, Skip::Refused) => Some(format!(
                "{} is under /proc, /sys or /dev, not forwarded",
                path.display()
            )),
            _ => None,
        })
        .collect()
}

/// What one argument is.
fn classify(index: usize, arg: &OsStr, visible: &[PathBuf], host: &dyn Host) -> Planned {
    let path = match host_path(arg) {
        Some(path) if path.is_absolute() => path,
        Some(path) => return Planned::Skip(index, path, Skip::Relative),
        None => return Planned::Untouched,
    };
    // The literal path and the path with its symlinks resolved are both
    // checked: a link under the user's home is a path into `/proc` as
    // much as the name itself is.
    let refused = |p: &Path| REFUSED_ROOTS.iter().any(|root| p.starts_with(root));
    if refused(&path) || host.canonicalize(&path).is_some_and(|real| refused(&real)) {
        return Planned::Skip(index, path, Skip::Refused);
    }
    if visible.iter().any(|root| path.starts_with(root)) {
        return Planned::Skip(index, path, Skip::AlreadyVisible);
    }
    let Some(kind) = host.file_type(&path) else {
        return Planned::Skip(index, path, Skip::NotAFile);
    };
    if kind.is_dir() {
        return Planned::Skip(index, path, Skip::Directory);
    }
    // A regular file always has a name; the `None` is `/` and paths
    // ending in `..`, which are directories anyway.
    let (true, Some(name)) = (kind.is_file(), path.file_name().map(OsStr::to_os_string)) else {
        return Planned::Skip(index, path, Skip::NotAFile);
    };
    let write = host.writable(&path);
    Planned::Forward(Candidate {
        arg_index: index,
        host: path,
        name,
        write,
    })
}

/// Host roots the sandbox can already reach: the source of every share
/// the config grants, and the instance's own home.
fn visible_roots(env: &Env, cfg: &InstanceConfig, instance_home: &Path) -> Vec<PathBuf> {
    let mut roots = vec![instance_home.to_path_buf()];
    for service in &cfg.services {
        match service {
            Service::HomeShare { path, .. } => roots.push(env.home.join(path)),
            Service::PathShare { path, .. } => roots.push(path.clone()),
            _ => {}
        }
    }
    // A root that is not absolute compares against nothing, and an
    // empty one is a prefix of every path — which would quietly forward
    // no file at all.
    roots.retain(|root| root.is_absolute());
    roots
}

/// The host path an argument names, or `None` when it names none: a
/// flag, a bare word, another URI scheme, a `file://` URI with a
/// foreign authority, or a path with a nul in it, which names no file.
fn host_path(arg: &OsStr) -> Option<PathBuf> {
    let bytes = arg.as_bytes();
    let decoded;
    let path: &[u8] = match bytes.split_at_checked(5) {
        // "file://localhost/x" and "file:///x" name the same file;
        // RFC 8089 gives an empty authority and "localhost" that
        // meaning and nothing else. A host bubbler cannot reach is not
        // a file to forward.
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case(b"file:") => {
            let rest = match rest.strip_prefix(b"//") {
                None => rest,
                Some(rest) => {
                    let split = rest.iter().position(|b| *b == b'/')?;
                    let (authority, path) = rest.split_at(split);
                    if !(authority.is_empty() || authority.eq_ignore_ascii_case(b"localhost")) {
                        return None;
                    }
                    path
                }
            };
            decoded = percent_decode(rest);
            &decoded
        }
        // A path only where the argument is shaped like one. Anything
        // else is the command's own business.
        _ if bytes.starts_with(b"/") || bytes.starts_with(b"./") || bytes.starts_with(b"../") => {
            bytes
        }
        _ => return None,
    };
    if path.is_empty() || path.contains(&0) {
        return None;
    }
    Some(PathBuf::from(OsString::from_vec(path.to_vec())))
}

/// Percent-decoding as "URI Syntax" defines it. A `%` that does not
/// start a valid escape is left as it is: senders that never encoded it
/// meant the character, and a file that does not exist is refused a few
/// lines later anyway.
fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while let Some((first, tail)) = rest.split_first() {
        match (first, tail.split_at_checked(2)) {
            (b'%', Some((digits, after))) => match (hex(digits[0]), hex(digits[1])) {
                (Some(high), Some(low)) => {
                    out.push(high << 4 | low);
                    rest = after;
                }
                _ => {
                    out.push(*first);
                    rest = tail;
                }
            },
            _ => {
                out.push(*first);
                rest = tail;
            }
        }
    }
    out
}

/// One hexadecimal digit, either case.
fn hex(b: u8) -> Option<u8> {
    char::from(b).to_digit(16).map(|d| d as u8)
}

/// The permission sets the candidates need, in the order they first
/// occur, so the calls go out in a fixed order.
fn permission_sets(candidates: &[Candidate]) -> Vec<bool> {
    let mut sets: Vec<bool> = Vec::with_capacity(2);
    for candidate in candidates {
        if !sets.contains(&candidate.write) {
            sets.push(candidate.write);
        }
    }
    sets
}

/// What the sandbox is granted over the file. `delete` and
/// `grant-permissions` are never asked for: an app that was handed one
/// file has no business removing it or passing it on.
fn permissions(write: bool) -> Vec<Value> {
    let mut list = vec![Value::Str("read".to_owned())];
    if write {
        list.push(Value::Str("write".to_owned()));
    }
    list
}

/// The word `--explain` prints for a permission set.
fn permission_text(write: bool) -> &'static str {
    match write {
        true => "write",
        false => "read",
    }
}

/// Open the file for the portal to `fstat`.
///
/// `O_PATH` is what Flatpak passes and all the portal needs: the
/// descriptor names the file without being readable or writable, so
/// bubbler never holds an open handle to the user's document. Symlinks
/// are followed — the desktop handed us the link and the user means the
/// file at the end of it — and the type is re-checked on the descriptor
/// so a path that changed since [`plan`] cannot pass as a file.
fn open_path(path: &Path) -> Result<OwnedFd, ForwardError> {
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
    Ok(fd)
}

/// The document ids out of an `AddFull` reply, checked to be one usable
/// name per file. The portal is another process on the bus, so an id
/// that is not a single path component is refused rather than joined
/// into a path.
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

/// Whether an id names one directory under the document view and
/// nothing else.
fn is_document_id(id: &str) -> bool {
    !id.is_empty() && id != "." && id != ".." && !id.contains('/') && !id.contains('\0')
}

/// A wire failure as a reason one file did not make it. A refusal keeps
/// the portal's own error name; everything else is the connection
/// failing, which is not the portal's word for anything.
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
    /// The same reason again, for the next file of a call that failed
    /// for all of them. [`io::Error`] is not `Clone`, so an open failure
    /// — which is never shared — keeps only its text here.
    fn again(&self) -> Self {
        match self {
            ForwardError::Open { path, source } => ForwardError::Open {
                path: path.clone(),
                source: io::Error::new(source.kind(), source.to_string()),
            },
            ForwardError::NotAFile(path) => ForwardError::NotAFile(path.clone()),
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
    use std::fs::FileType;
    use std::io::{IoSliceMut, Read, Write};
    use std::mem::MaybeUninit;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};

    use super::*;
    use crate::config::ShareMode;
    use crate::dbus_wire::{decode, encode};
    use crate::host::fake::{FakeHost, char_type, types};

    fn env() -> Env {
        Env {
            home: "/home/han".into(),
            data_home: "/home/han/.local/share".into(),
            config_home: "/home/han/.config".into(),
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
            seccomp_log: false,
            test_allow_path: None,
            profile_dir_override: None,
            proxy_override: None,
            pasta_override: None,
            wl_proxy_override: None,
        }
    }

    /// A config sharing `~/Documents` and `/srv/data`, so the plan has
    /// both kinds of source to compare against.
    fn cfg() -> InstanceConfig {
        InstanceConfig {
            services: vec![
                Service::HomeShare {
                    path: "Documents".into(),
                    mode: ShareMode::ReadOnly,
                },
                Service::PathShare {
                    path: "/srv/data".into(),
                    mode: ShareMode::ReadWrite,
                },
                Service::Portals,
            ],
            ..InstanceConfig::default()
        }
    }

    /// The host every plan case is decided against. `file_type` follows
    /// symlinks, so `link.pdf` is entered with the type of the file it
    /// points at and `canonicalize` says where it lands.
    fn tree() -> FakeHost {
        let (file, dir, socket) = types();
        FakeHost::default()
            .with("/home/han/a.pdf", file)
            .rw("/home/han/a.pdf")
            .with("/home/han/a b.pdf", file)
            .with("/home/han/theirs.pdf", file)
            .with("/home/han/pics", dir)
            .with("/home/han/s.sock", socket)
            .with("/home/han/link.pdf", file)
            .link("/home/han/link.pdf", "/home/han/a.pdf")
            .rw("/home/han/link.pdf")
            .with("/home/han/Documents/report.pdf", file)
            .with("/srv/data/x.csv", file)
            .with("/data/inst/home/note.txt", file)
            .with("/proc/self/exe", file)
            .with("/dev/null", char_type())
    }

    const INSTANCE_HOME: &str = "/data/inst/home";

    /// One planned argument as a line, so the table below reads as one.
    fn tag(planned: &Planned) -> String {
        match planned {
            Planned::Forward(c) => format!(
                "forward {} as {} ({})",
                c.host.display(),
                Path::new(&c.name).display(),
                permission_text(c.write)
            ),
            Planned::Skip(_, path, why) => format!("skip {} {why:?}", path.display()),
            Planned::Untouched => "untouched".to_owned(),
        }
    }

    fn planned(args: &[&str], host: &dyn Host) -> Vec<Planned> {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        plan(&env(), &cfg(), Path::new(INSTANCE_HOME), &args, host)
    }

    #[test]
    fn every_argument_is_classified_once() {
        let cases: &[(&str, &str)] = &[
            (
                "/home/han/a.pdf",
                "forward /home/han/a.pdf as a.pdf (write)",
            ),
            (
                "/home/han/theirs.pdf",
                "forward /home/han/theirs.pdf as theirs.pdf (read)",
            ),
            (
                "file:///home/han/a%20b.pdf",
                "forward /home/han/a b.pdf as a b.pdf (read)",
            ),
            (
                "file://localhost/home/han/a.pdf",
                "forward /home/han/a.pdf as a.pdf (write)",
            ),
            (
                "file:/home/han/a.pdf",
                "forward /home/han/a.pdf as a.pdf (write)",
            ),
            (
                "/home/han/link.pdf",
                "forward /home/han/link.pdf as link.pdf (write)",
            ),
            ("file://other/home/han/a.pdf", "untouched"),
            ("file://localhost", "untouched"),
            ("https://example.invalid/a.pdf", "untouched"),
            ("--flag", "untouched"),
            ("a.pdf", "untouched"),
            ("", "untouched"),
            ("./rel", "skip ./rel Relative"),
            ("../up/a.pdf", "skip ../up/a.pdf Relative"),
            ("file:rel/a.pdf", "skip rel/a.pdf Relative"),
            ("/home/han/pics", "skip /home/han/pics Directory"),
            ("/home/han/s.sock", "skip /home/han/s.sock NotAFile"),
            ("/home/han/gone.pdf", "skip /home/han/gone.pdf NotAFile"),
            ("/proc/self/exe", "skip /proc/self/exe Refused"),
            ("/dev/null", "skip /dev/null Refused"),
            ("/sys/power/state", "skip /sys/power/state Refused"),
            (
                "/home/han/Documents/report.pdf",
                "skip /home/han/Documents/report.pdf AlreadyVisible",
            ),
            ("/srv/data/x.csv", "skip /srv/data/x.csv AlreadyVisible"),
            (
                "/data/inst/home/note.txt",
                "skip /data/inst/home/note.txt AlreadyVisible",
            ),
        ];
        let args: Vec<&str> = cases.iter().map(|(arg, _)| *arg).collect();
        let out = planned(&args, &tree());
        let got: Vec<String> = out.iter().map(tag).collect();
        let want: Vec<&str> = cases.iter().map(|(_, want)| *want).collect();
        assert_eq!(got, want);
        for (index, entry) in out.iter().enumerate() {
            match entry {
                Planned::Forward(c) => assert_eq!(c.arg_index, index),
                Planned::Skip(at, ..) => assert_eq!(*at, index),
                Planned::Untouched => {}
            }
        }
    }

    #[test]
    fn a_link_that_lands_in_proc_is_refused_like_the_path_itself() {
        let (file, ..) = types();
        let host = FakeHost::default()
            .with("/home/han/kernel", file)
            .link("/home/han/kernel", "/proc/self/exe");
        assert_eq!(
            planned(&["/home/han/kernel"], &host),
            vec![Planned::Skip(
                0,
                PathBuf::from("/home/han/kernel"),
                Skip::Refused
            )]
        );
    }

    #[test]
    fn a_share_that_is_not_granted_does_not_hide_a_file() {
        let (file, ..) = types();
        let host = FakeHost::default().with("/home/han/Documents/report.pdf", file);
        let args = vec![OsString::from("/home/han/Documents/report.pdf")];
        let bare = InstanceConfig::default();
        let out = plan(&env(), &bare, Path::new(INSTANCE_HOME), &args, &host);
        assert_eq!(
            tag(&out[0]),
            "forward /home/han/Documents/report.pdf as report.pdf (read)"
        );
    }

    #[test]
    fn a_path_that_is_not_utf8_survives_decoding() {
        let arg = OsString::from_vec(b"file:///home/han/%ff.pdf".to_vec());
        let file: FileType = types().0;
        let name = OsString::from_vec(b"\xff.pdf".to_vec());
        let host = FakeHost::default().with("/home/han/\u{fffd}", file);
        let out = plan(
            &env(),
            &cfg(),
            Path::new(INSTANCE_HOME),
            &[arg],
            &host as &dyn Host,
        );
        // The file is not in the fake tree under that name, but the
        // decoded bytes are what was looked up.
        assert_eq!(
            out,
            vec![Planned::Skip(
                0,
                PathBuf::from(OsString::from_vec(b"/home/han/\xff.pdf".to_vec())),
                Skip::NotAFile
            )]
        );
        assert_eq!(
            host_path(OsStr::new("file:///home/han/%ff.pdf"))
                .and_then(|p| p.file_name().map(OsStr::to_os_string)),
            Some(name)
        );
    }

    #[test]
    fn a_root_that_is_no_root_hides_nothing() {
        let args = vec![OsString::from("/home/han/a.pdf")];
        let out = plan(&env(), &cfg(), Path::new(""), &args, &tree());
        assert_eq!(tag(&out[0]), "forward /home/han/a.pdf as a.pdf (write)");
    }

    #[test]
    fn a_nul_in_a_uri_names_no_file() {
        assert_eq!(host_path(OsStr::new("file:///home/han/a%00b.pdf")), None);
    }

    #[test]
    fn a_percent_that_starts_no_escape_stays_a_percent() {
        assert_eq!(percent_decode(b"100%.pdf"), b"100%.pdf");
        assert_eq!(percent_decode(b"a%zz"), b"a%zz");
        assert_eq!(percent_decode(b"a%2"), b"a%2");
        assert_eq!(percent_decode(b"%2f%2F"), b"//");
    }

    #[test]
    fn the_warning_lines_are_the_ones_the_cli_prints() {
        let out = planned(
            &[
                "/home/han/pics",
                "/home/han/s.sock",
                "/proc/self/exe",
                "/home/han/a.pdf",
                "/srv/data/x.csv",
                "./rel",
                "--flag",
            ],
            &tree(),
        );
        assert_eq!(
            warning_lines(&out),
            vec![
                "/home/han/pics is a directory; grant path-share or home-share to expose it",
                "/home/han/s.sock is not a regular file, not forwarded",
                "/proc/self/exe is under /proc, /sys or /dev, not forwarded",
            ]
        );
    }

    #[test]
    fn the_explain_lines_name_the_document_path_with_a_literal_id() {
        let out = planned(
            &["/home/han/a.pdf", "/home/han/theirs.pdf", "--flag"],
            &tree(),
        );
        assert_eq!(
            explain_lines(&out),
            vec![
                "forward: /home/han/a.pdf → $XDG_RUNTIME_DIR/doc/<id>/a.pdf (write)",
                "forward: /home/han/theirs.pdf → $XDG_RUNTIME_DIR/doc/<id>/theirs.pdf (read)",
            ]
        );
    }

    #[test]
    fn rewrite_replaces_only_what_was_registered() {
        let args: Vec<OsString> = ["--flag", "/home/han/a.pdf", "file:///home/han/b.pdf"]
            .iter()
            .map(OsString::from)
            .collect();
        let forwards = vec![
            Forward {
                arg_index: 1,
                host: "/home/han/a.pdf".into(),
                inside: "/run/user/1000/doc/abc/a.pdf".into(),
                write: true,
            },
            // An index past the end is left alone rather than pushed on.
            Forward {
                arg_index: 9,
                host: "/home/han/z.pdf".into(),
                inside: "/run/user/1000/doc/zzz/z.pdf".into(),
                write: false,
            },
        ];
        assert_eq!(
            rewrite(&args, &forwards),
            vec![
                OsString::from("--flag"),
                OsString::from("/run/user/1000/doc/abc/a.pdf"),
                OsString::from("file:///home/han/b.pdf"),
            ]
        );
        assert_eq!(rewrite(&args, &[]), args);
    }

    const FIELD_PATH: u8 = 1;
    const FIELD_INTERFACE: u8 = 2;
    const FIELD_MEMBER: u8 = 3;
    const FIELD_ERROR_NAME: u8 = 4;
    const FIELD_REPLY_SERIAL: u8 = 5;
    const FIELD_DESTINATION: u8 = 6;
    const FIELD_SENDER: u8 = 7;
    const FIELD_SIGNATURE: u8 = 8;
    const MSG_METHOD_RETURN: u8 = 2;
    const MSG_ERROR: u8 = 3;

    /// The unique name the fake bus says the portal holds. Every reply
    /// carries the `SENDER` a real bus stamps on it.
    const PORTAL_OWNER: &str = ":1.77";
    const BUS_OWNER: &str = "org.freedesktop.DBus";

    /// One method call as the fake bus saw it.
    struct Call {
        fields: Vec<(u8, Value)>,
        signature: String,
        body: Vec<Value>,
        serial: u32,
        fds: Vec<OwnedFd>,
    }

    impl Call {
        /// The text of a header field, e.g. the member name.
        fn text(&self, code: u8) -> String {
            match self.fields.iter().find(|(c, _)| *c == code) {
                Some((_, Value::Str(text) | Value::ObjectPath(text))) => text.clone(),
                other => panic!("header field {code} is {other:?}"),
            }
        }
    }

    /// A bus on a socket under `dir` that runs `script` on the one
    /// connection it accepts.
    fn fake_bus<F>(dir: &Path, script: F) -> (PathBuf, JoinHandle<()>)
    where
        F: FnOnce(UnixStream) + Send + 'static,
    {
        let path = dir.join("bus");
        let listener = UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            // So a client that never sends what the script waits for
            // fails the test instead of hanging it.
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .unwrap();
            script(stream);
        });
        (path, handle)
    }

    /// One `\r\n` line from the client, read a byte at a time so none of
    /// the message stream that follows `BEGIN` is swallowed.
    fn server_line(stream: &UnixStream) -> String {
        let mut out = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            (&*stream).read_exact(&mut byte).unwrap();
            out.push(byte[0]);
            if out.ends_with(b"\r\n") {
                out.truncate(out.len() - 2);
                return String::from_utf8(out).unwrap();
            }
        }
    }

    /// The `EXTERNAL` handshake and the `Hello` every connection opens
    /// with, from the bus's side.
    fn server_start(stream: &UnixStream) {
        assert!(server_line(stream).starts_with("\0AUTH EXTERNAL "));
        (&*stream).write_all(b"OK 1234deadbeef\r\n").unwrap();
        assert_eq!(server_line(stream), "NEGOTIATE_UNIX_FD");
        (&*stream).write_all(b"AGREE_UNIX_FD\r\n").unwrap();
        assert_eq!(server_line(stream), "BEGIN");
        let hello = server_call(stream);
        assert_eq!(hello.text(FIELD_MEMBER), "Hello");
        server_send(
            stream,
            MSG_METHOD_RETURN,
            BUS_OWNER,
            &[(FIELD_REPLY_SERIAL, Value::Uint32(hello.serial))],
            "s",
            &[Value::Str(":1.5".to_owned())],
        );
    }

    /// The next `AddFull` the client makes. A lookup of who owns the
    /// portal name is answered on the way, so this reads the same
    /// whether or not the client checks who it is talking to.
    fn server_addfull(stream: &UnixStream) -> Call {
        loop {
            let call = server_call(stream);
            match call.text(FIELD_MEMBER).as_str() {
                "AddFull" => return call,
                "GetNameOwner" => server_send(
                    stream,
                    MSG_METHOD_RETURN,
                    BUS_OWNER,
                    &[(FIELD_REPLY_SERIAL, Value::Uint32(call.serial))],
                    "s",
                    &[Value::Str(PORTAL_OWNER.to_owned())],
                ),
                other => panic!("the client called {other}"),
            }
        }
    }

    /// One whole method call from the client, with any descriptors it
    /// carried. The header is `yyyyuua(yv)` and the body starts at the
    /// next 8-byte boundary after it.
    fn server_call(stream: &UnixStream) -> Call {
        let mut buf: Vec<u8> = Vec::new();
        let mut fds = Vec::new();
        loop {
            if buf.len() >= 16 {
                let body_len = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
                let fields_len = u32::from_le_bytes(buf[12..16].try_into().unwrap()) as usize;
                let body_at = (16 + fields_len).next_multiple_of(8);
                if buf.len() >= body_at + body_len {
                    return parse_call(&buf[..body_at + body_len], fds);
                }
            }
            let mut chunk = [0u8; 4096];
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
            let mut ancillary = RecvAncillaryBuffer::new(&mut space);
            let got = recvmsg(
                stream.as_fd(),
                &mut [IoSliceMut::new(&mut chunk)],
                &mut ancillary,
                RecvFlags::CMSG_CLOEXEC,
            )
            .unwrap();
            for message in ancillary.drain() {
                if let RecvAncillaryMessage::ScmRights(received) = message {
                    fds.extend(received);
                }
            }
            assert!(got.bytes > 0, "the client hung up mid-message");
            buf.extend_from_slice(&chunk[..got.bytes]);
        }
    }

    fn parse_call(bytes: &[u8], fds: Vec<OwnedFd>) -> Call {
        let fields_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
        let header = decode("yyyyuua(yv)", &bytes[..16 + fields_len]).unwrap();
        let (Value::Uint32(serial), Value::Array(raw)) = (&header[5], &header[6]) else {
            panic!("a header that is not a header: {header:?}");
        };
        let fields: Vec<(u8, Value)> = raw
            .iter()
            .map(|field| match field {
                Value::Struct(pair) => match pair.as_slice() {
                    [Value::Byte(code), Value::Variant(value)] => (*code, (**value).clone()),
                    other => panic!("a header field that is not one: {other:?}"),
                },
                other => panic!("a header field that is not one: {other:?}"),
            })
            .collect();
        let signature = match fields.iter().find(|(code, _)| *code == FIELD_SIGNATURE) {
            Some((_, Value::Signature(sig))) => sig.clone(),
            _ => String::new(),
        };
        let body_at = (16 + fields_len).next_multiple_of(8);
        let body = decode(&signature, &bytes[body_at..]).unwrap();
        Call {
            fields,
            signature,
            body,
            serial: *serial,
            fds,
        }
    }

    /// Send one message from the bus's side.
    fn server_send(
        stream: &UnixStream,
        kind: u8,
        sender: &str,
        fields: &[(u8, Value)],
        sig: &str,
        body: &[Value],
    ) {
        let mut fields = fields.to_vec();
        fields.push((FIELD_SENDER, Value::Str(sender.to_owned())));
        if !sig.is_empty() {
            fields.push((FIELD_SIGNATURE, Value::Signature(sig.to_owned())));
        }
        let fields: Vec<Value> = fields
            .into_iter()
            .map(|(code, value)| {
                Value::Struct(vec![Value::Byte(code), Value::Variant(Box::new(value))])
            })
            .collect();
        let body = encode(sig, body).unwrap();
        let mut message = encode(
            "yyyyuua(yv)",
            &[
                Value::Byte(b'l'),
                Value::Byte(kind),
                Value::Byte(0),
                Value::Byte(1),
                Value::Uint32(body.len() as u32),
                Value::Uint32(7),
                Value::Array(fields),
            ],
        )
        .unwrap();
        while !message.len().is_multiple_of(8) {
            message.push(0);
        }
        message.extend_from_slice(&body);
        (&*stream).write_all(&message).unwrap();
    }

    /// The `(as, a{sv})` an `AddFull` answers with.
    fn server_ids(stream: &UnixStream, call: &Call, ids: &[&str]) {
        server_send(
            stream,
            MSG_METHOD_RETURN,
            PORTAL_OWNER,
            &[(FIELD_REPLY_SERIAL, Value::Uint32(call.serial))],
            "asa{sv}",
            &[
                Value::Array(ids.iter().map(|id| Value::Str((*id).to_owned())).collect()),
                Value::Dict(Vec::new()),
            ],
        );
    }

    fn candidate(arg_index: usize, path: &Path, write: bool) -> Candidate {
        Candidate {
            arg_index,
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
            assert_eq!(call.text(FIELD_DESTINATION), PORTAL_NAME);
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
            server_send(
                &stream,
                MSG_ERROR,
                PORTAL_OWNER,
                &[
                    (FIELD_REPLY_SERIAL, Value::Uint32(call.serial)),
                    (
                        FIELD_ERROR_NAME,
                        Value::Str("org.freedesktop.portal.Error.NotAllowed".to_owned()),
                    ),
                ],
                "s",
                &[Value::Str("no".to_owned())],
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
            server_send(
                &stream,
                MSG_METHOD_RETURN,
                PORTAL_OWNER,
                &[(FIELD_REPLY_SERIAL, Value::Uint32(call.serial))],
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
        let (bus, server) = fake_bus(tmp.path(), |stream| server_start(&stream));
        let mut session = Session::connect(&bus).unwrap();
        assert!(register(&env(), "pdf", &[], &mut session).is_empty());
        drop(session);
        server.join().unwrap();
    }
}
