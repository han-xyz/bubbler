//! Generates `$OUT_DIR/tables.rs`: one `Interface` entry per interface found
//! in the protocol XML that the `wayrs-protocols` and `wayrs-client` packages
//! ship in their sources. The proxy cannot forward a message it cannot
//! measure, so these tables — not a hand-maintained list — decide how many
//! fds a message owns and where its `new_id` sits.
//!
//! The packages are located through `cargo metadata`, so the XML always comes
//! from the exact versions Cargo.lock pins.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use wayrs_proto_parser::{ArgType, parse_protocol};

/// A build failure the reader can act on: every one of these means the
/// generated tables would be wrong, and wrong tables are a hole in the proxy.
fn die(msg: impl AsRef<str>) -> ! {
    panic!("bubbler-wl-proxy: {}", msg.as_ref());
}

/// One message of one interface, already reduced to what the table holds.
struct Msg {
    name: String,
    since: u32,
    args: Vec<&'static str>,
    new_id_interface: Option<String>,
}

/// One interface, with the file it came from so a duplicate can name both.
struct Iface {
    version: u32,
    requests: Vec<Msg>,
    events: Vec<Msg>,
    source: String,
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let manifest = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").unwrap_or_else(|| die("CARGO_MANIFEST_DIR is unset")),
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_else(|| die("OUT_DIR is unset")));

    let meta = cargo_metadata(&manifest);
    let protocols = package_dir(&meta, "wayrs-protocols");
    let client = package_dir(&meta, "wayrs-client");

    // A lock file change is what a `wayrs-*` bump looks like from here.
    if let Some(lock) = manifest
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("Cargo.lock"))
        && lock.is_file()
    {
        println!("cargo:rerun-if-changed={}", lock.display());
    }

    // Core first: on a tie it wins over any copy of the same interface.
    let core = client.join("wayland.xml");
    if !core.is_file() {
        die(format!(
            "{} is missing; the wayrs-client layout changed",
            core.display()
        ));
    }
    println!("cargo:rerun-if-changed={}", core.display());
    let mut files = vec![core];
    for dir in ["wayland-protocols", "wlr-protocols"] {
        let root = protocols.join(dir);
        if !root.is_dir() {
            die(format!(
                "{} is not a directory; the wayrs-protocols layout changed",
                root.display()
            ));
        }
        println!("cargo:rerun-if-changed={}", root.display());
        collect_xml(&root, &mut files);
    }

    let mut ifaces: BTreeMap<String, Iface> = BTreeMap::new();
    for file in &files {
        let text = fs::read_to_string(file)
            .unwrap_or_else(|e| die(format!("cannot read {}: {e}", file.display())));
        let proto = parse_protocol(&text)
            .unwrap_or_else(|e| die(format!("cannot parse {}: {e}", file.display())));
        let source = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        for parsed in proto.interfaces {
            let name = plain(&parsed.name);
            let iface = Iface {
                version: parsed.version,
                requests: parsed.requests.iter().map(message).collect(),
                events: parsed.events.iter().map(message).collect(),
                source: source.clone(),
            };
            let takes = match ifaces.get(&name) {
                None => true,
                Some(old) => {
                    let takes = iface.version > old.version;
                    let (kept, dropped) = if takes {
                        ((iface.version, &iface.source), (old.version, &old.source))
                    } else {
                        ((old.version, &old.source), (iface.version, &iface.source))
                    };
                    println!(
                        "cargo:warning=duplicate interface {name}: kept v{} from {}, ignored v{} from {}",
                        kept.0, kept.1, dropped.0, dropped.1
                    );
                    takes
                }
            };
            if takes {
                ifaces.insert(name, iface);
            }
        }
    }

    let display = ifaces
        .keys()
        .position(|name| name == "wl_display")
        .unwrap_or_else(|| die("wl_display is missing from the protocol XML"));
    let path = out.join("tables.rs");
    fs::write(&path, render(&ifaces, display))
        .unwrap_or_else(|e| die(format!("cannot write {}: {e}", path.display())));
}

/// Run `cargo metadata` for this workspace and return its JSON.
fn cargo_metadata(manifest: &Path) -> String {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(&cargo)
        .args(["metadata", "--format-version", "1"])
        .current_dir(manifest)
        .output()
        .unwrap_or_else(|e| die(format!("cannot run cargo metadata: {e}")));
    if !out.status.success() {
        die(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout)
        .unwrap_or_else(|e| die(format!("cargo metadata is not UTF-8: {e}")))
}

/// The source directory of package `name` as `cargo metadata` reports it.
///
/// The JSON is scanned rather than deserialised (a JSON parser in the build
/// graph would buy two paths); every assumption the scan makes is checked
/// afterwards, so a changed metadata layout fails the build instead of
/// silently pointing the tables at the wrong sources.
fn package_dir(meta: &str, name: &str) -> PathBuf {
    let anchor = format!("{{\"name\":\"{name}\",\"version\":\"");
    let from = meta.find(&anchor).unwrap_or_else(|| {
        die(format!(
            "{name} is not in `cargo metadata`: it must stay a dependency of the workspace \
             (bubbler-core) or become a build-dependency of bubbler-wl-proxy"
        ))
    });
    let key = "\"manifest_path\":\"";
    let rest = &meta[from..];
    let at = rest
        .find(key)
        .unwrap_or_else(|| die(format!("{name} has no manifest_path in `cargo metadata`")));
    let manifest = PathBuf::from(json_string(&rest[at + key.len()..]));
    let dir = manifest
        .parent()
        .unwrap_or_else(|| die(format!("{name}: manifest_path has no directory")))
        .to_path_buf();
    let base = dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !base.starts_with(name) {
        die(format!(
            "{name}: `cargo metadata` gave {}, which is not that package's directory; \
             the metadata field order changed and the scan in build.rs must be replaced",
            dir.display()
        ));
    }
    dir
}

/// Decode the JSON string that starts at `s`, just past its opening quote.
fn json_string(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    loop {
        match chars.next() {
            Some('"') => return out,
            Some('\\') => match chars.next() {
                Some(c @ ('"' | '\\' | '/')) => out.push(c),
                other => die(format!(
                    "unsupported escape \\{} in a `cargo metadata` path",
                    other.unwrap_or(' ')
                )),
            },
            Some(c) => out.push(c),
            None => die("`cargo metadata` ended inside a string"),
        }
    }
}

/// Every `*.xml` under `dir`, sorted, so the generated table is reproducible.
fn collect_xml(dir: &Path, out: &mut Vec<PathBuf>) {
    let read =
        fs::read_dir(dir).unwrap_or_else(|e| die(format!("cannot read {}: {e}", dir.display())));
    let mut entries: Vec<PathBuf> = read
        .map(|entry| {
            entry
                .unwrap_or_else(|e| die(format!("cannot read {}: {e}", dir.display())))
                .path()
        })
        .collect();
    entries.sort();
    for entry in entries {
        if entry.is_dir() {
            collect_xml(&entry, out);
        } else if entry.extension().is_some_and(|ext| ext == "xml") {
            out.push(entry);
        }
    }
}

/// Turn one parsed message into its table row.
fn message(msg: &wayrs_proto_parser::Message<'_>) -> Msg {
    let mut args = Vec::new();
    let mut new_id_interface = None;
    for arg in &msg.args {
        match &arg.arg_type {
            ArgType::Int => args.push("Int"),
            // The XML says whether an enum argument is int or uint; both are
            // four bytes and the proxy re-encodes what it read, so the tables
            // keep one kind for them.
            ArgType::Uint | ArgType::Enum(_) => args.push("Uint"),
            ArgType::Fixed => args.push("Fixed"),
            ArgType::String { .. } => args.push("String"),
            ArgType::Object { .. } => args.push("Object"),
            ArgType::Array => args.push("Array"),
            ArgType::Fd => args.push("Fd"),
            ArgType::NewId { iface: Some(iface) } => {
                if new_id_interface.is_some() {
                    die(format!(
                        "{} creates more than one object; the table has room for one",
                        msg.name
                    ));
                }
                new_id_interface = Some(plain(iface));
                args.push("NewId");
            }
            // Only `wl_registry.bind`: libwayland puts the interface name and
            // the version on the wire ahead of the id, and the tables spell
            // that out so the decoder needs no special case.
            ArgType::NewId { iface: None } => {
                args.push("String");
                args.push("Uint");
                args.push("NewId");
            }
        }
    }
    Msg {
        name: plain(&msg.name),
        since: msg.since,
        args,
        new_id_interface,
    }
}

/// Protocol names reach the generated source verbatim, so refuse anything
/// that is not a bare identifier rather than quoting it.
fn plain(name: &str) -> String {
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        die(format!("{name:?} is not a plain protocol name"));
    }
    name.to_owned()
}

/// Render the whole table as Rust source.
fn render(ifaces: &BTreeMap<String, Iface>, display: usize) -> String {
    let mut out = String::from(
        "// @generated by build.rs from the protocol XML of wayrs-protocols and\n\
         // wayrs-client. Do not edit; `cargo build` rewrites it.\n\n\
         /// Every interface the proxy can parse, sorted by name so a lookup is a\n\
         /// binary search and the index of an entry is stable for one build.\n\
         pub static INTERFACES: &[Interface] = &[\n",
    );
    for (name, iface) in ifaces {
        out.push_str(&format!(
            "    Interface {{ name: \"{name}\", version: {}, requests: &[",
            iface.version
        ));
        for msg in &iface.requests {
            render_message(&mut out, msg);
        }
        out.push_str("], events: &[");
        for msg in &iface.events {
            render_message(&mut out, msg);
        }
        out.push_str("] },\n");
    }
    out.push_str("];\n\n");
    out.push_str(&format!(
        "/// Index of `wl_display` in [`INTERFACES`]. Object id 1 is always that\n\
         /// interface, on every connection, before a single message is exchanged.\n\
         pub const WL_DISPLAY_INDEX: usize = {display};\n"
    ));
    out
}

/// Render one `Message` literal into `out`.
fn render_message(out: &mut String, msg: &Msg) {
    out.push_str(&format!(
        "Message {{ name: \"{}\", since: {}, args: &[",
        msg.name, msg.since
    ));
    for (i, arg) in msg.args.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str("ArgKind::");
        out.push_str(arg);
    }
    match &msg.new_id_interface {
        Some(iface) => out.push_str(&format!("], new_id_interface: Some(\"{iface}\") }}, ")),
        None => out.push_str("], new_id_interface: None }, "),
    }
}
