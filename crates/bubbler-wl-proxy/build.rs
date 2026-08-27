//! Generates `$OUT_DIR/tables.rs`: one `Interface` entry per interface found
//! in the protocol XML that the `wayrs-protocols` and `wayrs-client` packages
//! ship in their sources. The proxy cannot forward a message it cannot
//! measure, so these tables — not a hand-maintained list — decide how many
//! fds a message owns and where its `new_id` sits.
//!
//! The packages are located through `cargo metadata`, so the XML always comes
//! from the exact versions Cargo.lock pins.
//!
//! XML this parser cannot read, and two stable files that describe one
//! interface differently, fail the build on purpose: the remedy is to pin the
//! `wayrs-*` versions, not to let the proxy guess which layout a client meant.
//!
//! `BUBBLER_WL_PROXY_TABLES=verbose` prints which copy of a clashing
//! interface was kept and which file was dropped whole. Those notes are for
//! whoever bumps the `wayrs-*` versions; every other build is quiet, because
//! a `cargo:warning` on every build of every dependent crate is a warning
//! nobody reads.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
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
#[derive(PartialEq, Eq)]
struct Msg {
    name: String,
    since: u32,
    is_destructor: bool,
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
    println!("cargo:rerun-if-env-changed=BUBBLER_WL_PROXY_TABLES");
    // What the tables did with a clashing interface, asked for by whoever
    // is changing them. Nothing here decides what is generated.
    let verbose = env::var_os("BUBBLER_WL_PROXY_TABLES").is_some_and(|v| v == "verbose");
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
        let source = file
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut conflict = None;
        let mut kept: Vec<(String, String)> = Vec::new();
        // The file is folded into its own map first: one XML file may name an
        // interface twice, and that copy passes the same test as any other.
        let mut own: BTreeMap<String, Iface> = BTreeMap::new();
        for (name, iface) in parse_file(file, &source) {
            match own.get(&name) {
                None => {
                    own.insert(name, iface);
                }
                Some(old) => match check(&name, old, &iface) {
                    Err(why) => {
                        conflict.get_or_insert(why);
                    }
                    Ok(note) => {
                        let takes = iface.version > old.version;
                        kept.extend(note);
                        if takes {
                            own.insert(name, iface);
                        }
                    }
                },
            }
        }
        for (name, iface) in &own {
            if let Some(old) = ifaces.get(name) {
                match check(name, old, iface) {
                    Err(why) => {
                        conflict.get_or_insert(why);
                    }
                    Ok(note) => kept.extend(note),
                }
            }
        }
        // Two files that describe one interface differently cannot both be
        // trusted: the proxy would decode an object with one layout while the
        // compositor used the other. The whole unstable file goes, its own
        // globals included, so nothing from it can be advertised or bound.
        if let Some(why) = conflict {
            if !is_unstable(file) {
                die(format!("{source}: {why}"));
            }
            if verbose {
                println!("cargo:warning={source} dropped whole: {why}");
            }
            continue;
        }
        if verbose && !kept.is_empty() {
            let names: Vec<&str> = kept.iter().map(|(name, _)| name.as_str()).collect();
            let from: BTreeSet<&str> = kept.iter().map(|(_, from)| from.as_str()).collect();
            println!(
                "cargo:warning=kept {} from {}, dropped the copy in {source}",
                names.join(", "),
                from.into_iter().collect::<Vec<_>>().join(" and ")
            );
        }
        for (name, iface) in own {
            if ifaces
                .get(&name)
                .is_none_or(|old| iface.version > old.version)
            {
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
    let hits: Vec<usize> = meta.match_indices(&anchor).map(|(at, _)| at).collect();
    let [from] = hits[..] else {
        if hits.is_empty() {
            die(format!(
                "{name} is not in `cargo metadata`: it must stay a dependency of the workspace \
                 (bubbler-core) or become a build-dependency of bubbler-wl-proxy"
            ));
        }
        die(format!(
            "`cargo metadata` reports {} copies of {name}; the tables must come from one version",
            hits.len()
        ));
    };
    let version = json_string(&meta[from + anchor.len()..]);
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
    // The package's own manifest is the authority; the directory name is the
    // fallback, because a vendored crate or a path dependency sits in a
    // directory named after the package alone, or after nothing in particular.
    let named = manifest_field(&manifest, "name").as_deref() == Some(name);
    let versioned = manifest_field(&manifest, "version").as_deref() == Some(version.as_str());
    let plausible = base == format!("{name}-{version}") || base == name;
    if !((named && versioned) || plausible) {
        die(format!(
            "{name}: `cargo metadata` gave {}, whose manifest is not {name} {version}; the \
             metadata field order changed and the scan in build.rs must be replaced",
            manifest.display()
        ));
    }
    dir
}

/// The `[package]` value of `key` in a Cargo.toml, read line by line — enough
/// for `name` and `version`, and no TOML parser in the build graph. `None`
/// when the file cannot be read or inherits the value from a workspace.
fn manifest_field(manifest: &Path, key: &str) -> Option<String> {
    let text = fs::read_to_string(manifest).ok()?;
    let mut in_package = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(rest) = line.strip_prefix(key)
            && let Some(rest) = rest.trim_start().strip_prefix('=')
            && let Some(rest) = rest.trim_start().strip_prefix('"')
            && let Some(end) = rest.find('"')
        {
            return Some(rest[..end].to_owned());
        }
    }
    None
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

/// Every interface of one XML file, in the order the file declares them.
fn parse_file(file: &Path, source: &str) -> Vec<(String, Iface)> {
    let text = fs::read_to_string(file)
        .unwrap_or_else(|e| die(format!("cannot read {}: {e}", file.display())));
    let proto = parse_protocol(&text)
        .unwrap_or_else(|e| die(format!("cannot parse {}: {e}", file.display())));
    proto
        .interfaces
        .iter()
        .map(|parsed| {
            let iface = Iface {
                version: parsed.version,
                requests: parsed.requests.iter().map(message).collect(),
                events: parsed.events.iter().map(message).collect(),
                source: source.to_owned(),
            };
            (plain(&parsed.name), iface)
        })
        .collect()
}

/// Whether `kept` can stand in for `dropped` on the wire: no fewer messages,
/// and the very same message — name, `since`, arguments and the interface it
/// creates — at every opcode `dropped` uses. Anything else is two protocols
/// wearing one name, and a divergence in what a message creates would put the
/// wrong interface on a new object id.
fn supersedes(kept: &Iface, dropped: &Iface) -> bool {
    fn prefix(kept: &[Msg], dropped: &[Msg]) -> bool {
        kept.len() >= dropped.len()
            && kept
                .iter()
                .zip(dropped)
                .all(|(kept, dropped)| kept == dropped)
    }
    kept.version >= dropped.version
        && prefix(&kept.requests, &dropped.requests)
        && prefix(&kept.events, &dropped.events)
}

/// Compare two copies of the interface `name`.
///
/// `Err` is a conflict: neither copy may stand for the other. `Ok` carries the
/// name and the file of the copy that is kept, and only when the two differ —
/// an identical copy is not worth a word.
fn check(name: &str, old: &Iface, new: &Iface) -> Result<Option<(String, String)>, String> {
    let (kept, dropped) = if new.version > old.version {
        (new, old)
    } else {
        (old, new)
    };
    if !supersedes(kept, dropped) {
        return Err(format!(
            "{name} v{} from {} is not the same protocol as v{} from {}",
            dropped.version, dropped.source, kept.version, kept.source
        ));
    }
    Ok((!identical(old, new)).then(|| (name.to_owned(), kept.source.clone())))
}

/// Whether two copies of an interface would generate the same table, in which
/// case the duplicate is not worth a word.
fn identical(one: &Iface, other: &Iface) -> bool {
    one.version == other.version && one.requests == other.requests && one.events == other.events
}

/// Whether the file describes an unstable protocol. Its interfaces are the
/// ones that give way when a stable file describes the same name differently.
fn is_unstable(file: &Path) -> bool {
    file.components().any(|part| part.as_os_str() == "unstable")
        || file
            .file_name()
            .is_some_and(|name| name.to_string_lossy().contains("unstable"))
}

/// Turn one parsed message into its table row.
fn message(msg: &wayrs_proto_parser::Message<'_>) -> Msg {
    let mut args = Vec::new();
    let mut new_id_interface = None;
    let mut new_ids = 0;
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
                new_ids += 1;
                new_id_interface = Some(plain(iface));
                args.push("NewId");
            }
            // Only `wl_registry.bind`: libwayland puts the interface name and
            // the version on the wire ahead of the id, and the tables spell
            // that out so the decoder needs no special case.
            ArgType::NewId { iface: None } => {
                new_ids += 1;
                args.push("String");
                args.push("Uint");
                args.push("NewId");
            }
        }
    }
    // The table has one `new_id_interface` per message, and the object map
    // registers one id per message; a second one would go unrecorded.
    if new_ids > 1 {
        die(format!(
            "{} creates {new_ids} objects; the table has room for one",
            msg.name
        ));
    }
    Msg {
        name: plain(&msg.name),
        since: msg.since,
        // The XML's `type="destructor"`: the request that ends the object,
        // which is the only thing the proxy has to tell apart from the rest.
        is_destructor: msg.kind.as_deref() == Some("destructor"),
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
        "Message {{ name: \"{}\", since: {}, is_destructor: {}, args: &[",
        msg.name, msg.since, msg.is_destructor
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
