//! Dependencies inside bubbler-core point one way: run uses plan, plan
//! uses model, never back. Every `crate::` path in `src/` is an edge
//! between two modules; an edge that points up (model to plan or run,
//! plan to run) has to be listed in `DEBT` (production code) or
//! `TEST_DEBT` (code inside `#[cfg(test)]` items). Both lists only shrink:
//! an edge in neither fails, and so does an entry whose edge is gone.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::ops::Range;
use std::path::Path;

/// `(from, to, first occurrence)`; an entry matches on `from` and `to`.
type Entry = (&'static str, &'static str, &'static str);

const DEBT: &[Entry] = &[
    ("dbus", "dbus_wire", "plan/dbus.rs:11"),
    ("dbus", "launcher", "plan/dbus.rs:15"),
    ("error", "wayland", "model/error.rs:368"),
    ("explain", "cgroup", "plan/explain.rs:13"),
    ("explain", "version", "plan/explain.rs:108"),
    ("lint", "audio_policy", "plan/lint.rs:17"),
    ("lint", "desktop", "plan/lint.rs:19"),
];

const TEST_DEBT: &[Entry] = &[
    ("bwrap", "launcher", "plan/bwrap.rs:1167"),
    ("config", "network", "model/config/mod.rs:4296"),
    ("dbus", "dbus_wire", "plan/dbus.rs:829"),
    ("explain", "audio_policy", "plan/explain.rs:1252"),
    ("explain", "version", "plan/explain.rs:850"),
    ("profile", "audio_policy", "model/profile.rs:1625"),
    ("profile", "bwrap", "model/profile.rs:3174"),
    ("profile", "explain", "model/profile.rs:3194"),
    ("profile", "host", "model/profile.rs:1186"),
    ("profile", "init_bin", "model/profile.rs:3172"),
    ("profile", "launcher", "model/profile.rs:3180"),
    ("profile", "lint", "model/profile.rs:1187"),
    ("profile", "network", "model/profile.rs:2040"),
    ("profile", "service", "model/profile.rs:3168"),
    ("profile", "version", "model/profile.rs:3209"),
    ("service", "launcher", "plan/service.rs:1461"),
];

const LAYERS: [&str; 3] = ["model", "plan", "run"];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Edge {
    from: String,
    to: String,
    test: bool,
    at: String,
}

#[test]
fn upward_edges_are_exactly_the_recorded_debt() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    source_files(&src, &src, &mut files);
    files.sort();
    let modules = module_layers(files.iter().map(|(rel, _)| rel.as_str()));
    let mut edges = Vec::new();
    let mut problems = Vec::new();
    for (rel, text) in &files {
        if is_exempt(rel) {
            problems.extend(root_file_problems(rel, text));
            continue;
        }
        match edges_in(rel, text, &modules) {
            Ok(found) => edges.extend(found),
            Err(errors) => problems.extend(errors),
        }
    }
    problems.extend(debt_problems(&edges, &modules, DEBT, TEST_DEBT));
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

fn source_files(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            source_files(root, &path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let rel = path.strip_prefix(root).unwrap().to_string_lossy();
            out.push((rel.replace('\\', "/"), fs::read_to_string(&path).unwrap()));
        }
    }
}

fn is_exempt(rel: &str) -> bool {
    rel == "lib.rs" || LAYERS.iter().any(|l| rel == format!("{l}/mod.rs"))
}

/// lib.rs re-exports whatever it likes; a layer's mod.rs only declares
/// the layer's modules, so a `crate::` path there would be an edge the
/// scan does not see.
fn root_file_problems(rel: &str, text: &str) -> Vec<String> {
    if rel == "lib.rs" {
        return Vec::new();
    }
    let code = strip(text);
    crate_refs(&code)
        .into_iter()
        .map(|(pos, _)| {
            let line = code[..pos].matches('\n').count() + 1;
            format!("{rel}:{line}: a layer's mod.rs holds only `pub mod` lines")
        })
        .collect()
}

/// `model/config.rs` and `plan/service/dri.rs` belong to the modules
/// `config` and `service`.
fn file_module(rel: &str) -> Option<(&str, &'static str)> {
    let mut parts = rel.split('/');
    let layer = parts.next()?;
    let layer = LAYERS.into_iter().find(|l| *l == layer)?;
    let name = parts.next()?;
    if name == "mod.rs" {
        return None;
    }
    Some((name.strip_suffix(".rs").unwrap_or(name), layer))
}

fn module_layers<'a>(rels: impl Iterator<Item = &'a str>) -> BTreeMap<String, &'static str> {
    rels.filter_map(file_module)
        .map(|(module, layer)| (module.to_string(), layer))
        .collect()
}

fn edges_in(
    rel: &str,
    text: &str,
    modules: &BTreeMap<String, &'static str>,
) -> Result<Vec<Edge>, Vec<String>> {
    let Some((from, _)) = file_module(rel) else {
        return Err(vec![format!("{rel}: not inside model/, plan/ or run/")]);
    };
    let code = strip(text);
    let tests = test_ranges(&code);
    let mut edges = Vec::new();
    let mut errors = Vec::new();
    for (pos, segment) in crate_refs(&code) {
        let at = format!("{rel}:{}", code[..pos].matches('\n').count() + 1);
        if !modules.contains_key(&segment) {
            errors.push(format!("{at}: `crate::{segment}` names no module"));
            continue;
        }
        edges.push(Edge {
            from: from.to_string(),
            to: segment,
            test: tests.iter().any(|r| r.contains(&pos)),
            at,
        });
    }
    if errors.is_empty() {
        Ok(edges)
    } else {
        Err(errors)
    }
}

fn debt_problems(
    edges: &[Edge],
    modules: &BTreeMap<String, &'static str>,
    debt: &[Entry],
    test_debt: &[Entry],
) -> Vec<String> {
    let rank = |m: &str| LAYERS.iter().position(|l| *l == modules[m]).unwrap();
    let upward: Vec<&Edge> = edges
        .iter()
        .filter(|e| rank(&e.to) > rank(&e.from))
        .collect();
    let pairs = |test: bool| -> BTreeSet<(&str, &str)> {
        upward
            .iter()
            .filter(|e| e.test == test)
            .map(|e| (e.from.as_str(), e.to.as_str()))
            .collect()
    };
    let (production, test) = (pairs(false), pairs(true));
    let listed =
        |table: &[Entry], pair: (&str, &str)| table.iter().any(|(f, t, _)| (*f, *t) == pair);
    let mut problems = Vec::new();
    let mut reported = BTreeSet::new();
    for e in &upward {
        let pair = (e.from.as_str(), e.to.as_str());
        let (table, name) = match e.test {
            true => (test_debt, "TEST_DEBT"),
            false => (debt, "DEBT"),
        };
        if !listed(table, pair) && reported.insert((pair, e.test)) {
            problems.push(format!(
                "upward edge not in {name}: (\"{}\", \"{}\", \"{}\"),",
                e.from, e.to, e.at
            ));
        }
    }
    for (table, entries, found) in [("DEBT", debt, &production), ("TEST_DEBT", test_debt, &test)] {
        for (f, t, at) in entries {
            if !found.contains(&(*f, *t)) {
                problems.push(format!(
                    "({f}, {t}, {at}) no longer occurs: remove it from {table}"
                ));
            }
        }
    }
    problems
}

/// Comments and string and char literals blanked to spaces, newlines
/// kept, so a path in a doc link or a message is not an edge and line
/// numbers still match the file.
fn strip(src: &str) -> String {
    let c: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < c.len() {
        match non_code_end(&c, i) {
            Some(end) => {
                out.extend(
                    c[i..end]
                        .iter()
                        .map(|&ch| if ch == '\n' { '\n' } else { ' ' }),
                );
                i = end;
            }
            None => {
                out.push(c[i]);
                i += 1;
            }
        }
    }
    out
}

fn non_code_end(c: &[char], i: usize) -> Option<usize> {
    let at = |k: usize| c.get(k).copied();
    let find = |from: usize, ch: char| {
        c[from.min(c.len())..]
            .iter()
            .position(|&x| x == ch)
            .map(|n| from + n)
    };
    match (c[i], at(i + 1)) {
        ('/', Some('/')) => Some(find(i, '\n').unwrap_or(c.len())),
        ('/', Some('*')) => {
            let (mut depth, mut k) = (0, i);
            while k < c.len() {
                match (c[k], at(k + 1)) {
                    ('/', Some('*')) => (depth, k) = (depth + 1, k + 2),
                    ('*', Some('/')) if depth == 1 => return Some(k + 2),
                    ('*', Some('/')) => (depth, k) = (depth - 1, k + 2),
                    _ => k += 1,
                }
            }
            Some(c.len())
        }
        ('"', _) => {
            let mut k = i + 1;
            while k < c.len() && c[k] != '"' {
                k += if c[k] == '\\' { 2 } else { 1 };
            }
            Some((k + 1).min(c.len()))
        }
        ('\'', Some('\\')) => find(i + 3, '\'').map(|k| k + 1),
        ('\'', _) if at(i + 2) == Some('\'') => Some(i + 3),
        ('r' | 'b', _) if i == 0 || !is_ident(c[i - 1]) => {
            let mut k = i + 1;
            if c[i] == 'b' {
                if at(k) != Some('r') {
                    return None;
                }
                k += 1;
            }
            let hashes = c[k..].iter().take_while(|&&x| x == '#').count();
            if at(k + hashes) != Some('"') {
                return None;
            }
            let mut j = k + hashes + 1;
            while j < c.len() {
                if c[j] == '"'
                    && c[j + 1..]
                        .iter()
                        .take(hashes)
                        .filter(|&&x| x == '#')
                        .count()
                        == hashes
                {
                    return Some(j + 1 + hashes);
                }
                j += 1;
            }
            Some(c.len())
        }
        _ => None,
    }
}

fn is_ident(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

/// The byte ranges of items marked `#[cfg(test)]`, each from the
/// attribute to its closing brace or semicolon.
fn test_ranges(code: &str) -> Vec<Range<usize>> {
    const MARK: &str = "#[cfg(test)]";
    code.match_indices(MARK)
        .map(|(start, _)| start..item_end(code.as_bytes(), start + MARK.len()))
        .collect()
}

fn item_end(b: &[u8], mut k: usize) -> usize {
    loop {
        k = skip_ws(b, k);
        if !b[k..].starts_with(b"#[") {
            break;
        }
        k = matching(b, k + 1) + 1;
    }
    let is_use = {
        let mut j = k;
        if starts_word(b, j, "pub") {
            j = skip_ws(b, j + 3);
            if b.get(j) == Some(&b'(') {
                j = skip_ws(b, matching(b, j) + 1);
            }
        }
        starts_word(b, j, "use")
    };
    let mut depth = 0i32;
    while k < b.len() {
        match b[k] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' => depth -= 1,
            b'}' => {
                depth -= 1;
                if depth == 0 && !is_use {
                    return k + 1;
                }
            }
            b';' if depth == 0 => return k + 1,
            _ => {}
        }
        k += 1;
    }
    b.len()
}

/// Each `crate::` path's first module, with its byte offset; a path
/// through a layer (`crate::run::launcher`) yields the module after it.
fn crate_refs(code: &str) -> Vec<(usize, String)> {
    let b = code.as_bytes();
    let mut out = Vec::new();
    for (start, _) in code.match_indices("crate") {
        let before = start.checked_sub(1).map(|k| b[k]);
        if before.is_some_and(|ch| is_ident(ch as char) || ch == b'$') || starts_ident(b, start + 5)
        {
            continue;
        }
        let k = skip_ws(b, start + 5);
        if b[k..].starts_with(b"::") {
            use_tree(b, k + 2, true, &mut out);
        }
    }
    out
}

fn use_tree(b: &[u8], k: usize, at_root: bool, out: &mut Vec<(usize, String)>) -> usize {
    let mut k = skip_ws(b, k);
    if b.get(k) == Some(&b'{') {
        k += 1;
        loop {
            k = skip_ws(b, k);
            match b.get(k) {
                None => return k,
                Some(b'}') => return k + 1,
                Some(b',') => k += 1,
                Some(_) => k = use_tree(b, k, at_root, out),
            }
        }
    }
    let end = ident_end(b, k);
    let segment = String::from_utf8_lossy(&b[k..end]).into_owned();
    let next = skip_ws(b, end);
    if at_root && LAYERS.contains(&segment.as_str()) && b[next..].starts_with(b"::") {
        return use_tree(b, next + 2, false, out);
    }
    out.push((k, segment));
    // An empty segment (a path form this parser does not know) still has
    // to move past one byte, or a group would loop on it.
    rest_of_tree(b, end).max(k + 1)
}

fn rest_of_tree(b: &[u8], mut k: usize) -> usize {
    loop {
        let j = skip_ws(b, k);
        if b[j..].starts_with(b"::") {
            let j = skip_ws(b, j + 2);
            k = match b.get(j) {
                Some(b'{') => matching(b, j) + 1,
                Some(b'*') => j + 1,
                _ => ident_end(b, j),
            };
        } else if starts_word(b, j, "as") {
            k = ident_end(b, skip_ws(b, j + 2));
        } else {
            return k;
        }
    }
}

fn matching(b: &[u8], open: usize) -> usize {
    let mut depth = 0;
    for (k, ch) in b.iter().enumerate().skip(open) {
        match ch {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return k;
                }
            }
            _ => {}
        }
    }
    b.len()
}

fn skip_ws(b: &[u8], mut k: usize) -> usize {
    while b.get(k).is_some_and(u8::is_ascii_whitespace) {
        k += 1;
    }
    k
}

fn ident_end(b: &[u8], mut k: usize) -> usize {
    while starts_ident(b, k) {
        k += 1;
    }
    k
}

fn starts_ident(b: &[u8], k: usize) -> bool {
    b.get(k).is_some_and(|&ch| is_ident(ch as char))
}

fn starts_word(b: &[u8], k: usize, word: &str) -> bool {
    b[k.min(b.len())..].starts_with(word.as_bytes()) && !starts_ident(b, k + word.len())
}

mod scanner {
    use super::*;

    fn modules() -> BTreeMap<String, &'static str> {
        [("config", "model"), ("bwrap", "plan"), ("launcher", "run")]
            .into_iter()
            .map(|(m, l)| (m.to_string(), l))
            .collect()
    }

    fn names(code: &str) -> Vec<String> {
        crate_refs(&strip(code))
            .into_iter()
            .map(|(_, s)| s)
            .collect()
    }

    #[test]
    fn upward_use_in_a_model_file_is_reported() {
        let edges = edges_in("model/config.rs", "use crate::launcher::X;\n", &modules()).unwrap();
        let problems = debt_problems(&edges, &modules(), &[], &[]);
        assert_eq!(problems.len(), 1);
        assert!(
            problems[0].contains("\"config\", \"launcher\", \"model/config.rs:1\""),
            "{problems:?}"
        );
    }

    #[test]
    fn a_path_through_a_layer_maps_to_the_module_after_it() {
        assert_eq!(
            names("let x = crate::run::launcher::X::new();"),
            ["launcher"]
        );
    }

    #[test]
    fn an_unknown_first_segment_fails_with_file_and_line() {
        let errors = edges_in("model/config.rs", "\nuse crate::nope::X;", &modules()).unwrap_err();
        assert_eq!(errors, ["model/config.rs:2: `crate::nope` names no module"]);
    }

    #[test]
    fn a_group_across_lines_is_parsed() {
        assert_eq!(
            names("use crate::{config,\n    bwrap::c};"),
            ["config", "bwrap"]
        );
    }

    #[test]
    fn a_nested_group_is_parsed() {
        assert_eq!(
            names("use crate::{bwrap::{b, c}, config};"),
            ["bwrap", "config"]
        );
    }

    #[test]
    fn comments_and_literals_are_not_edges() {
        let code = "/// [`crate::launcher`]\n// crate::launcher\n/* a /* crate::launcher */ */\nlet s = \"crate::launcher\";\nlet r = r#\"crate::launcher\"#;\nlet q = '\"';\n";
        assert!(names(code).is_empty());
    }

    #[test]
    fn a_cfg_test_item_is_test_code_and_what_follows_is_production() {
        let code = "#[cfg(test)]\nfn helper() { crate::launcher::x(); }\nfn prod() { crate::launcher::y(); }\n";
        let edges = edges_in("plan/bwrap.rs", code, &modules()).unwrap();
        let kinds: Vec<_> = edges.iter().map(|e| (e.at.as_str(), e.test)).collect();
        assert_eq!(
            kinds,
            [("plan/bwrap.rs:2", true), ("plan/bwrap.rs:3", false)]
        );
    }

    #[test]
    fn a_stale_entry_is_reported() {
        let problems = debt_problems(
            &[],
            &modules(),
            &[("config", "launcher", "model/config.rs:1")],
            &[],
        );
        assert_eq!(
            problems,
            ["(config, launcher, model/config.rs:1) no longer occurs: remove it from DEBT"]
        );
    }

    #[test]
    fn test_code_is_held_to_test_debt_even_when_production_has_the_edge() {
        let code = "fn prod() { crate::launcher::y(); }\n#[cfg(test)]\nmod t { use crate::launcher::x; }\n";
        let edges = edges_in("plan/bwrap.rs", code, &modules()).unwrap();
        let problems = debt_problems(
            &edges,
            &modules(),
            &[("bwrap", "launcher", "plan/bwrap.rs:1")],
            &[("config", "launcher", "model/config.rs:9")],
        );
        assert_eq!(
            problems,
            [
                "upward edge not in TEST_DEBT: (\"bwrap\", \"launcher\", \"plan/bwrap.rs:3\"),",
                "(config, launcher, model/config.rs:9) no longer occurs: remove it from TEST_DEBT",
            ]
        );
    }

    #[test]
    fn a_crate_path_in_a_layer_mod_rs_fails() {
        assert_eq!(
            root_file_problems(
                "plan/mod.rs",
                "pub mod bwrap;\npub use crate::run::launcher;\n"
            ),
            ["plan/mod.rs:2: a layer's mod.rs holds only `pub mod` lines"]
        );
        assert!(
            root_file_problems(
                "lib.rs",
                "pub use run::launcher;\npub use crate::run::tty;\n"
            )
            .is_empty()
        );
    }
}
