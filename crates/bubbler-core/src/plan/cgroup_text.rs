//! The cgroup names an explanation shows: the leaf the egress proxy runs
//! in, and the placeholder for the path a run would create, from
//! bubbler's own cgroup as the caller read it.

// The leaf the egress proxy writes itself into, which is what the
// ruleset accepts.
pub(crate) const PROXY_LEAF: &str = "proxy";

/// The leaf an explanation names, under the cgroup a run of `instance`
/// would create: the sandbox pid is not part of it, and bubbler's own is
/// whatever the run has.
pub fn placeholder(own: &str, instance: &str) -> String {
    let base = match own.is_empty() {
        true => String::new(),
        false => format!("{own}/"),
    };
    format!("{base}bubbler-{instance}-<pid>/{PROXY_LEAF}")
}
