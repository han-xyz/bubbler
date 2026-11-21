//! Why a run's data could not be computed: a host resource a service
//! needs, a destination the symlink sweep refuses, a seccomp filter
//! that does not compile.

use std::io;
use std::path::PathBuf;

use libseccomp::error::SeccompError;
use thiserror::Error;

/// Failures while resolving what a run binds, sets and filters.
#[derive(Debug, Error)]
pub enum PlanError {
    /// A service needs a host path that does not exist.
    #[error("service `{service}` needs `{path}` which does not exist")]
    MissingResource {
        /// Name of the service that made the request.
        service: &'static str,
        /// The host path that is missing.
        path: PathBuf,
    },
    /// A host path exists but is of the wrong type to bind, e.g. a
    /// directory where a socket is expected.
    #[error("service `{service}` needs `{path}` to be {expected}")]
    WrongType {
        /// Name of the service that made the request.
        service: &'static str,
        /// The host path with the wrong type.
        path: PathBuf,
        /// What the service expected, as an article plus noun.
        expected: &'static str,
    },
    /// A service needs an environment variable that is unset.
    #[error("service `{service}` needs ${var} to be set")]
    MissingEnv {
        /// Name of the service that made the request.
        service: &'static str,
        /// The environment variable that must be set.
        var: &'static str,
    },
    /// A service was given a value it cannot interpret.
    #[error("service `{service}`: {reason}")]
    BadValue {
        /// Name of the service that rejected the value.
        service: &'static str,
        /// Why the value was rejected.
        reason: String,
    },
    /// A destination bwrap would create sits behind a symlink inside a
    /// tree the application can write.
    #[error(
        "refusing to start: {inside} is a symlink in {tree} (-> {target}); an app may have \
         planted it. Remove it from {host}/ to continue."
    )]
    PlantedSymlink {
        /// Path inside the sandbox, as the argv writes it.
        inside: PathBuf,
        /// Which app-writable tree it is in, as a message names it.
        tree: &'static str,
        /// What the link points at, read without following it.
        target: PathBuf,
        /// Root of that tree on the host: where the link has to be
        /// removed from.
        host: PathBuf,
    },
    /// Whether a destination sits behind a symlink could not be told: a
    /// component under a directory the user cannot search, or a loop on
    /// the way.
    #[error(
        "refusing to start: cannot check whether {inside} is a symlink in {tree} ({host}: \
         {source}); make it readable or remove it"
    )]
    UncheckedDestination {
        /// Path inside the sandbox, as the argv writes it.
        inside: PathBuf,
        /// Which app-writable tree it is in, as a message names it.
        tree: &'static str,
        /// The host path the check failed at.
        host: PathBuf,
        /// Why `lstat` could not answer.
        #[source]
        source: io::Error,
    },
    /// A destination the argv was built with has a `..` or a root
    /// component, which the symlink sweep cannot walk on the host.
    /// bubbler builds every destination itself, so this is a bug in the
    /// builder.
    #[error(
        "refusing to start: destination {0} has a `..` or root component the symlink sweep cannot walk"
    )]
    UnwalkableDestination(PathBuf),
    /// Creating an fd bwrap must inherit failed: a data file, the control
    /// socket or a sidecar's ready pipe.
    #[error("preparing an fd for bwrap")]
    Data(#[source] io::Error),
    /// libseccomp refused the rule set or the program; the message is
    /// its own. Not a `#[source]`: the text already carries it.
    #[error("compiling the seccomp filter: {0}")]
    SeccompCompile(SeccompError),
    /// The compiled program could not be read back through its memfd.
    #[error("compiling the seccomp filter: exporting the filter: {0}")]
    SeccompExport(io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refused_rule_reads_as_the_compiler_message() {
        let cause = libseccomp::ScmpSyscall::from_name("no_such_syscall").unwrap_err();
        let text = format!("compiling the seccomp filter: {cause}");
        assert_eq!(PlanError::SeccompCompile(cause).to_string(), text);
    }

    #[test]
    fn a_failed_export_reads_as_an_export_failure() {
        let e = PlanError::SeccompExport(io::Error::other("no memfd"));
        assert_eq!(
            e.to_string(),
            "compiling the seccomp filter: exporting the filter: no memfd"
        );
    }
}
