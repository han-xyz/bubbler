//! What the proxy is allowed to reach: the names an `allow-host` writes
//! and the single port each of them carries.
//!
//! The patterns live here rather than in bubbler's core because both
//! sides need the same rule — the config that accepts a name and the
//! proxy that judges a `CONNECT` target — and two copies of a matching
//! rule is one copy too many for a filter. Core re-exports
//! [`HostPattern`]; the proxy takes the list as argv and never reads a
//! config file.

use std::fmt;

/// A name an `allow-host` names: ASCII labels, lower case, with an
/// optional `*.` in front standing for exactly one label.
///
/// The rules are DNS's own (RFC 1035 §2.3.1 with RFC 1123 §2.1's leading
/// digit): letters, digits and `-`, no label starting or ending in `-`,
/// 63 characters to a label and 253 to a name. bubbler converts nothing:
/// an internationalised name is written as the `xn--` A-labels it
/// resolves as, so what the config says and what the proxy compares a
/// `CONNECT` target against are the same bytes.
///
/// A name whose last label is all digits is refused, so no address in
/// the notations a config would write one in parses as a name;
/// `allow-out` is where an address goes. `getaddrinfo` also reads hex
/// forms such as `0x7f000001`, which are letters and digits and do parse
/// here — a config writing one has named an address on purpose, and the
/// proxy refuses an address as a `CONNECT` target whatever its shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPattern {
    /// The labels under the wildcard, lower case and without the root
    /// dot: `["example", "com"]` for `example.com` and for
    /// `*.example.com` alike.
    pub labels: Vec<String>,
    /// Whether a `*.` stands in front of [`HostPattern::labels`], which
    /// matches one label and never zero or two.
    pub wildcard: bool,
}

impl HostPattern {
    /// Longest name accepted, measured over the text as written: a
    /// trailing dot counts toward it, so no name buys a label with one.
    const MAX_NAME: usize = 253;
    /// Longest single label, from DNS.
    const MAX_LABEL: usize = 63;

    /// Parse `s` as an `allow-host` name, or say what is wrong with it.
    ///
    /// The reason never echoes the value: it is arbitrary text out of a
    /// config file and may hold the control bytes the message would then
    /// carry to a terminal.
    pub fn parse(s: &str) -> Result<Self, String> {
        if s.len() > Self::MAX_NAME {
            return Err(format!(
                "a name is at most {} characters, trailing dot included",
                Self::MAX_NAME
            ));
        }
        // The root dot is what a name may end in and nothing else: two
        // of them leave an empty label, which the loop below refuses.
        let name = s.strip_suffix('.').unwrap_or(s);
        let mut labels = Vec::new();
        let mut wildcard = false;
        for (i, label) in name.split('.').enumerate() {
            if i == 0 && label == "*" {
                wildcard = true;
                continue;
            }
            Self::check_label(label)?;
            labels.push(label.to_ascii_lowercase());
        }
        if labels.is_empty() {
            return Err(
                "a wildcard stands for one label under a name, as in `*.example.com`".to_owned(),
            );
        }
        // `1.2.3.4` would otherwise parse as a name of four labels and
        // match nothing a resolver ever answers with.
        if labels
            .last()
            .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(
                "a name whose last label is all digits is an address, and an address is \
                 what `allow-out` names; the proxy matches names only"
                    .to_owned(),
            );
        }
        Ok(Self { labels, wildcard })
    }

    /// Whether `s` is a label, or why it is not one. The one place the
    /// rule is written: [`HostPattern::parse`] holds a config to it and
    /// [`HostPattern::matches`] holds the probe to the same rule, so a
    /// name that could never be written cannot be matched either.
    pub(crate) fn check_label(s: &str) -> Result<(), String> {
        if s.is_empty() {
            return Err(
                "a name holds no empty label: no two dots in a row, and none at the start"
                    .to_owned(),
            );
        }
        if s.len() > Self::MAX_LABEL {
            return Err(format!("a label is at most {} characters", Self::MAX_LABEL));
        }
        if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(
                "a label holds ASCII letters, digits and `-` only; write an internationalised \
                 name as the `xn--` form it resolves as, and a `*` as the whole first label"
                    .to_owned(),
            );
        }
        if s.starts_with('-') || s.ends_with('-') {
            return Err("a label neither starts nor ends with `-`".to_owned());
        }
        Ok(())
    }

    /// Whether `host` is a name this pattern covers. Case is ignored and
    /// one trailing dot with it, since a `CONNECT` target may carry
    /// either form; a wildcard covers exactly one label, never the name
    /// itself and never two labels under it.
    ///
    /// The probe is held to the rules [`HostPattern::parse`] takes, the
    /// wildcard's own label included: a `CONNECT` target is text the
    /// sandbox wrote, and one that is no name matches nothing here
    /// rather than reaching a resolver on the strength of its suffix.
    pub fn matches(&self, host: &str) -> bool {
        if host.len() > Self::MAX_NAME {
            return false;
        }
        let host = host.strip_suffix('.').unwrap_or(host);
        let mut got: Vec<&str> = host.split('.').collect();
        if !got.iter().all(|l| Self::check_label(l).is_ok()) {
            return false;
        }
        if self.wildcard {
            // Never empty: `split` yields at least one label and every
            // one of them just passed the rule above.
            got.remove(0);
        }
        got.len() == self.labels.len()
            && got
                .iter()
                .zip(&self.labels)
                .all(|(g, l)| g.eq_ignore_ascii_case(l))
    }
}

impl fmt::Display for HostPattern {
    /// The name as a config writes it, which is its canonical form:
    /// lower case, no trailing dot.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.wildcard {
            f.write_str("*.")?;
        }
        f.write_str(&self.labels.join("."))
    }
}

/// The names and ports one run of the proxy may connect to, as the
/// `--allow` words gave them.
///
/// Order is the argv's and means nothing: a target is allowed when any
/// entry covers it, and no entry ever widens another.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Allowlist {
    entries: Vec<(HostPattern, u16)>,
}

impl Allowlist {
    /// Read one `--allow` word: a name, a `:`, and a port.
    ///
    /// The port is written out even where it is the default, so the
    /// argv says exactly what a run allows and the proxy has no default
    /// of its own to disagree with the config's.
    pub fn entry(word: &str) -> Result<(HostPattern, u16), String> {
        let (name, port) = word
            .rsplit_once(':')
            .ok_or_else(|| "an allowed target is written `name:port`".to_owned())?;
        let pattern = HostPattern::parse(name)?;
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err("a port is one to five digits".to_owned());
        }
        match port.parse::<u16>() {
            Ok(0) | Err(_) => Err("a port is between 1 and 65535".to_owned()),
            Ok(port) => Ok((pattern, port)),
        }
    }

    /// Build the list from the `--allow` words, or say which one is not
    /// a target. An empty list is a list that allows nothing.
    pub fn parse<I, S>(words: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut entries = Vec::new();
        for word in words {
            entries.push(Self::entry(word.as_ref())?);
        }
        Ok(Self { entries })
    }

    /// Whether a `CONNECT` target may be reached: some entry's name
    /// covers `host` and that same entry's port is `port`.
    ///
    /// Name and port are one grant, never two: an entry for
    /// `api.example:443` is no reason to reach `api.example:22`.
    pub fn matches(&self, host: &str, port: u16) -> bool {
        self.entries
            .iter()
            .any(|(pattern, allowed)| *allowed == port && pattern.matches(host))
    }

    /// How many targets the list holds, for the line the proxy logs
    /// when it starts.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the list allows nothing at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(s: &str) -> HostPattern {
        HostPattern::parse(s).expect(s)
    }

    #[test]
    fn host_patterns_parse_by_the_ldh_rules() {
        for ok in [
            "api.anthropic.com",
            "Claude.AI.",
            "xn--bcher-kva.example",
            "*.example.com",
            "a1.b2",
        ] {
            assert!(HostPattern::parse(ok).is_ok(), "{ok}");
        }
        assert_eq!(pattern("Claude.AI.").to_string(), "claude.ai");
        assert_eq!(pattern("*.Example.COM").to_string(), "*.example.com");
        for bad in [
            "",
            ".",
            "a..b",
            "-a.b",
            "a-.b",
            "a_b.c",
            "b\u{fc}cher.de",
            "*",
            "*.",
            "a.*.b",
            "*.*.c",
            "1.2.3.4",
            "[::1]",
            "a b",
            &format!("{}.c", "x".repeat(64)),
            &"a.".repeat(127),
        ] {
            assert!(HostPattern::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_wildcard_matches_exactly_one_label() {
        let p = pattern("*.example.com");
        assert!(p.matches("a.example.com"));
        assert!(!p.matches("example.com"));
        assert!(!p.matches("a.b.example.com"));
        assert!(!p.matches(".example.com"));
        let e = pattern("example.com");
        assert!(e.matches("EXAMPLE.com."));
        assert!(!e.matches("a.example.com"));
    }

    /// The probe is held to the rules a config is held to, the
    /// wildcard's own label included: a `CONNECT` target is text the
    /// sandbox wrote, and one that is no name must not reach a resolver
    /// on the strength of its suffix.
    #[test]
    fn a_probe_that_is_no_name_matches_nothing() {
        let p = pattern("*.example.com");
        assert!(p.matches("a1.example.com"));
        for bad in [
            "a_b.example.com",
            "-a.example.com",
            "a-.example.com",
            "a b.example.com",
            "b\u{fc}cher.example.com",
            "a..example.com",
            "*.example.com",
            &format!("{}.example.com", "x".repeat(64)),
            &format!("{}.example.com", "x.".repeat(126)),
        ] {
            assert!(!p.matches(bad), "{bad}");
        }
        let e = pattern("example.com");
        assert!(!e.matches("exam ple.com"));
        assert!(!e.matches("example.com.."));
    }

    #[test]
    fn an_allowlist_grants_a_name_and_its_port_together() {
        let list = Allowlist::parse(["api.example:443", "*.cdn.example:443"]).expect("two targets");
        assert!(list.matches("api.example", 443));
        assert!(!list.matches("api.example", 80));
        assert!(list.matches("x.cdn.example", 443));
        assert!(!list.matches("cdn.example", 443));
        assert!(!list.matches("api.example.com", 443));
        assert_eq!(list.len(), 2);
        assert!(!list.is_empty());
    }

    #[test]
    fn an_empty_allowlist_allows_nothing() {
        let list = Allowlist::default();
        assert!(!list.matches("api.example", 443));
        assert!(list.is_empty());
    }

    #[test]
    fn a_word_that_is_no_target_is_refused() {
        for bad in [
            "api.example",
            "api.example:",
            ":443",
            "api.example:0",
            "api.example:65536",
            "api.example:443443",
            "api.example:+443",
            "api.example:4 3",
            "1.2.3.4:443",
            "[::1]:443",
            "a_b.example:443",
        ] {
            assert!(Allowlist::parse([bad]).is_err(), "{bad}");
        }
        assert_eq!(
            Allowlist::entry("*.cdn.example:8443").expect("a target"),
            (pattern("*.cdn.example"), 8443)
        );
    }
}
