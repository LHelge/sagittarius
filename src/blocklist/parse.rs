//! Blocklist text parsers — `hosts` and `domain-list` formats (SPEC §6, E7.2).
//!
//! Each format is implemented as a zero-sized unit struct that implements
//! [`BlocklistParser`].  The [`Parser`] enum unifies them and can be obtained
//! from a [`BlocklistFormat`] via the standard [`From`] trait, so the call site
//! reduces to a one-liner:
//!
//! ```rust
//! use sagittarius::blocklist::parse::{BlocklistParser as _, Parser};
//! use sagittarius::storage::blocklists::BlocklistFormat;
//!
//! let text = "0.0.0.0 ads.example.com\n";
//! let names = Parser::from(BlocklistFormat::Hosts).parse(text);
//! assert!(names.contains(&"ads.example.com".parse().unwrap()));
//! ```
//!
//! # Comment handling
//!
//! Both parsers share the same pre-processing rules:
//!
//! - A line that is blank or entirely whitespace is ignored.
//! - A line whose first non-whitespace character is `#` or `!` is a comment
//!   and is ignored entirely.
//! - Everything from the first `#` to end-of-line is stripped as an inline
//!   comment **before** tokenizing, so `0.0.0.0 ads.example.com # note` and
//!   `ads.example.com # note` are handled correctly by both parsers.
//!   A lone `!` mid-line is not treated as an inline comment; only `!` at the
//!   **start** of a line (after whitespace) starts a whole-line comment.
//!
//! # Invalid domain handling
//!
//! Lines (or individual hostname fields within a hosts line) that fail
//! [`Name::from_str`] validation are **silently skipped**.  Parsing is never
//! fatal; the returned set contains only the valid entries.

use std::collections::HashSet;

use crate::{codec::name::Name, storage::blocklists::BlocklistFormat};

// ── BlocklistParser trait ─────────────────────────────────────────────────────

/// Parses raw blocklist text into a set of normalized domain names.
///
/// Implementors must:
/// - Ignore blank/whitespace-only lines.
/// - Ignore lines whose first non-whitespace character is `#` or `!`.
/// - Strip inline `#` comments before tokenizing.
/// - Silently skip any domain field that is not a valid [`Name`] (never fatal).
pub trait BlocklistParser {
    /// Parse `text`, returning the set of normalized [`Name`]s it contains.
    ///
    /// Comments and blank lines are ignored; lines (or individual fields) whose
    /// domain is not a valid [`Name`] are skipped — they never cause an error.
    ///
    /// The returned [`HashSet`] deduplicates case-insensitively because
    /// [`Name`] normalizes to lowercase and implements [`Eq`] + [`Hash`] on
    /// the normalized form.
    fn parse(&self, text: &str) -> HashSet<Name>;
}

// ── Shared pre-processing ─────────────────────────────────────────────────────

/// Pre-process a single line: strip inline `#` comments, trim whitespace, and
/// return `None` if the result is a whole-line comment (`#`/`!` first char) or
/// blank.
///
/// `str::lines()` already handles `\r\n` by stripping the `\r`, so callers
/// should iterate via `text.lines()` before calling this function.
#[inline]
fn preprocess(line: &str) -> Option<&str> {
    // Strip inline comment (everything from the first `#` onward).
    let line = if let Some(pos) = line.find('#') {
        &line[..pos]
    } else {
        line
    };

    let trimmed = line.trim();

    // Blank line.
    if trimmed.is_empty() {
        return None;
    }

    // Whole-line comment: first non-whitespace char is `!`.
    if trimmed.starts_with('!') {
        return None;
    }

    Some(trimmed)
}

// ── HostsParser ───────────────────────────────────────────────────────────────

/// Parser for `hosts`-style blocklists.
///
/// Each content line has the form:
///
/// ```text
/// <sink-ip>  <hostname> [<hostname> ...]
/// ```
///
/// The first whitespace-delimited field (the sink IP) is discarded; every
/// remaining field is parsed as a [`Name`].  Invalid fields are silently
/// skipped.  Lines with only an IP and no hostname (i.e. a single field) yield
/// no entries.
///
/// # Examples
///
/// ```text
/// 0.0.0.0 ads.example.com          # → ads.example.com.
/// 127.0.0.1 tracker.example.org    # → tracker.example.org.
/// 0.0.0.0 a.example.com b.example.com   # → both names
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct HostsParser;

impl BlocklistParser for HostsParser {
    fn parse(&self, text: &str) -> HashSet<Name> {
        let mut names = HashSet::new();

        for line in text.lines() {
            let Some(content) = preprocess(line) else {
                continue;
            };

            // Split on whitespace; skip the first field (the sink IP).
            let mut fields = content.split_ascii_whitespace();
            // Discard the IP field.
            fields.next();

            for field in fields {
                if let Ok(name) = field.parse::<Name>() {
                    names.insert(name);
                }
                // Invalid fields are silently skipped.
            }
        }

        names
    }
}

// ── DomainListParser ──────────────────────────────────────────────────────────

/// Parser for `domain-list`-style blocklists.
///
/// Each content line contains exactly one domain name.  After inline-comment
/// stripping and trimming, the entire remaining content of the line is parsed
/// as a [`Name`].  Lines that are blank, a comment, or contain an invalid
/// domain name are silently skipped.
///
/// # Examples
///
/// ```text
/// ads.example.com            # → ads.example.com.
/// Tracker.Example.Org        # → tracker.example.org.  (lowercased)
/// ! whole-line comment       # → ignored
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct DomainListParser;

impl BlocklistParser for DomainListParser {
    fn parse(&self, text: &str) -> HashSet<Name> {
        let mut names = HashSet::new();

        for line in text.lines() {
            let Some(content) = preprocess(line) else {
                continue;
            };

            // The entire (pre-processed) line must be a single token — any
            // embedded whitespace means the line is not a plain domain name
            // (e.g. an unparsed hosts-style line slipped in) and is skipped.
            if content.contains(char::is_whitespace) {
                continue;
            }

            if let Ok(name) = content.parse::<Name>() {
                names.insert(name);
            }
            // Lines with invalid domain structure are silently skipped.
        }

        names
    }
}

// ── Parser (format dispatch) ──────────────────────────────────────────────────

/// A unified parser that dispatches to the correct format-specific
/// implementation.
///
/// Construct from a [`BlocklistFormat`] via [`From`]:
///
/// ```rust
/// use sagittarius::blocklist::parse::{BlocklistParser as _, Parser};
/// use sagittarius::storage::blocklists::BlocklistFormat;
///
/// let parser = Parser::from(BlocklistFormat::DomainList);
/// let names = parser.parse("ads.example.com\ntracker.example.org\n");
/// assert_eq!(names.len(), 2);
/// ```
#[derive(Debug, Clone, Copy)]
pub enum Parser {
    /// Dispatch to [`HostsParser`].
    Hosts(HostsParser),
    /// Dispatch to [`DomainListParser`].
    DomainList(DomainListParser),
}

impl From<BlocklistFormat> for Parser {
    fn from(format: BlocklistFormat) -> Self {
        match format {
            BlocklistFormat::Hosts => Self::Hosts(HostsParser),
            BlocklistFormat::DomainList => Self::DomainList(DomainListParser),
        }
    }
}

impl BlocklistParser for Parser {
    fn parse(&self, text: &str) -> HashSet<Name> {
        match self {
            Self::Hosts(p) => p.parse(text),
            Self::DomainList(p) => p.parse(text),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::blocklists::BlocklistFormat;

    // ── Helper ────────────────────────────────────────────────────────────────

    fn name(s: &str) -> Name {
        s.parse().expect("valid name in test helper")
    }

    // ── HostsParser: basic entries ────────────────────────────────────────────

    /// `0.0.0.0 ads.example.com` yields the normalized name (lowercase,
    /// trailing dot).
    #[test]
    fn hosts_basic_0000_entry() {
        let set = HostsParser.parse("0.0.0.0 ads.example.com\n");
        assert!(
            set.contains(&name("ads.example.com")),
            "expected ads.example.com. in set; got {set:?}"
        );
        assert_eq!(set.len(), 1);
    }

    /// `127.0.0.1 tracker.example.org` yields the normalized name.
    #[test]
    fn hosts_basic_loopback_entry() {
        let set = HostsParser.parse("127.0.0.1 tracker.example.org\n");
        assert!(set.contains(&name("tracker.example.org")));
        assert_eq!(set.len(), 1);
    }

    /// Mixed-case input is normalized to lowercase.
    #[test]
    fn hosts_mixed_case_normalizes() {
        let set = HostsParser.parse("0.0.0.0 ADS.Example.COM\n");
        assert!(set.contains(&name("ads.example.com")));
        assert_eq!(set.len(), 1);
    }

    // ── HostsParser: multiple hostnames per line ──────────────────────────────

    /// A hosts line with multiple hostnames yields all of them.
    #[test]
    fn hosts_multiple_hostnames_per_line() {
        let set = HostsParser.parse("0.0.0.0 a.example.com b.example.com\n");
        assert!(set.contains(&name("a.example.com")));
        assert!(set.contains(&name("b.example.com")));
        assert_eq!(set.len(), 2);
    }

    // ── HostsParser: comment and blank handling ───────────────────────────────

    /// A line starting with `#` is ignored (whole-line comment).
    #[test]
    fn hosts_hash_comment_line_ignored() {
        let set = HostsParser.parse("# This is a comment\n0.0.0.0 ads.example.com\n");
        assert_eq!(set.len(), 1);
        assert!(set.contains(&name("ads.example.com")));
    }

    /// A line starting with `!` is ignored (AdBlock-style whole-line comment).
    #[test]
    fn hosts_exclamation_comment_line_ignored() {
        let set = HostsParser.parse("! This is also a comment\n0.0.0.0 ads.example.com\n");
        assert_eq!(set.len(), 1);
        assert!(set.contains(&name("ads.example.com")));
    }

    /// A blank line is ignored.
    #[test]
    fn hosts_blank_line_ignored() {
        let set = HostsParser.parse("\n\n0.0.0.0 ads.example.com\n\n");
        assert_eq!(set.len(), 1);
    }

    /// A whitespace-only line is ignored.
    #[test]
    fn hosts_whitespace_only_line_ignored() {
        let set = HostsParser.parse("   \t   \n0.0.0.0 ads.example.com\n");
        assert_eq!(set.len(), 1);
    }

    /// An inline `#` comment is stripped; the domain before it is still parsed.
    #[test]
    fn hosts_inline_comment_stripped() {
        let set = HostsParser.parse("0.0.0.0 ads.example.com # this is tracked\n");
        assert!(
            set.contains(&name("ads.example.com")),
            "domain before inline comment must still be parsed"
        );
        assert_eq!(set.len(), 1);
    }

    // ── HostsParser: malformed lines skipped ─────────────────────────────────

    /// An empty-label domain (`foo..bar`) is skipped (not fatal).
    #[test]
    fn hosts_empty_label_skipped() {
        let set = HostsParser.parse("0.0.0.0 foo..bar\n0.0.0.0 valid.example.com\n");
        assert!(
            !set.contains(&name("foo.")),
            "invalid domain must not appear"
        );
        assert!(set.contains(&name("valid.example.com")));
        assert_eq!(set.len(), 1, "only the valid entry should be present");
    }

    /// A label that is longer than 63 bytes is skipped (not fatal).
    #[test]
    fn hosts_overlength_label_skipped() {
        let long = "a".repeat(64);
        let input = format!("0.0.0.0 {long}.example.com\n0.0.0.0 valid.example.com\n");
        let set = HostsParser.parse(&input);
        assert!(set.contains(&name("valid.example.com")));
        assert_eq!(set.len(), 1);
    }

    /// A hosts line with only an IP and no hostname yields no entries.
    #[test]
    fn hosts_ip_only_line_yields_no_entry() {
        let set = HostsParser.parse("0.0.0.0\n");
        assert!(set.is_empty(), "IP-only line must yield no entries");
    }

    /// A hosts line with a partially valid and an invalid field: the valid one
    /// is kept, the invalid one is skipped.
    #[test]
    fn hosts_mixed_valid_invalid_fields() {
        let set = HostsParser.parse("0.0.0.0 good.example.com bad..domain\n");
        assert!(set.contains(&name("good.example.com")));
        assert_eq!(set.len(), 1);
    }

    // ── DomainListParser: basic entries ──────────────────────────────────────

    /// One domain per line yields each domain normalized.
    #[test]
    fn domain_list_basic_entries() {
        let text = "ads.example.com\ntracker.example.org\n";
        let set = DomainListParser.parse(text);
        assert!(set.contains(&name("ads.example.com")));
        assert!(set.contains(&name("tracker.example.org")));
        assert_eq!(set.len(), 2);
    }

    /// Mixed-case input is normalized to lowercase.
    #[test]
    fn domain_list_mixed_case_normalizes() {
        let set = DomainListParser.parse("Tracker.Example.Org\n");
        assert!(set.contains(&name("tracker.example.org")));
        assert_eq!(set.len(), 1);
    }

    // ── DomainListParser: comment and blank handling ──────────────────────────

    /// A line starting with `#` is ignored.
    #[test]
    fn domain_list_hash_comment_ignored() {
        let set = DomainListParser.parse("# comment\nads.example.com\n");
        assert_eq!(set.len(), 1);
        assert!(set.contains(&name("ads.example.com")));
    }

    /// A line starting with `!` is ignored.
    #[test]
    fn domain_list_exclamation_comment_ignored() {
        let set = DomainListParser.parse("! comment\nads.example.com\n");
        assert_eq!(set.len(), 1);
        assert!(set.contains(&name("ads.example.com")));
    }

    /// A blank line is ignored.
    #[test]
    fn domain_list_blank_line_ignored() {
        let set = DomainListParser.parse("\nads.example.com\n\n");
        assert_eq!(set.len(), 1);
    }

    /// An inline `#` comment is stripped; the domain before it is still parsed.
    #[test]
    fn domain_list_inline_comment_stripped() {
        let set = DomainListParser.parse("ads.example.com # this domain is blocked\n");
        assert!(set.contains(&name("ads.example.com")));
        assert_eq!(set.len(), 1);
    }

    // ── DomainListParser: malformed lines skipped ─────────────────────────────

    /// A domain-list line with embedded spaces is skipped (the whole line after
    /// inline-comment stripping still contains a space, making it invalid as a
    /// single domain).
    ///
    /// Note: `"foo bar"` after stripping is not a valid `Name` because it
    /// contains a space, so `Name::from_str` rejects it — the line is skipped.
    #[test]
    fn domain_list_embedded_space_skipped() {
        // After trimming "foo bar" is not a valid name; should be skipped.
        let set = DomainListParser.parse("foo bar\nads.example.com\n");
        assert!(set.contains(&name("ads.example.com")));
        assert_eq!(set.len(), 1, "line with spaces must be skipped");
    }

    /// An empty-label domain is skipped.
    #[test]
    fn domain_list_empty_label_skipped() {
        let set = DomainListParser.parse("foo..bar\nads.example.com\n");
        assert!(set.contains(&name("ads.example.com")));
        assert_eq!(set.len(), 1);
    }

    /// An over-long label is skipped.
    #[test]
    fn domain_list_overlength_label_skipped() {
        let long = "a".repeat(64);
        let input = format!("{long}.example.com\nads.example.com\n");
        let set = DomainListParser.parse(&input);
        assert!(set.contains(&name("ads.example.com")));
        assert_eq!(set.len(), 1);
    }

    // ── Equivalence: hosts and domain-list ───────────────────────────────────

    /// Parsing equivalent content via both formats yields identical sets.
    #[test]
    fn hosts_and_domain_list_equivalent_content_match() {
        let hosts_text = "0.0.0.0 ads.example.com\n";
        let domain_list_text = "ads.example.com\n";

        let hosts_set = HostsParser.parse(hosts_text);
        let dl_set = DomainListParser.parse(domain_list_text);

        assert_eq!(
            hosts_set, dl_set,
            "equivalent content must produce identical sets"
        );
    }

    // ── Deduplication ─────────────────────────────────────────────────────────

    /// The same domain appearing twice collapses to one entry (hosts format).
    #[test]
    fn hosts_deduplicates_same_domain() {
        let set = HostsParser.parse("0.0.0.0 ads.example.com\n0.0.0.0 ads.example.com\n");
        assert_eq!(set.len(), 1);
    }

    /// Mixed-case duplicates also collapse (domain-list format).
    #[test]
    fn domain_list_deduplicates_case_insensitive() {
        let set = DomainListParser.parse("ADS.Example.com\nads.example.com\n");
        assert_eq!(set.len(), 1);
    }

    /// Duplicate that appears once in hosts uppercase and once lowercase still
    /// collapses to a single entry.
    #[test]
    fn hosts_deduplicates_case_insensitive() {
        let set = HostsParser.parse("0.0.0.0 ADS.EXAMPLE.COM\n0.0.0.0 ads.example.com\n");
        assert_eq!(set.len(), 1);
    }

    // ── CRLF line endings ─────────────────────────────────────────────────────

    /// `\r\n` line endings are handled correctly by both parsers.
    #[test]
    fn hosts_crlf_line_endings() {
        let set = HostsParser.parse("0.0.0.0 ads.example.com\r\n0.0.0.0 tracker.example.org\r\n");
        assert!(set.contains(&name("ads.example.com")));
        assert!(set.contains(&name("tracker.example.org")));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn domain_list_crlf_line_endings() {
        let set = DomainListParser.parse("ads.example.com\r\ntracker.example.org\r\n");
        assert!(set.contains(&name("ads.example.com")));
        assert!(set.contains(&name("tracker.example.org")));
        assert_eq!(set.len(), 2);
    }

    // ── Format dispatch via Parser enum ──────────────────────────────────────

    /// `Parser::from(BlocklistFormat::Hosts)` correctly parses a hosts-format
    /// input.
    #[test]
    fn parser_dispatch_hosts_format() {
        let parser = Parser::from(BlocklistFormat::Hosts);
        let set = parser.parse("0.0.0.0 ads.example.com\n");
        assert!(set.contains(&name("ads.example.com")));
        assert_eq!(set.len(), 1);
    }

    /// `Parser::from(BlocklistFormat::DomainList)` correctly parses a
    /// domain-list-format input.
    #[test]
    fn parser_dispatch_domain_list_format() {
        let parser = Parser::from(BlocklistFormat::DomainList);
        let set = parser.parse("ads.example.com\ntracker.example.org\n");
        assert!(set.contains(&name("ads.example.com")));
        assert!(set.contains(&name("tracker.example.org")));
        assert_eq!(set.len(), 2);
    }

    /// `Parser::from(BlocklistFormat::Hosts)` does NOT treat the first field as
    /// a domain (it is discarded as the sink IP).
    #[test]
    fn parser_dispatch_hosts_discards_ip_field() {
        let parser = Parser::from(BlocklistFormat::Hosts);
        let set = parser.parse("0.0.0.0 ads.example.com\n");
        // The IP "0.0.0.0" must not appear in the result.
        // "0.0.0.0" would parse as a valid Name (it has no invalid characters
        // for the Name type, but we discard the first field regardless).
        assert!(set.contains(&name("ads.example.com")));
        assert_eq!(set.len(), 1, "the IP field must be discarded, not included");
    }

    // ── Large-ish input: reasonable allocation ────────────────────────────────

    /// Parsing a thousand-line hosts file completes without error and yields the
    /// expected number of distinct names.
    #[test]
    fn hosts_large_input_parses_correctly() {
        let mut text = String::new();
        for i in 0..1_000u32 {
            text.push_str(&format!("0.0.0.0 host{i}.example.com\n"));
        }
        let set = HostsParser.parse(&text);
        assert_eq!(set.len(), 1_000);
        assert!(set.contains(&name("host0.example.com")));
        assert!(set.contains(&name("host999.example.com")));
    }
}
