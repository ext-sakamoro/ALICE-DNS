//! Blocklist Parser — StevenBlack/hosts Format
//!
//! Parses the standard hosts-format blocklist used by Pi-hole:
//! ```text
//! 0.0.0.0 ads.example.com
//! 0.0.0.0 tracker.example.com
//! # This is a comment
//! ```
//!
//! Also supports plain domain lists (one domain per line).

use alloc::string::String;
use alloc::vec::Vec;

/// Parse a hosts-format blocklist into a list of domains.
///
/// Handles:
/// - `0.0.0.0 domain.com` (StevenBlack format)
/// - `127.0.0.1 domain.com` (alternative format)
/// - `domain.com` (plain domain list)
/// - `# comments` (ignored)
/// - Empty lines (ignored)
/// - `localhost`, `local`, `broadcasthost` (skipped)
pub fn parse_hosts(content: &str) -> Vec<String> {
    let mut domains = Vec::new();
    let skip_domains = [
        "localhost",
        "localhost.localdomain",
        "local",
        "broadcasthost",
        "ip6-localhost",
        "ip6-loopback",
        "ip6-localnet",
        "ip6-mcastprefix",
        "ip6-allnodes",
        "ip6-allrouters",
        "ip6-allhosts",
        "0.0.0.0",
    ];

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }

        // Extract domain from hosts format: "0.0.0.0 domain" or "127.0.0.1 domain"
        let domain = if line.starts_with("0.0.0.0 ") || line.starts_with("127.0.0.1 ") {
            // Split on whitespace, take second field
            line.split_whitespace().nth(1)
        } else if line.starts_with("::1 ") || line.starts_with("fe80::") || line.starts_with("ff") {
            // IPv6 hosts entries — take second field
            line.split_whitespace().nth(1)
        } else if !line.contains(' ') && line.contains('.') {
            // Plain domain (no IP prefix)
            Some(line)
        } else {
            None
        };

        if let Some(d) = domain {
            let d = d.trim();
            // Skip system domains and empty
            if !d.is_empty() && !skip_domains.contains(&d) {
                // Basic validation: must contain at least one dot, no spaces
                if d.contains('.') && !d.contains(' ') && d.len() <= 253 {
                    domains.push(d.to_lowercase());
                }
            }
        }
    }

    // Deduplicate (sort + dedup)
    domains.sort_unstable();
    domains.dedup();

    domains
}

/// Load a blocklist from a file path.
///
/// Returns parsed domain list or error.
pub fn load_from_file(path: &std::path::Path) -> std::io::Result<Vec<String>> {
    let content = std::fs::read_to_string(path)?;
    Ok(parse_hosts(&content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_stevenblack_format() {
        let content = "\
# Comment line
0.0.0.0 0.0.0.0
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.com
127.0.0.1 localhost
127.0.0.1 localhost.localdomain
0.0.0.0 doubleclick.net
";
        let domains = parse_hosts(content);
        assert_eq!(domains, vec![
            "ads.example.com",
            "doubleclick.net",
            "tracker.example.com",
        ]);
    }

    #[test]
    fn test_parse_plain_domain_list() {
        let content = "\
ads.example.com
tracker.example.com
doubleclick.net
";
        let domains = parse_hosts(content);
        assert_eq!(domains.len(), 3);
        assert!(domains.contains(&"doubleclick.net".to_string()));
    }

    #[test]
    fn test_skip_system_domains() {
        let content = "\
0.0.0.0 localhost
0.0.0.0 ip6-localhost
::1 ip6-loopback
0.0.0.0 ads.malware.com
";
        let domains = parse_hosts(content);
        assert_eq!(domains, vec!["ads.malware.com"]);
    }

    #[test]
    fn test_deduplication() {
        let content = "\
0.0.0.0 duplicate.com
0.0.0.0 duplicate.com
0.0.0.0 unique.com
";
        let domains = parse_hosts(content);
        assert_eq!(domains, vec!["duplicate.com", "unique.com"]);
    }

    #[test]
    fn test_case_normalization() {
        let content = "\
0.0.0.0 ADS.EXAMPLE.COM
0.0.0.0 Tracker.Example.COM
";
        let domains = parse_hosts(content);
        assert_eq!(domains, vec!["ads.example.com", "tracker.example.com"]);
    }

    #[test]
    fn test_ipv6_hosts() {
        let content = "\
::1 localhost
fe80::1%lo0 localhost
ff00::0 ip6-localnet
0.0.0.0 real-blocked.com
";
        let domains = parse_hosts(content);
        assert_eq!(domains, vec!["real-blocked.com"]);
    }

    #[test]
    fn test_empty_and_comments() {
        let content = "\n# This is a comment\n! Another comment style\n\n  # Indented comment\n0.0.0.0 valid.domain.com\n";
        let domains = parse_hosts(content);
        assert_eq!(domains, vec!["valid.domain.com"]);
    }
}
