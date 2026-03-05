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
/// - `0.0.0.0 domain.com` (`StevenBlack` format)
/// - `127.0.0.1 domain.com` (alternative format)
/// - `domain.com` (plain domain list)
/// - `# comments` (ignored)
/// - Empty lines (ignored)
/// - `localhost`, `local`, `broadcasthost` (skipped)
#[must_use]
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
///
/// # Errors
///
/// Returns an I/O error if the file cannot be read.
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
        assert_eq!(
            domains,
            vec!["ads.example.com", "doubleclick.net", "tracker.example.com",]
        );
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

    #[test]
    fn test_empty_input() {
        let domains = parse_hosts("");
        assert!(domains.is_empty());
    }

    #[test]
    fn test_only_comments() {
        let content = "# comment\n# another\n! exclamation comment\n";
        let domains = parse_hosts(content);
        assert!(domains.is_empty());
    }

    #[test]
    fn test_only_blank_lines() {
        let content = "\n\n\n   \n\t\n";
        let domains = parse_hosts(content);
        assert!(domains.is_empty());
    }

    #[test]
    fn test_domain_max_length_accepted() {
        // 253文字ちょうどは受け入れる: "aaa...a.com" (249 'a' + ".com" = 253)
        let long = format!("{}.com", "a".repeat(249));
        assert_eq!(long.len(), 253);
        let content = format!("0.0.0.0 {long}");
        let domains = parse_hosts(&content);
        assert_eq!(domains.len(), 1);
    }

    #[test]
    fn test_domain_too_long_rejected() {
        // 254文字は拒否する
        let too_long = format!("{}.com", "a".repeat(250));
        assert_eq!(too_long.len(), 254);
        let content = format!("0.0.0.0 {too_long}");
        let domains = parse_hosts(&content);
        assert!(domains.is_empty());
    }

    #[test]
    fn test_no_dot_domains_rejected() {
        // ドットを含まないエントリは無効
        let content = "plain-no-dot\nanother-no-dot\n";
        let domains = parse_hosts(content);
        assert!(domains.is_empty());
    }

    #[test]
    fn test_127_0_0_1_format() {
        let content = "127.0.0.1 ads.example.com\n127.0.0.1 tracker.bad.net\n";
        let domains = parse_hosts(content);
        assert_eq!(domains, vec!["ads.example.com", "tracker.bad.net"]);
    }

    #[test]
    fn test_all_skip_domains_rejected() {
        let content = "\
0.0.0.0 localhost
0.0.0.0 localhost.localdomain
0.0.0.0 local
0.0.0.0 broadcasthost
0.0.0.0 ip6-localhost
0.0.0.0 ip6-loopback
0.0.0.0 ip6-localnet
0.0.0.0 ip6-mcastprefix
0.0.0.0 ip6-allnodes
0.0.0.0 ip6-allrouters
0.0.0.0 ip6-allhosts
0.0.0.0 0.0.0.0
";
        let domains = parse_hosts(content);
        assert!(domains.is_empty());
    }

    #[test]
    fn test_sorted_output() {
        let content = "\
0.0.0.0 z.example.com
0.0.0.0 a.example.com
0.0.0.0 m.example.com
";
        let domains = parse_hosts(content);
        assert_eq!(
            domains,
            vec!["a.example.com", "m.example.com", "z.example.com"]
        );
    }

    #[test]
    fn test_whitespace_trimming() {
        // 行頭・行末の空白をトリムしてパース
        let content = "   0.0.0.0 trimmed.example.com   \n";
        let domains = parse_hosts(content);
        assert_eq!(domains, vec!["trimmed.example.com"]);
    }

    #[test]
    fn test_single_label_no_dot_rejected() {
        // ドットなし単一ラベルは除外、ドットあり平文ドメインは通る
        let content = "single-label-only\nad.example.org\n";
        let domains = parse_hosts(content);
        assert_eq!(domains, vec!["ad.example.org"]);
    }

    #[test]
    fn test_mixed_formats() {
        let content = "\
# StevenBlack mixed format
0.0.0.0 ads1.example.com
127.0.0.1 ads2.example.com
ads3.example.com
# end
";
        let domains = parse_hosts(content);
        assert_eq!(
            domains,
            vec!["ads1.example.com", "ads2.example.com", "ads3.example.com"]
        );
    }

    #[test]
    fn test_domain_with_space_in_plain_form_rejected() {
        // スペースを含む行は平文ドメインとして認識されず除外される
        let content = "domain with spaces.com\n0.0.0.0 valid.domain.net\n";
        let domains = parse_hosts(content);
        assert_eq!(domains, vec!["valid.domain.net"]);
    }
}
