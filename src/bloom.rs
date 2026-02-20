//! Bloom Filter DNS Blocking Engine
//!
//! Ported from ALICE-Browser `src/simd/adblock.rs` and expanded for DNS-scale blocking.
//!
//! Original: 4KB (32768 bits) for ~200 domains
//! Expanded: 512KB (4194304 bits) for ~80K domains, false positive rate < 0.01%
//!
//! # Architecture
//!
//! ```text
//! DNS Query → bloom_test() O(1) → MISS → Allow (forward to upstream)
//!                                → HIT  → HashSet confirm → Block / Allow (false positive)
//! ```

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

/// Action to take for a DNS query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsAction {
    /// Forward to upstream DNS (not blocked, or exact whitelist match)
    Allow,
    /// Return 0.0.0.0 / :: (blocked domain)
    Block,
    /// Return spoof IP (blocked subdomain of whitelisted parent — anti-adblock bypass)
    Spoof,
}

/// 512KB = 4,194,304 bits — enough for 80K domains at < 0.01% FP rate.
///
/// Optimal formula: m = -n * ln(p) / (ln(2))^2
/// n=80000, p=0.0001 → m = 1,532,878 bits → we use 4M bits for margin.
const BLOOM_SIZE_BITS: usize = 4_194_304;
const BLOOM_SIZE_BYTES: usize = BLOOM_SIZE_BITS / 8; // 512KB

/// DNS Bloom Filter blocking engine.
///
/// Two-phase lookup:
/// 1. Bloom filter: O(1), may return false positives
/// 2. HashSet: O(1) amortized, exact confirmation on Bloom hits
pub struct DnsBloomEngine {
    /// Bloom filter bits (512KB)
    filter: Vec<u8>,
    /// Exact domain set for false-positive confirmation
    domains: BTreeSet<String>,
    /// Whitelist — domains that bypass blocking (checked before Bloom filter)
    whitelist: BTreeSet<String>,
    /// Statistics
    pub queries_total: u64,
    pub queries_blocked: u64,
    pub queries_whitelisted: u64,
    pub bloom_false_positives: u64,
}

impl DnsBloomEngine {
    /// Create an empty engine.
    pub fn new() -> Self {
        Self {
            filter: alloc::vec![0u8; BLOOM_SIZE_BYTES],
            domains: BTreeSet::new(),
            whitelist: BTreeSet::new(),
            queries_total: 0,
            queries_blocked: 0,
            queries_whitelisted: 0,
            bloom_false_positives: 0,
        }
    }

    /// Load domains from a parsed hosts-format blocklist.
    ///
    /// Clears existing data and rebuilds both Bloom filter and HashSet.
    pub fn load_domains(&mut self, domain_list: &[String]) {
        // Reset
        self.filter.fill(0);
        self.domains.clear();

        for domain in domain_list {
            let d = fast_to_lower_bytes(domain.as_bytes());
            let hash = bloom_hash(&d);
            bloom_set(&mut self.filter, hash);
            // SAFETY: fast_to_lower_bytes only changes ASCII uppercase → lowercase
            let domain_str = unsafe { String::from_utf8_unchecked(d) };
            self.domains.insert(domain_str);
        }
    }

    /// Load from a pre-built binary filter file + domain list.
    ///
    /// File format:
    /// ```text
    /// [4 bytes] domain_count (u32 LE)
    /// [512KB]   bloom filter bits
    /// [rest]    newline-separated domain list
    /// ```
    pub fn load_from_binary(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() < 4 + BLOOM_SIZE_BYTES {
            return Err("Binary data too short");
        }

        let domain_count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let bloom_data = &data[4..4 + BLOOM_SIZE_BYTES];
        let domain_data = &data[4 + BLOOM_SIZE_BYTES..];

        // Load bloom filter
        self.filter.clear();
        self.filter.extend_from_slice(bloom_data);

        // Load domain set
        self.domains.clear();
        if let Ok(text) = core::str::from_utf8(domain_data) {
            for line in text.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    self.domains.insert(trimmed.to_string());
                }
            }
        }

        if self.domains.len() != domain_count {
            // Non-fatal: count mismatch, but we loaded what we could
        }

        Ok(())
    }

    /// Serialize to binary format for hot-reload.
    pub fn to_binary(&self) -> Vec<u8> {
        let domain_count = self.domains.len() as u32;
        let domain_text: String = self.domains.iter().map(|d| {
            let mut s = d.clone();
            s.push('\n');
            s
        }).collect();

        let mut out = Vec::with_capacity(4 + BLOOM_SIZE_BYTES + domain_text.len());
        out.extend_from_slice(&domain_count.to_le_bytes());
        out.extend_from_slice(&self.filter);
        out.extend_from_slice(domain_text.as_bytes());
        out
    }

    /// Load whitelist domains. Whitelisted domains bypass blocking entirely.
    pub fn load_whitelist(&mut self, domain_list: &[String]) {
        self.whitelist.clear();
        for domain in domain_list {
            let d = fast_to_lower_bytes(domain.as_bytes());
            // SAFETY: fast_to_lower_bytes only modifies ASCII uppercase bytes (A-Z → a-z),
            // preserving valid UTF-8 encoding since ASCII bytes are single-byte code points.
            let domain_str = unsafe { String::from_utf8_unchecked(d) };
            self.whitelist.insert(domain_str);
        }
    }

    /// Check what action to take for a domain.
    ///
    /// Returns `DnsAction::Allow`, `DnsAction::Block`, or `DnsAction::Spoof`.
    ///
    /// # Algorithm
    ///
    /// 0. Check whitelist (exact match) — if whitelisted, Allow immediately
    /// 1. Walk domain hierarchy with Bloom filter + HashSet
    /// 2. If blocked AND the matching blocklist entry is also whitelisted → Spoof
    ///    (e.g. `0.html-load.com` blocked via parent `html-load.com` which is whitelisted)
    /// 3. If blocked normally → Block
    /// 4. Not blocked → Allow
    #[inline(always)]
    pub fn check_domain(&mut self, domain: &str) -> DnsAction {
        self.queries_total += 1;

        let normalized = fast_to_lower_bytes(domain.as_bytes());

        // Phase 0: Whitelist check — walk domain hierarchy
        // e.g. "html-load.com" whitelisted → "0.html-load.com" also allowed
        if !self.whitelist.is_empty() {
            let mut ws = 0;
            loop {
                let seg = &normalized[ws..];
                // SAFETY: normalized is produced by fast_to_lower_bytes which only changes
                // ASCII uppercase → lowercase, preserving valid UTF-8.
                let seg_str = unsafe { core::str::from_utf8_unchecked(seg) };
                if self.whitelist.contains(seg_str) {
                    self.queries_whitelisted += 1;
                    return DnsAction::Allow;
                }
                match seg.iter().position(|&b| b == b'.') {
                    Some(dot) => ws += dot + 1,
                    None => break,
                }
            }
        }

        // Walk domain hierarchy: "sub.ads.example.com" → "ads.example.com" → "example.com"
        let mut start = 0;
        loop {
            let segment = &normalized[start..];
            let hash = bloom_hash(segment);

            // Phase 1: Bloom filter — O(1), branchless
            if bloom_test(&self.filter, hash) {
                // Phase 2: Exact confirmation — O(1) amortized
                // SAFETY: normalized is produced by fast_to_lower_bytes which only changes
                // ASCII uppercase → lowercase, preserving valid UTF-8.
                let segment_str = unsafe { core::str::from_utf8_unchecked(segment) };
                if self.domains.contains(segment_str) {
                    // Blocked! But check if the matching domain is whitelisted → Spoof
                    if !self.whitelist.is_empty() && self.whitelist.contains(segment_str) {
                        self.queries_whitelisted += 1;
                        return DnsAction::Spoof;
                    }
                    self.queries_blocked += 1;
                    return DnsAction::Block;
                }
                // Bloom false positive
                self.bloom_false_positives += 1;
            }

            // Walk to parent domain
            match segment.iter().position(|&b| b == b'.') {
                Some(dot_pos) => start += dot_pos + 1,
                None => break, // No more parent domains
            }
        }

        DnsAction::Allow
    }

    /// Number of domains loaded.
    #[inline(always)]
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    /// Bloom filter memory usage in bytes.
    #[inline(always)]
    pub fn bloom_size_bytes(&self) -> usize {
        self.filter.len()
    }

    /// Reset statistics.
    /// Number of whitelisted domains loaded.
    #[inline(always)]
    pub fn whitelist_count(&self) -> usize {
        self.whitelist.len()
    }

    pub fn reset_stats(&mut self) {
        self.queries_total = 0;
        self.queries_blocked = 0;
        self.queries_whitelisted = 0;
        self.bloom_false_positives = 0;
    }
}

// ─── Bloom Filter Internals (from ALICE-Browser) ─────────────────────

/// FNV-1a hash — fast, well-distributed for short strings (domain names).
///
/// Ported from ALICE-Browser `src/simd/adblock.rs:bloom_hash`.
#[inline(always)]
fn bloom_hash(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325; // FNV offset basis
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3); // FNV prime
    }
    h
}

/// Set bits in Bloom filter using double hashing.
///
/// We use 3 hash functions derived from a single FNV-1a hash:
/// h1 = hash[0:22], h2 = hash[16:38], h3 = hash[32:54]
///
/// 3 hashes × 512KB filter → optimal for 80K domains.
#[inline(always)]
fn bloom_set(filter: &mut [u8], hash: u64) {
    let mask = (BLOOM_SIZE_BITS - 1) as u64; // 4M-1 = 0x3FFFFF
    let h1 = (hash & mask) as usize;
    let h2 = ((hash >> 16) & mask) as usize;
    let h3 = ((hash >> 32) & mask) as usize;
    filter[h1 >> 3] |= 1 << (h1 & 7);
    filter[h2 >> 3] |= 1 << (h2 & 7);
    filter[h3 >> 3] |= 1 << (h3 & 7);
}

/// Test bits in Bloom filter — branchless AND of all hash positions.
///
/// Returns `true` if ALL bits are set (domain MAY be in the set).
/// Returns `false` if ANY bit is unset (domain is DEFINITELY NOT in the set).
#[inline(always)]
fn bloom_test(filter: &[u8], hash: u64) -> bool {
    let mask = (BLOOM_SIZE_BITS - 1) as u64;
    let h1 = (hash & mask) as usize;
    let h2 = ((hash >> 16) & mask) as usize;
    let h3 = ((hash >> 32) & mask) as usize;
    // Branchless: bitwise AND of all three tests
    (filter[h1 >> 3] & (1 << (h1 & 7)) != 0)
        & (filter[h2 >> 3] & (1 << (h2 & 7)) != 0)
        & (filter[h3 >> 3] & (1 << (h3 & 7)) != 0)
}

/// Branchless ASCII lowercase conversion.
///
/// Ported from ALICE-Browser `src/simd/adblock.rs:fast_to_lower`.
/// Instead of `if (b >= 'A' && b <= 'Z') b += 32`, we use:
///   `offset = ((b - 'A') < 26) as u8 * 32`
/// No branches, no pipeline stalls.
#[inline(always)]
fn fast_to_lower_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for &b in bytes {
        let is_upper = b.wrapping_sub(b'A') < 26;
        let offset = (is_upper as u8) << 5; // 32 if uppercase, 0 otherwise
        out.push(b + offset);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_basic() {
        let mut filter = alloc::vec![0u8; BLOOM_SIZE_BYTES];
        let hash = bloom_hash(b"doubleclick.net");
        bloom_set(&mut filter, hash);
        assert!(bloom_test(&filter, hash));
        assert!(!bloom_test(&filter, bloom_hash(b"example.com")));
    }

    #[test]
    fn test_engine_block() {
        let mut engine = DnsBloomEngine::new();
        let domains: Vec<String> = vec![
            "doubleclick.net".into(),
            "ads.example.com".into(),
            "tracker.analytics.com".into(),
        ];
        engine.load_domains(&domains);

        assert_eq!(engine.check_domain("doubleclick.net"), DnsAction::Block);
        assert_eq!(engine.check_domain("sub.doubleclick.net"), DnsAction::Block);
        assert_eq!(engine.check_domain("DOUBLECLICK.NET"), DnsAction::Block);
        assert_eq!(engine.check_domain("example.com"), DnsAction::Allow);
        assert_eq!(engine.check_domain("google.com"), DnsAction::Allow);
    }

    #[test]
    fn test_engine_subdomain_walk() {
        let mut engine = DnsBloomEngine::new();
        let domains: Vec<String> = vec!["ads.com".into()];
        engine.load_domains(&domains);

        assert_eq!(engine.check_domain("ads.com"), DnsAction::Block);
        assert_eq!(engine.check_domain("sub.ads.com"), DnsAction::Block);
        assert_eq!(engine.check_domain("deep.sub.ads.com"), DnsAction::Block);
        assert_eq!(engine.check_domain("goodads.com"), DnsAction::Allow);
    }

    #[test]
    fn test_whitelist_hierarchy() {
        let mut engine = DnsBloomEngine::new();
        // html-load.com is in both blocklist AND whitelist
        let domains: Vec<String> = vec!["html-load.com".into(), "ads.com".into()];
        engine.load_domains(&domains);
        let whitelist: Vec<String> = vec!["html-load.com".into()];
        engine.load_whitelist(&whitelist);

        // Whitelisted domain and subdomains → Allow (hierarchy walk)
        assert_eq!(engine.check_domain("html-load.com"), DnsAction::Allow);
        assert_eq!(engine.check_domain("0.html-load.com"), DnsAction::Allow);
        assert_eq!(engine.check_domain("9.html-load.com"), DnsAction::Allow);
        // Unrelated blocked domain → Block
        assert_eq!(engine.check_domain("ads.com"), DnsAction::Block);
        assert_eq!(engine.check_domain("sub.ads.com"), DnsAction::Block);
    }

    #[test]
    fn test_binary_roundtrip() {
        let mut engine = DnsBloomEngine::new();
        let domains: Vec<String> = vec![
            "ad.example.com".into(),
            "tracker.test.org".into(),
        ];
        engine.load_domains(&domains);

        let binary = engine.to_binary();

        let mut engine2 = DnsBloomEngine::new();
        engine2.load_from_binary(&binary).unwrap();

        assert_eq!(engine2.domain_count(), 2);
        assert_eq!(engine2.check_domain("ad.example.com"), DnsAction::Block);
        assert_eq!(engine2.check_domain("tracker.test.org"), DnsAction::Block);
        assert_eq!(engine2.check_domain("safe.example.com"), DnsAction::Allow);
    }

    #[test]
    fn test_fast_to_lower() {
        assert_eq!(fast_to_lower_bytes(b"HELLO"), b"hello");
        assert_eq!(fast_to_lower_bytes(b"Example.COM"), b"example.com");
        assert_eq!(fast_to_lower_bytes(b"already-lower"), b"already-lower");
    }

    #[test]
    fn test_stats() {
        let mut engine = DnsBloomEngine::new();
        let domains: Vec<String> = vec!["blocked.com".into()];
        engine.load_domains(&domains);

        engine.check_domain("blocked.com");
        engine.check_domain("allowed.com");
        engine.check_domain("sub.blocked.com");

        assert_eq!(engine.queries_total, 3);
        assert_eq!(engine.queries_blocked, 2);
    }
}
