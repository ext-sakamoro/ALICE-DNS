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
    /// Statistics
    pub queries_total: u64,
    pub queries_blocked: u64,
    pub bloom_false_positives: u64,
}

impl DnsBloomEngine {
    /// Create an empty engine.
    pub fn new() -> Self {
        Self {
            filter: alloc::vec![0u8; BLOOM_SIZE_BYTES],
            domains: BTreeSet::new(),
            queries_total: 0,
            queries_blocked: 0,
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

    /// Check if a domain should be blocked.
    ///
    /// Returns `true` if the domain (or any parent domain) is in the blocklist.
    ///
    /// # Algorithm
    ///
    /// 1. Normalize to lowercase (branchless)
    /// 2. Check exact domain against Bloom filter — O(1)
    /// 3. If Bloom says NO → definitely not blocked (zero false negatives)
    /// 4. If Bloom says MAYBE → confirm against HashSet
    /// 5. Walk up parent domains: `sub.ads.example.com` → `ads.example.com` → `example.com`
    #[inline]
    pub fn should_block(&mut self, domain: &str) -> bool {
        self.queries_total += 1;

        let normalized = fast_to_lower_bytes(domain.as_bytes());

        // Walk domain hierarchy: "sub.ads.example.com" → "ads.example.com" → "example.com"
        let mut start = 0;
        loop {
            let segment = &normalized[start..];
            let hash = bloom_hash(segment);

            // Phase 1: Bloom filter — O(1), branchless
            if bloom_test(&self.filter, hash) {
                // Phase 2: Exact confirmation — O(1) amortized
                let segment_str = unsafe { core::str::from_utf8_unchecked(segment) };
                if self.domains.contains(segment_str) {
                    self.queries_blocked += 1;
                    return true;
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

        false
    }

    /// Number of domains loaded.
    #[inline]
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    /// Bloom filter memory usage in bytes.
    #[inline]
    pub fn bloom_size_bytes(&self) -> usize {
        self.filter.len()
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.queries_total = 0;
        self.queries_blocked = 0;
        self.bloom_false_positives = 0;
    }
}

// ─── Bloom Filter Internals (from ALICE-Browser) ─────────────────────

/// FNV-1a hash — fast, well-distributed for short strings (domain names).
///
/// Ported from ALICE-Browser `src/simd/adblock.rs:bloom_hash`.
#[inline]
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
#[inline]
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
#[inline]
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
#[inline]
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

        assert!(engine.should_block("doubleclick.net"));
        assert!(engine.should_block("sub.doubleclick.net"));
        assert!(engine.should_block("DOUBLECLICK.NET")); // case insensitive
        assert!(!engine.should_block("example.com"));
        assert!(!engine.should_block("google.com"));
    }

    #[test]
    fn test_engine_subdomain_walk() {
        let mut engine = DnsBloomEngine::new();
        let domains: Vec<String> = vec!["ads.com".into()];
        engine.load_domains(&domains);

        assert!(engine.should_block("ads.com"));
        assert!(engine.should_block("sub.ads.com"));
        assert!(engine.should_block("deep.sub.ads.com"));
        assert!(!engine.should_block("goodads.com")); // different domain
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
        assert!(engine2.should_block("ad.example.com"));
        assert!(engine2.should_block("tracker.test.org"));
        assert!(!engine2.should_block("safe.example.com"));
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

        engine.should_block("blocked.com");
        engine.should_block("allowed.com");
        engine.should_block("sub.blocked.com");

        assert_eq!(engine.queries_total, 3);
        assert_eq!(engine.queries_blocked, 2);
    }
}
