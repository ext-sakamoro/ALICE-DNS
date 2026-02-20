//! Statistics & Monitoring
//!
//! Optional ALICE-Analytics integration for Pi-hole dashboard replacement.
//!
//! When compiled with `--features analytics`:
//! - HyperLogLog: unique domains queried (cardinality estimation)
//! - CountMinSketch: top blocked domains (heavy hitters)
//! - DDSketch: query latency percentiles (P50/P95/P99)
//!
//! Without analytics feature: basic counters only.

use alloc::string::String;

#[cfg(feature = "analytics")]
use alice_analytics::{HyperLogLog, CountMinSketch, DDSketch};

/// DNS server statistics.
pub struct DnsStats {
    // Basic counters (always available)
    /// Total DNS queries received.
    pub queries_total: u64,
    /// Queries blocked by Bloom filter.
    pub queries_blocked: u64,
    /// Queries forwarded to upstream.
    pub queries_forwarded: u64,
    /// Cache hits (response served from cache).
    pub cache_hits: u64,
    /// Cache misses (forwarded to upstream).
    pub cache_misses: u64,
    /// Upstream errors (all resolvers failed).
    pub upstream_errors: u64,
    /// Bloom filter false positives.
    pub bloom_false_positives: u64,

    // Advanced analytics (optional)
    #[cfg(feature = "analytics")]
    unique_domains: HyperLogLog,
    #[cfg(feature = "analytics")]
    top_blocked: CountMinSketch,
    #[cfg(feature = "analytics")]
    latency_sketch: DDSketch,
}

impl DnsStats {
    pub fn new() -> Self {
        Self {
            queries_total: 0,
            queries_blocked: 0,
            queries_forwarded: 0,
            cache_hits: 0,
            cache_misses: 0,
            upstream_errors: 0,
            bloom_false_positives: 0,
            #[cfg(feature = "analytics")]
            unique_domains: HyperLogLog::new(),
            #[cfg(feature = "analytics")]
            top_blocked: CountMinSketch::new(),
            #[cfg(feature = "analytics")]
            latency_sketch: DDSketch::new(0.01),
        }
    }

    /// Record a query event.
    pub fn record_query(&mut self, domain: &str, blocked: bool, latency_us: u64) {
        self.queries_total += 1;

        if blocked {
            self.queries_blocked += 1;
            #[cfg(feature = "analytics")]
            self.top_blocked.add_str(domain);
        } else {
            self.queries_forwarded += 1;
        }

        #[cfg(feature = "analytics")]
        {
            self.unique_domains.add_str(domain);
            self.latency_sketch.insert(latency_us as f64);
        }

        // Suppress unused variable warnings when analytics disabled
        #[cfg(not(feature = "analytics"))]
        {
            let _ = domain;
            let _ = latency_us;
        }
    }

    /// Block rate (0.0 to 1.0).
    #[inline(always)]
    pub fn block_rate(&self) -> f64 {
        if self.queries_total == 0 {
            return 0.0;
        }
        // Reciprocal multiplication: avoids repeated integer division on each call.
        let inv_total = 1.0_f64 / self.queries_total as f64;
        self.queries_blocked as f64 * inv_total
    }

    /// Print a summary report to stdout.
    pub fn print_summary(&self) {
        println!("┌─────────────────────────────────────────┐");
        println!("│         ALICE-DNS Statistics             │");
        println!("├─────────────────────────────────────────┤");
        println!("│ Queries total:      {:>18} │", self.queries_total);
        println!("│ Queries blocked:    {:>18} │", self.queries_blocked);
        println!("│ Queries forwarded:  {:>18} │", self.queries_forwarded);
        println!("│ Block rate:         {:>17.1}% │", self.block_rate() * 100.0);
        println!("│ Cache hits:         {:>18} │", self.cache_hits);
        println!("│ Cache misses:       {:>18} │", self.cache_misses);
        println!("│ Upstream errors:    {:>18} │", self.upstream_errors);
        println!("│ Bloom false pos:    {:>18} │", self.bloom_false_positives);

        #[cfg(feature = "analytics")]
        {
            println!("├─────────────────────────────────────────┤");
            println!("│ Unique domains:     {:>18} │", self.unique_domains.count() as u64);
            println!("│ Latency P50:        {:>15.0} μs │", self.latency_sketch.quantile(0.50).unwrap_or(0.0));
            println!("│ Latency P95:        {:>15.0} μs │", self.latency_sketch.quantile(0.95).unwrap_or(0.0));
            println!("│ Latency P99:        {:>15.0} μs │", self.latency_sketch.quantile(0.99).unwrap_or(0.0));
        }

        println!("└─────────────────────────────────────────┘");
    }

    /// Generate a JSON stats string (for API endpoint or logging).
    pub fn to_json(&self) -> String {
        let mut json = alloc::format!(
            r#"{{"queries_total":{},"queries_blocked":{},"queries_forwarded":{},"block_rate":{:.4},"cache_hits":{},"cache_misses":{},"upstream_errors":{},"bloom_false_positives":{}"#,
            self.queries_total,
            self.queries_blocked,
            self.queries_forwarded,
            self.block_rate(),
            self.cache_hits,
            self.cache_misses,
            self.upstream_errors,
            self.bloom_false_positives,
        );

        #[cfg(feature = "analytics")]
        {
            json.push_str(&alloc::format!(
                r#","unique_domains":{},"latency_p50":{:.0},"latency_p95":{:.0},"latency_p99":{:.0}"#,
                self.unique_domains.count() as u64,
                self.latency_sketch.quantile(0.50).unwrap_or(0.0),
                self.latency_sketch.quantile(0.95).unwrap_or(0.0),
                self.latency_sketch.quantile(0.99).unwrap_or(0.0),
            ));
        }

        json.push('}');
        json
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_basic() {
        let mut stats = DnsStats::new();
        stats.record_query("ads.example.com", true, 50);
        stats.record_query("google.com", false, 2000);
        stats.record_query("tracker.net", true, 30);

        assert_eq!(stats.queries_total, 3);
        assert_eq!(stats.queries_blocked, 2);
        assert_eq!(stats.queries_forwarded, 1);
        assert!((stats.block_rate() - 0.6667).abs() < 0.01);
    }

    #[test]
    fn test_stats_empty() {
        let stats = DnsStats::new();
        assert_eq!(stats.block_rate(), 0.0);
    }

    #[test]
    fn test_stats_json() {
        let mut stats = DnsStats::new();
        stats.queries_total = 100;
        stats.queries_blocked = 30;
        stats.queries_forwarded = 70;

        let json = stats.to_json();
        assert!(json.contains("\"queries_total\":100"));
        assert!(json.contains("\"queries_blocked\":30"));
    }
}
