//! Upstream DNS Forwarding with ALICE-Cache
//!
//! Forwards allowed DNS queries to upstream resolvers (1.1.1.1, 8.8.8.8)
//! with intelligent caching via ALICE-Cache.
//!
//! # Cache Strategy
//!
//! - Key: domain name + query type (e.g., "example.com:A")
//! - Value: raw DNS response bytes
//! - TTL: respected from upstream response (capped at 1 hour)
//! - Eviction: ALICE-Cache sampled eviction (Redis-style)
//! - Prefetch: Markov oracle predicts likely next queries

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use alice_cache::{AliceCache, CacheConfig};

/// Maximum DNS response size (UDP, 4096 for EDNS support).
const MAX_DNS_RESPONSE: usize = 4096;
/// Query timeout for upstream DNS.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
/// Maximum cache TTL (cap upstream TTLs to 1 hour).
const MAX_CACHE_TTL_SECS: u64 = 3600;
/// Default cache capacity (number of DNS responses).
const DEFAULT_CACHE_CAPACITY: usize = 50_000;

/// Upstream DNS resolver address.
#[derive(Debug, Clone)]
pub struct UpstreamResolver {
    pub addr: String,
    pub name: String,
}

/// Cached DNS response with TTL tracking.
#[derive(Clone)]
struct CachedResponse {
    data: Vec<u8>,
    cached_at: Instant,
    ttl_secs: u64,
}

/// Upstream DNS forwarder with ALICE-Cache.
pub struct UpstreamForwarder {
    /// Upstream resolvers (tried in order).
    resolvers: Vec<UpstreamResolver>,
    /// DNS response cache (ALICE-Cache: 256-shard, Markov prefetch).
    cache: AliceCache<String, CachedResponse>,
    /// UDP socket for upstream queries.
    socket: UdpSocket,
    /// Statistics.
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub upstream_errors: u64,
}

impl UpstreamForwarder {
    /// Create a new forwarder with default upstream resolvers.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the UDP socket cannot be bound.
    pub fn new() -> std::io::Result<Self> {
        Self::with_resolvers(vec![
            UpstreamResolver {
                addr: "1.1.1.1:53".into(),
                name: "Cloudflare".into(),
            },
            UpstreamResolver {
                addr: "8.8.8.8:53".into(),
                name: "Google".into(),
            },
        ])
    }

    /// Create with custom resolvers.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the UDP socket cannot be bound or configured.
    pub fn with_resolvers(resolvers: Vec<UpstreamResolver>) -> std::io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;

        let cache = AliceCache::with_config(CacheConfig {
            capacity: DEFAULT_CACHE_CAPACITY,
            num_nodes: 1,
            node_id: 0,
            enable_oracle: true,
            ..Default::default()
        });

        Ok(Self {
            resolvers,
            cache,
            socket,
            cache_hits: 0,
            cache_misses: 0,
            upstream_errors: 0,
        })
    }

    /// Forward a DNS query, using cache when possible.
    ///
    /// Returns the response bytes to send back to the client.
    /// The transaction ID in the response is rewritten to match the original query.
    pub fn forward(&mut self, query_packet: &[u8], domain: &str, qtype: u16) -> Option<Vec<u8>> {
        let cache_key = format!("{domain}:{qtype}");

        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key) {
            // Check if still valid (TTL not expired)
            let elapsed = cached.cached_at.elapsed().as_secs();
            if elapsed < cached.ttl_secs {
                self.cache_hits += 1;
                let mut response = cached.data;
                // Rewrite transaction ID to match this query
                if response.len() >= 2 && query_packet.len() >= 2 {
                    response[0] = query_packet[0];
                    response[1] = query_packet[1];
                }
                return Some(response);
            }
            // TTL expired — fall through to upstream
        }

        self.cache_misses += 1;

        // Try each upstream resolver
        for resolver in &self.resolvers {
            if let Some(response) = self.query_upstream(query_packet, &resolver.addr) {
                // Extract TTL from first answer record
                let ttl = extract_min_ttl(&response).unwrap_or(300);
                let capped_ttl = ttl.min(MAX_CACHE_TTL_SECS);

                // Cache the response
                self.cache.put(
                    cache_key,
                    CachedResponse {
                        data: response.clone(),
                        cached_at: Instant::now(),
                        ttl_secs: capped_ttl,
                    },
                );

                return Some(response);
            }
            self.upstream_errors += 1;
        }

        None // All upstreams failed
    }

    /// Send query to a single upstream resolver.
    ///
    /// Validates that the response transaction ID matches the query.
    /// Stale responses from previous queries are discarded (max 3 retries).
    fn query_upstream(&self, query_packet: &[u8], addr: &str) -> Option<Vec<u8>> {
        if query_packet.len() < 2 {
            return None;
        }

        if self.socket.send_to(query_packet, addr).is_err() {
            return None;
        }

        let expected_id = [query_packet[0], query_packet[1]];
        let mut buf = [0u8; MAX_DNS_RESPONSE];

        // Retry up to 3 times to skip stale responses from previous queries
        for _ in 0..3 {
            match self.socket.recv_from(&mut buf) {
                Ok((size, _)) if size >= 2 => {
                    if buf[0] == expected_id[0] && buf[1] == expected_id[1] {
                        return Some(buf[..size].to_vec());
                    }
                    // Transaction ID mismatch — stale response, try again
                }
                _ => return None, // Timeout or error
            }
        }

        None // All retries consumed by stale responses
    }

    /// Cache hit rate (0.0 to 1.0).
    #[inline(always)]
    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            return 0.0;
        }
        // Reciprocal multiplication: avoids division on each reporting call.
        let inv_total = 1.0_f64 / total as f64;
        self.cache_hits as f64 * inv_total
    }

    /// Number of entries currently in cache.
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

/// Extract the minimum TTL from DNS response answer records.
///
/// Scans answer section and returns the smallest TTL value found.
fn extract_min_ttl(response: &[u8]) -> Option<u64> {
    if response.len() < 12 {
        return None;
    }

    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    // Skip header (12 bytes) and question section
    let mut pos = 12;

    // Skip question section
    while pos < response.len() {
        let label_len = response[pos] as usize;
        if label_len == 0 {
            pos += 1; // Root label
            pos += 4; // QTYPE + QCLASS
            break;
        }
        if label_len & 0xC0 == 0xC0 {
            // Compression pointer
            pos += 2;
            pos += 4;
            break;
        }
        pos += 1 + label_len;
    }

    // Parse answer records for TTL
    let mut min_ttl: Option<u64> = None;
    for _ in 0..ancount {
        if pos >= response.len() {
            break;
        }

        // Skip name (handle compression)
        if pos < response.len() && response[pos] & 0xC0 == 0xC0 {
            pos += 2; // Compression pointer
        } else {
            while pos < response.len() {
                let len = response[pos] as usize;
                pos += 1;
                if len == 0 {
                    break;
                }
                pos += len;
            }
        }

        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
        if pos + 10 > response.len() {
            break;
        }

        let ttl = u32::from_be_bytes([
            response[pos + 4],
            response[pos + 5],
            response[pos + 6],
            response[pos + 7],
        ]) as u64;

        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10 + rdlength;

        min_ttl = Some(min_ttl.map_or(ttl, |current| current.min(ttl)));
    }

    min_ttl
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_format() {
        let key = format!("{}:{}", "example.com", 1);
        assert_eq!(key, "example.com:1");
    }

    #[test]
    fn test_extract_ttl_empty() {
        assert_eq!(extract_min_ttl(&[]), None);
        assert_eq!(extract_min_ttl(&[0u8; 12]), None); // ANCOUNT=0
    }
}
