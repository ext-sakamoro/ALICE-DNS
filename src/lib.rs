//! # ALICE-DNS — Bloom Filter DNS Ad-Blocker
//!
//! Lightweight Pi-hole replacement for Raspberry Pi.
//!
//! ## Architecture
//!
//! ```text
//! [Client] → UDP:53 → [ALICE-DNS]
//!                          │
//!                          ├── Bloom Filter O(1) → BLOCKED → 0.0.0.0
//!                          │
//!                          └── MISS → [ALICE-Cache] → HIT → cached response
//!                                          │
//!                                          └── MISS → [Upstream 1.1.1.1/8.8.8.8]
//! ```
//!
//! ## Components
//!
//! - **bloom**: 512KB Bloom Filter + HashSet (79K domains, <0.01% FP)
//! - **dns**: DNS packet parser & response builder (RFC 1035)
//! - **upstream**: Upstream forwarding with ALICE-Cache (Markov prefetch)
//! - **blocklist**: StevenBlack/hosts format parser
//! - **stats**: Query statistics (optional ALICE-Analytics)
//!
//! ## ALICE Ecosystem Integration
//!
//! | Component | From | Purpose |
//! |-----------|------|---------|
//! | Bloom Filter | ALICE-Browser `adblock.rs` | O(1) domain lookup |
//! | DNS Cache | ALICE-Cache | 256-shard, Markov prefetch |
//! | Analytics | ALICE-Analytics (optional) | HLL, CMS, DDSketch |

extern crate alloc;

pub mod bloom;
pub mod blocklist;
pub mod dns;
pub mod stats;
pub mod upstream;

// Re-exports
pub use bloom::DnsBloomEngine;
pub use blocklist::parse_hosts;
pub use dns::{parse_query, build_blocked_response, build_nxdomain_response, DnsQuery};
pub use stats::DnsStats;
pub use upstream::UpstreamForwarder;

/// ALICE-DNS version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
