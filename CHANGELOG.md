# Changelog

All notable changes to ALICE-DNS will be documented in this file.

## [0.1.0] - 2026-02-23

### Added
- `bloom` — `DnsBloomEngine` with 512KB Bloom filter + HashSet confirmation, `DnsAction` (Block/Allow/Spoof), whitelist, binary hot-reload
- `dns` — RFC 1035 DNS packet parser (`parse_query`), `build_blocked_response`, `build_spoof_response`, `build_nxdomain_response`
- `upstream` — `UpstreamForwarder` with ALICE-Cache integration (Markov prefetch), multi-resolver failover
- `blocklist` — StevenBlack/hosts format parser (`parse_hosts`)
- `stats` — `DnsStats` with optional ALICE-Analytics (HLL, CMS, DDSketch)
- `nullserver` — HTTP/HTTPS null server for ad neutralization (transparent GIF, empty JS/CSS/JSON)
- `AliceQueue`-style integrated pipeline: Bloom → Cache → Upstream
- Signal handling (SIGHUP reload, SIGUSR1 stats, SIGTERM stop)
- 50 unit tests

### Fixed
- Missing `Default` impl for `DnsBloomEngine` and `DnsStats` (clippy)
- `if let Ok(stream)` → `.flatten()` in nullserver (clippy)
- `% N == 0` → `.is_multiple_of(N)` in main (clippy)
- Complex type in signal handler → type alias (clippy)
