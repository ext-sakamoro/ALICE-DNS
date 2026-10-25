# Changelog

All notable changes to ALICE-DNS will be documented in this file.

## [Unreleased]

### 破壊的変更

- `--spoof-ip` に既定値が無くなった neutralize mode、または blocklist と whitelist の両方にある domain (spoof で応答する domain) があるのに `--spoof-ip` が無いと、flag を名指しする error で起動しない (SIGHUP の reload も同じ条件で拒否し、元の list のまま動く) 以前は固定の LAN 内 address を既定で返していた

### Changed

- `alice-sign` の git rev を 8a1b00d に上げた (HMAC-SHA256 の追加のみ、使っている API と byte 列は同じ)
- Ed25519 の署名・検証を `alice-blockchain` から `alice-sign` (MIT OR Apache-2.0、公開) に移した 鍵・署名の byte 列は同じ (`alice-sign` の golden で固定) `alice-blockchain` への依存は無くなった
- Licence: `MIT` → `LicenseRef-Proprietary`

### Fixed
- feature `analytics` が compile できなかった (`alice-analytics` の依存が無かった) `alice-analytics` (git rev) を optional で引き、`DnsStats::unique_domains` / `blocked_estimate` / `latency_quantile` を足した この feature の下では `DnsStats::new` / `record_query` は const ではない

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
