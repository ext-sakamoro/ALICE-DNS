# Changelog

All notable changes to ALICE-DNS will be documented in this file.

## [Unreleased]

### Changed
- **License: `AGPL-3.0` → `AGPL-3.0 OR LicenseRef-Commercial` (dual-licensed、2026-09-27)** AGPL 側の条件は変更なし (既存 AGPL 利用者への影響ゼロ)、商用という選択肢が追加されただけ SPDX が AGPL 単独だと cargo-deny / FOSSA / SBOM に「商用オプションなし」と見えるため宣言を dual に 変更点: SPDX / `LICENSE` → `LICENSE-AGPL` / `LICENSE-COMMERCIAL.md` (商用トリガー 6 条件 = クローズド製品・商用 SaaS・エッジ / ファームウェア配布・plugin 再配布・プラットフォーム NDA・保証、社内利用は AGPL 側で無償と明記) / README の選択肢表 商用窓口は法人 `contact@extoria.co.jp`

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
