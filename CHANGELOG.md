# Changelog

All notable changes to ALICE-DNS will be documented in this file.

## [Unreleased]

### Behavior change
- `--spoof-ip` に固定の既定値が無くなった 指定しない時は、上流の resolver へ向かう経路の自機の IPv4 を起動時に求める (UDP の connect と local_addr で、packet は送らない) 求められない時 (経路が無い / loopback だけ) は理由を出して起動を止める 影響を受けるのは `--spoof-ip` を指定せずに起動していた利用者で、spoof の応答がこれまでの固定値から自機の address に変わる
- `--spoof-ip` の値が IPv4 でない時は起動を止める (これまでは黙って無視していた)

### Added
- `spoof_ip` module (`parse` / `usable` / `local_ipv4_toward` / `resolve`) と、その試験 9 本 (書式、使えない address の拒否、loopback の resolver、経路の無い入力、指定値の優先、上流が無い時、失敗の報告順)

### Changed
- Ed25519 の署名・検証を `alice-blockchain` から `alice-sign` (MIT OR Apache-2.0、公開) に移した 鍵・署名の byte 列は同じ (`alice-sign` の golden で固定) `alice-blockchain` への依存は無くなった
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
