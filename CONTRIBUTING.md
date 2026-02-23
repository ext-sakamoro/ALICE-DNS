# Contributing to ALICE-DNS

## Build

```bash
cargo build
```

## Test

```bash
cargo test
```

## Lint

```bash
cargo clippy -- -W clippy::all
cargo fmt -- --check
cargo doc --no-deps 2>&1 | grep warning
```

## Design Constraints

- **O(1) domain lookup**: 512KB Bloom filter with HashSet confirmation for zero false-positive blocking.
- **Neutralize mode**: spoof blocked domains to Pi's LAN IP + HTTP null server, bypassing anti-adblock detection.
- **Hot-reload**: SIGHUP reloads blocklist/whitelist with zero downtime; binary filter cache for fast restarts.
- **ALICE-Cache integration**: DNS response cache with Markov-chain prefetch for frequent queries.
- **Minimal dependencies**: only `blake3` (message hashing) and `memmap2` (journal); `rustls` optional for TLS.
