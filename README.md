# ALICE-DNS

**Bloom Filter DNS Ad-Blocker — Pi-hole replacement in 453KB**

ALICE-DNS is an ultra-lightweight DNS ad-blocker for Raspberry Pi that replaces Pi-hole with a single Rust binary. It uses a 512KB Bloom filter for O(1) domain lookup, backed by ALICE-Cache for intelligent DNS response caching.

## Architecture

```
                         ALICE-DNS (453KB binary, 15MB RSS)
 ┌──────────────────────────────────────────────────────────────────┐
 │                                                                  │
 │  [Client]──UDP:53──▶[DNS Parser]──▶[Bloom Filter 512KB]         │
 │                          │              │           │            │
 │                          │         HIT (O(1))   MISS            │
 │                          │              │           │            │
 │                          │         [HashSet]    [ALICE-Cache]    │
 │                          │          confirm     256-shard        │
 │                          │           │  │       Markov prefetch  │
 │                          │        BLOCK ALLOW       │            │
 │                          │           │    │    HIT  │  MISS      │
 │                          ▼           ▼    │     │   │    │       │
 │                     [Response]   0.0.0.0  │  cached │ [Upstream] │
 │                                           │         │ 1.1.1.1   │
 │                                           └─────────┘ 8.8.8.8   │
 └──────────────────────────────────────────────────────────────────┘

 ┌──────────────────────────────────────────────────────────────────┐
 │  update-blocklist.py (cron, daily 3:00 AM)                      │
 │  StevenBlack/hosts download → parse → SIGHUP → hot-reload       │
 └──────────────────────────────────────────────────────────────────┘
```

## Benchmark: Pi-hole vs ALICE-DNS (実機計測)

Raspberry Pi 5 での実測値（2026-02-16）。Pi-hole v6.3 (FTL v6.4.1) を ALICE-DNS で置き換えた結果。

**計測環境:**

| Item | Detail |
|------|--------|
| Hardware | Raspberry Pi 5 (Cortex-A76 quad-core, 16GB RAM) |
| Storage | 128GB microSD (SD128) |
| OS | Raspberry Pi OS (Debian Bookworm, aarch64) |
| Kernel | Linux 6.12.25 |
| Replaced | Pi-hole v6.3 / FTL v6.4.1 |
| Blocklist | StevenBlack/hosts (unified hosts) |

**比較結果:**

| Metric | Pi-hole FTL | ALICE-DNS | Improvement |
|--------|------------|-----------|-------------|
| **Binary size** | ~15 MB | **453 KB** | 33x smaller |
| **Memory (RSS)** | 43 MB | **15 MB** | 2.9x less |
| **Blocked domains** | 79,078 | **79,078** | Equivalent |
| **Domain lookup** | SQLite SELECT | **O(1) Bloom** | Constant time |
| **DNS cache** | dnsmasq built-in | **ALICE-Cache** | Markov prefetch |
| **Bloom filter size** | N/A | **512 KB** | <0.01% FP rate |
| **Dependencies** | C + SQLite + PHP + lighttpd | **Rust only** | Zero runtime deps |
| **Build time (Pi 5)** | N/A | **19 sec** | From source |

### Test Results (Raspberry Pi 5 実測)

ポート53で稼働中の ALICE-DNS に対して `dig @127.0.0.1` で計測。

```
doubleclick.net       → 0.0.0.0           (BLOCKED)
google-analytics.com  → 0.0.0.0           (BLOCKED)
google.com            → 142.251.169.139   (ALLOWED)
github.com            → 20.27.177.113     (ALLOWED)
amazon.co.jp          → 18.246.98.187     (ALLOWED)
```

## ALICE Ecosystem Integration

ALICE-DNS reuses components from the ALICE crate ecosystem:

| Component | Source Crate | Usage |
|-----------|-------------|-------|
| Bloom Filter (FNV-1a, 3-hash) | **ALICE-Browser** `adblock.rs` | O(1) domain blocking |
| DNS Response Cache (256-shard) | **ALICE-Cache** | Markov predictive caching |
| Query Analytics (HLL, CMS, DDS) | **ALICE-Analytics** (optional) | Dashboard replacement |
| Release Profile (LTO=fat, strip) | ALICE カリカリ methodology | 453KB binary |

## Raspberry Pi 導入ガイド (Step by Step)

Raspberry Pi 上でゼロからビルド・本番投入するまでの手順。Pi 5 で実証済み。

### Step 1: Rust インストール (初回のみ)

```bash
# Rust toolchain インストール (~2分)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env

# 確認
rustc --version   # rustc 1.93.1 以上
cargo --version
```

### Step 2: ソース取得

```bash
git clone https://github.com/ext-sakamoro/ALICE-DNS.git
git clone https://github.com/ext-sakamoro/ALICE-Cache.git

# ALICE-Cache は ALICE-DNS と同じ階層に配置
# ~/ALICE-DNS/
# ~/ALICE-Cache/
```

### Step 3: ビルド

```bash
cd ~/ALICE-DNS
cargo build --release
# Pi 5: ~19秒、Pi 4: ~60秒 (目安)

# 確認
ls -lh target/release/alice-dns
# → 453KB, ELF 64-bit aarch64
```

### Step 4: インストール & Pi-hole 置き換え

```bash
# バイナリ配置
sudo cp target/release/alice-dns /usr/local/bin/
sudo chmod 755 /usr/local/bin/alice-dns

# 設定ディレクトリ作成
sudo mkdir -p /etc/alice-dns

# ブロックリスト更新スクリプト配置
sudo cp update-blocklist.py /etc/alice-dns/
sudo chmod 755 /etc/alice-dns/update-blocklist.py

# 初回ブロックリストダウンロード (StevenBlack/hosts, ~79K domains)
sudo python3 /etc/alice-dns/update-blocklist.py
```

### Step 5: systemd サービス登録

```bash
sudo tee /etc/systemd/system/alice-dns.service > /dev/null << 'EOF'
[Unit]
Description=ALICE-DNS — Bloom Filter DNS Ad-Blocker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/alice-dns --blocklist /etc/alice-dns/blocklist.hosts
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
User=root
Group=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/alice-dns
PrivateTmp=true
LimitNOFILE=65536
MemoryMax=64M

[Install]
WantedBy=multi-user.target
EOF
```

### Step 6: ブロックリスト自動更新 (cron)

```bash
sudo tee /etc/cron.d/alice-dns > /dev/null << 'EOF'
# ALICE-DNS blocklist update — daily at 3:00 AM
0 3 * * * root /usr/bin/python3 /etc/alice-dns/update-blocklist.py >> /etc/alice-dns/update.log 2>&1
EOF
```

### Step 7: Pi-hole 停止 → ALICE-DNS 起動

```bash
# Pi-hole を停止・無効化
sudo systemctl stop pihole-FTL
sudo systemctl disable pihole-FTL

# ALICE-DNS を起動・有効化
sudo systemctl daemon-reload
sudo systemctl enable alice-dns
sudo systemctl start alice-dns

# 動作確認
sudo systemctl status alice-dns
```

### Step 8: DNS 動作テスト

```bash
# ブロック対象 → 0.0.0.0 が返る
dig @127.0.0.1 doubleclick.net A +short
# → 0.0.0.0

dig @127.0.0.1 google-analytics.com A +short
# → 0.0.0.0

# 通常ドメイン → 正常に解決される
dig @127.0.0.1 google.com A +short
# → 142.251.x.x

dig @127.0.0.1 github.com A +short
# → 20.27.177.113
```

### Pi-hole に戻す場合

```bash
sudo systemctl stop alice-dns
sudo systemctl disable alice-dns
sudo systemctl enable pihole-FTL
sudo systemctl start pihole-FTL
```

## Build (その他の方法)

### On Raspberry Pi (recommended)

```bash
# Install Rust (one-time)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env

# Clone
git clone https://github.com/ext-sakamoro/ALICE-DNS.git
git clone https://github.com/ext-sakamoro/ALICE-Cache.git

# Build (release, ~19 sec on Pi 5)
cd ALICE-DNS
cargo build --release

# Binary at: target/release/alice-dns (453KB)
```

### Cross-compile (macOS → aarch64 Linux)

```bash
# Requires aarch64-unknown-linux-gnu toolchain or Docker
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu

# Transfer to Pi
scp target/aarch64-unknown-linux-gnu/release/alice-dns pi@raspberrypi:~/
```

## Install (Automated)

```bash
# Automated installer (stops Pi-hole, starts alice-dns)
chmod +x install.sh
./install.sh

# To restore Pi-hole
./install.sh --uninstall
```

## Usage

```bash
# Start with defaults (port 53, StevenBlack blocklist)
sudo alice-dns

# Custom port
alice-dns --port 5354

# Custom blocklist
alice-dns --blocklist /path/to/hosts

# Custom upstream DNS
alice-dns --upstream 9.9.9.9,1.0.0.1

# Signals
kill -HUP  $(pgrep alice-dns)   # Reload blocklist (zero downtime)
kill -USR1 $(pgrep alice-dns)   # Print statistics
kill -TERM $(pgrep alice-dns)   # Graceful shutdown
```

### systemd

```bash
sudo systemctl start alice-dns
sudo systemctl stop alice-dns
sudo systemctl reload alice-dns    # SIGHUP → hot-reload blocklist
sudo systemctl status alice-dns
journalctl -u alice-dns -f         # Live logs
```

## Blocklist Updates

`update-blocklist.py` runs via cron daily at 3:00 AM:

```bash
# Manual update
sudo python3 /etc/alice-dns/update-blocklist.py

# Cron (installed automatically by install.sh)
# 0 3 * * * root /usr/bin/python3 /etc/alice-dns/update-blocklist.py
```

Supports StevenBlack/hosts format (same as Pi-hole default). Additional lists can be added by editing `BLOCKLIST_URLS` in the script.

## Project Structure

```
ALICE-DNS/
├── Cargo.toml              # Dependencies: alice-cache, カリカリ release profile
├── src/
│   ├── lib.rs              # Core library exports
│   ├── main.rs             # DNS server (UDP:53, signal handlers)
│   ├── bloom.rs            # 512KB Bloom Filter (ported from ALICE-Browser)
│   ├── dns.rs              # DNS packet parser & response builder (RFC 1035)
│   ├── upstream.rs         # Upstream forwarding + ALICE-Cache
│   ├── blocklist.rs        # StevenBlack/hosts format parser
│   └── stats.rs            # Query statistics (optional: ALICE-Analytics)
├── update-blocklist.py     # Cron blocklist updater (Python)
├── install.sh              # Raspberry Pi installer
└── README.md
```

## How the Bloom Filter Works

```
 79,078 domains → bloom_hash() FNV-1a → 3 bit positions per domain
                                         │
                              ┌──────────┘
                              ▼
 ┌────────────────────────────────────────────────┐
 │  Bloom Filter: 512KB (4,194,304 bits)          │
 │  [0100101001...01101001010...10010110010...]    │
 │                                                 │
 │  bloom_test(domain):                            │
 │    h1 = hash & 0x3FFFFF        → check bit     │
 │    h2 = (hash >> 16) & 0x3FFFFF → check bit    │
 │    h3 = (hash >> 32) & 0x3FFFFF → check bit    │
 │    return h1 AND h2 AND h3  (branchless)        │
 │                                                 │
 │  False positive rate: < 0.01%                   │
 │  False negative rate: 0% (guaranteed)           │
 └────────────────────────────────────────────────┘
                              │
                    HIT?──────┤
                    │         │
                    ▼         ▼
               [HashSet]    MISS → forward to upstream
               exact check
               (confirm or
                reject FP)
```

## License

MIT

## Author

Moroya Sakamoto
