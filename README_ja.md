# ALICE-DNS

**Bloom Filter DNS 広告ブロッカー — 453KB で Pi-hole を置き換え**

[English README](README.md)

ALICE-DNS は Raspberry Pi 向けの超軽量 DNS 広告ブロッカーです。Pi-hole を単一の Rust バイナリで置き換えます。512KB の Bloom Filter による O(1) ドメイン検索と、ALICE-Cache によるインテリジェントな DNS レスポンスキャッシュを備えています。

## アーキテクチャ

```
                         ALICE-DNS (453KB バイナリ, 15MB RSS)
 ┌──────────────────────────────────────────────────────────────────┐
 │                                                                  │
 │  [Client]──UDP:53──▶[DNS Parser]──▶[Bloom Filter 512KB]         │
 │                          │              │           │            │
 │                          │         HIT (O(1))   MISS            │
 │                          │              │           │            │
 │                          │         [HashSet]    [ALICE-Cache]    │
 │                          │          確認判定     256-shard        │
 │                          │           │  │       Markov 先読み    │
 │                          │        BLOCK ALLOW       │            │
 │                          │           │    │    HIT  │  MISS      │
 │                          ▼           ▼    │     │   │    │       │
 │                     [Response]   0.0.0.0  │  cached │ [Upstream] │
 │                                           │         │ 1.1.1.1   │
 │                                           └─────────┘ 8.8.8.8   │
 └──────────────────────────────────────────────────────────────────┘

 ┌──────────────────────────────────────────────────────────────────┐
 │  update-blocklist.py (cron, 毎日 3:00 AM)                       │
 │  StevenBlack/hosts ダウンロード → 解析 → SIGHUP → ホットリロード  │
 └──────────────────────────────────────────────────────────────────┘
```

## ベンチマーク: Pi-hole vs ALICE-DNS (実機計測)

Raspberry Pi 5 での実測値（2026-02-16）。Pi-hole v6.3 (FTL v6.4.1) を ALICE-DNS で置き換えた結果です。

**計測環境:**

| 項目 | 詳細 |
|------|------|
| ハードウェア | Raspberry Pi 5 (Cortex-A76 クアッドコア, 16GB RAM) |
| ストレージ | 128GB microSD (SD128) |
| OS | Raspberry Pi OS (Debian Bookworm, aarch64) |
| カーネル | Linux 6.12.25 |
| 置き換え対象 | Pi-hole v6.3 / FTL v6.4.1 |
| ブロックリスト | StevenBlack/hosts (unified hosts) |

**比較結果:**

| 指標 | Pi-hole FTL | ALICE-DNS | 改善 |
|------|------------|-----------|------|
| **バイナリサイズ** | ~15 MB | **453 KB** | 33倍小さい |
| **メモリ (RSS)** | 43 MB | **15 MB** | 2.9倍削減 |
| **ブロックドメイン数** | 79,078 | **79,078** | 同等 |
| **ドメイン検索** | SQLite SELECT | **O(1) Bloom** | 定数時間 |
| **DNSキャッシュ** | dnsmasq 内蔵 | **ALICE-Cache** | Markov 先読み |
| **Bloom Filter サイズ** | N/A | **512 KB** | 偽陽性率 <0.01% |
| **依存関係** | C + SQLite + PHP + lighttpd | **Rust のみ** | ランタイム依存ゼロ |
| **ビルド時間 (Pi 5)** | N/A | **19秒** | ソースから |

### テスト結果 (Raspberry Pi 5 実測)

ポート53で稼働中の ALICE-DNS に対して `dig @127.0.0.1` で計測。

```
doubleclick.net       → 0.0.0.0           (ブロック)
google-analytics.com  → 0.0.0.0           (ブロック)
google.com            → 142.251.169.139   (許可)
github.com            → 20.27.177.113     (許可)
amazon.co.jp          → 18.246.98.187     (許可)
```

## ALICE エコシステム統合

ALICE-DNS は ALICE クレートエコシステムのコンポーネントを再利用しています:

| コンポーネント | 元クレート | 用途 |
|--------------|-----------|------|
| Bloom Filter (FNV-1a, 3-hash) | **ALICE-Browser** `adblock.rs` | O(1) ドメインブロック |
| DNS レスポンスキャッシュ (256-shard) | **ALICE-Cache** | Markov 予測キャッシュ |
| クエリ分析 (HLL, CMS, DDS) | **ALICE-Analytics** (オプション) | ダッシュボード代替 |
| リリースプロファイル (LTO=fat, strip) | ALICE カリカリ最適化 | 453KB バイナリ |

## クイックインストール (Rust不要)

```bash
# ワンライナーでインストール — ビルド済みバイナリをダウンロードして自動設定
curl -fsSL https://raw.githubusercontent.com/ext-sakamoro/ALICE-DNS/main/install.sh | sudo bash
```

手動でインストールする場合:

```bash
# Raspberry Pi (aarch64) 用ビルド済みバイナリをダウンロード
curl -fsSL https://github.com/ext-sakamoro/ALICE-DNS/releases/latest/download/alice-dns-aarch64-linux -o alice-dns
chmod +x alice-dns
sudo ./alice-dns
```

## Raspberry Pi 導入ガイド (ソースからビルド)

Raspberry Pi 上でゼロからビルド・本番投入するまでの完全手順です。Pi 5 で実証済み。

### Step 1: Rust インストール (初回のみ)

```bash
# Rust ツールチェーンのインストール (~2分)
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

# ALICE-Cache は ALICE-DNS と同じ親ディレクトリに配置してください
# ~/ALICE-DNS/
# ~/ALICE-Cache/
```

### Step 3: ビルド

```bash
cd ~/ALICE-DNS
cargo build --release
# Pi 5: 約19秒、Pi 4: 約60秒 (目安)

# 確認
ls -lh target/release/alice-dns
# → 453KB, ELF 64-bit aarch64
```

### Step 4: インストール & Pi-hole 置き換え

```bash
# バイナリを配置
sudo cp target/release/alice-dns /usr/local/bin/
sudo chmod 755 /usr/local/bin/alice-dns

# 設定ディレクトリを作成
sudo mkdir -p /etc/alice-dns

# ブロックリスト更新スクリプトを配置
sudo cp update-blocklist.py /etc/alice-dns/
sudo chmod 755 /etc/alice-dns/update-blocklist.py

# 初回ブロックリストダウンロード (StevenBlack/hosts, 約79,000ドメイン)
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
# ALICE-DNS ブロックリスト更新 — 毎日午前3時
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

## ビルド方法 (その他)

### Raspberry Pi 上でビルド (推奨)

```bash
# Rust インストール (初回のみ)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env

# クローン
git clone https://github.com/ext-sakamoro/ALICE-DNS.git
git clone https://github.com/ext-sakamoro/ALICE-Cache.git

# ビルド (リリース, Pi 5 で約19秒)
cd ALICE-DNS
cargo build --release

# バイナリ: target/release/alice-dns (453KB)
```

### クロスコンパイル (macOS → aarch64 Linux)

```bash
# aarch64-unknown-linux-gnu ツールチェーンまたは Docker が必要
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu

# Pi に転送
scp target/aarch64-unknown-linux-gnu/release/alice-dns pi@raspberrypi:~/
```

## インストール (自動)

```bash
# 自動インストーラー (Pi-hole を停止し、alice-dns を起動)
chmod +x install.sh
./install.sh

# Pi-hole を復元する場合
./install.sh --uninstall
```

## 使い方

```bash
# デフォルト設定で起動 (ポート53, StevenBlack ブロックリスト)
sudo alice-dns

# ポート指定
alice-dns --port 5354

# ブロックリスト指定
alice-dns --blocklist /path/to/hosts

# アップストリーム DNS 指定
alice-dns --upstream 9.9.9.9,1.0.0.1

# シグナル
kill -HUP  $(pgrep alice-dns)   # ブロックリスト再読み込み (ゼロダウンタイム)
kill -USR1 $(pgrep alice-dns)   # 統計情報を表示
kill -TERM $(pgrep alice-dns)   # 安全なシャットダウン
```

### systemd 操作

```bash
sudo systemctl start alice-dns
sudo systemctl stop alice-dns
sudo systemctl reload alice-dns    # SIGHUP → ブロックリスト ホットリロード
sudo systemctl status alice-dns
journalctl -u alice-dns -f         # ライブログ
```

## ブロックリスト更新

`update-blocklist.py` は cron で毎日午前3時に自動実行されます:

```bash
# 手動更新
sudo python3 /etc/alice-dns/update-blocklist.py

# cron 設定 (install.sh により自動設定済み)
# 0 3 * * * root /usr/bin/python3 /etc/alice-dns/update-blocklist.py
```

StevenBlack/hosts 形式（Pi-hole のデフォルトと同一）に対応。追加リストはスクリプト内の `BLOCKLIST_URLS` を編集して設定できます。

## プロジェクト構成

```
ALICE-DNS/
├── Cargo.toml              # 依存関係: alice-cache, カリカリ リリースプロファイル
├── src/
│   ├── lib.rs              # コアライブラリ エクスポート
│   ├── main.rs             # DNS サーバー (UDP:53, シグナルハンドラ)
│   ├── bloom.rs            # 512KB Bloom Filter (ALICE-Browser から移植)
│   ├── dns.rs              # DNS パケットパーサー & レスポンスビルダー (RFC 1035)
│   ├── upstream.rs         # アップストリーム転送 + ALICE-Cache
│   ├── blocklist.rs        # StevenBlack/hosts 形式パーサー
│   └── stats.rs            # クエリ統計 (オプション: ALICE-Analytics)
├── update-blocklist.py     # cron ブロックリスト更新スクリプト (Python)
├── install.sh              # Raspberry Pi インストーラー
├── README.md               # 英語版
└── README_ja.md            # 日本語版 (本ファイル)
```

## Bloom Filter の仕組み

```
 79,078 ドメイン → bloom_hash() FNV-1a → ドメインあたり3ビット位置
                                         │
                              ┌──────────┘
                              ▼
 ┌────────────────────────────────────────────────┐
 │  Bloom Filter: 512KB (4,194,304 ビット)         │
 │  [0100101001...01101001010...10010110010...]    │
 │                                                 │
 │  bloom_test(domain):                            │
 │    h1 = hash & 0x3FFFFF        → ビット確認     │
 │    h2 = (hash >> 16) & 0x3FFFFF → ビット確認    │
 │    h3 = (hash >> 32) & 0x3FFFFF → ビット確認    │
 │    return h1 AND h2 AND h3  (ブランチレス)       │
 │                                                 │
 │  偽陽性率: < 0.01%                               │
 │  偽陰性率: 0% (保証)                             │
 └────────────────────────────────────────────────┘
                              │
                    HIT?──────┤
                    │         │
                    ▼         ▼
               [HashSet]    MISS → アップストリームに転送
               厳密確認
               (偽陽性を
                排除)
```

## ライセンス

MIT

## 作者

Moroya Sakamoto
