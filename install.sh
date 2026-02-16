#!/bin/bash
# ALICE-DNS Installer for Raspberry Pi
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/ext-sakamoro/ALICE-DNS/main/install.sh | sudo bash
#   ./install.sh              # Install and start
#   ./install.sh --uninstall  # Remove and restore Pi-hole
#
# No Rust toolchain required — downloads pre-built binary from GitHub Releases.

set -euo pipefail

REPO="ext-sakamoro/ALICE-DNS"
ALICE_DNS_BIN="/usr/local/bin/alice-dns"
ALICE_DNS_DIR="/etc/alice-dns"
SYSTEMD_SERVICE="/etc/systemd/system/alice-dns.service"
UPDATE_SCRIPT="${ALICE_DNS_DIR}/update-blocklist.py"
CRON_FILE="/etc/cron.d/alice-dns"

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ── Detect architecture ──
detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        aarch64|arm64) echo "aarch64-linux" ;;
        x86_64)        echo "x86_64-linux" ;;
        *)
            error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
}

# ── Uninstall ──

if [ "${1:-}" = "--uninstall" ]; then
    info "Uninstalling ALICE-DNS..."

    sudo systemctl stop alice-dns 2>/dev/null || true
    sudo systemctl disable alice-dns 2>/dev/null || true
    sudo rm -f "$SYSTEMD_SERVICE"
    sudo rm -f "$CRON_FILE"
    sudo rm -f "$ALICE_DNS_BIN"

    info "Restoring Pi-hole..."
    sudo systemctl enable pihole-FTL 2>/dev/null || true
    sudo systemctl start pihole-FTL 2>/dev/null || true

    info "ALICE-DNS uninstalled. Pi-hole restored."
    exit 0
fi

# ── Install ──

info "Installing ALICE-DNS..."

# Check root
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root (use sudo)"
    exit 1
fi

# Create directories
mkdir -p "$ALICE_DNS_DIR"

# Download or use local binary
if [ -f "./alice-dns" ]; then
    info "Using local binary: ./alice-dns"
    BIN_SRC="./alice-dns"
elif [ -f "./target/release/alice-dns" ]; then
    info "Using locally built binary"
    BIN_SRC="./target/release/alice-dns"
else
    ARCH=$(detect_arch)
    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/alice-dns-${ARCH}"
    info "Downloading pre-built binary for ${ARCH}..."
    if command -v curl &>/dev/null; then
        curl -fsSL "$DOWNLOAD_URL" -o /tmp/alice-dns
    elif command -v wget &>/dev/null; then
        wget -q "$DOWNLOAD_URL" -O /tmp/alice-dns
    else
        error "curl or wget is required"
        exit 1
    fi
    BIN_SRC="/tmp/alice-dns"
fi

# Install binary
info "Installing binary to ${ALICE_DNS_BIN}..."
cp "$BIN_SRC" "$ALICE_DNS_BIN"
chmod 755 "$ALICE_DNS_BIN"

# Download update script
if [ -f "./update-blocklist.py" ]; then
    cp ./update-blocklist.py "$UPDATE_SCRIPT"
else
    info "Downloading blocklist update script..."
    curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/update-blocklist.py" -o "$UPDATE_SCRIPT"
fi
chmod 755 "$UPDATE_SCRIPT"

# Download initial blocklist
info "Downloading initial blocklist (StevenBlack/hosts, ~79K domains)..."
python3 "$UPDATE_SCRIPT"

# Create systemd service
info "Creating systemd service..."
tee "$SYSTEMD_SERVICE" > /dev/null << 'SYSTEMD_EOF'
[Unit]
Description=ALICE-DNS — Bloom Filter DNS Ad-Blocker
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/ext-sakamoro/ALICE-DNS

[Service]
Type=simple
ExecStart=/usr/local/bin/alice-dns --blocklist /etc/alice-dns/blocklist.hosts
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

# Security hardening
User=root
Group=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/alice-dns
PrivateTmp=true

# Resource limits
LimitNOFILE=65536
MemoryMax=64M

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

# Create cron job for blocklist updates
info "Creating cron job (daily 3:00 AM)..."
tee "$CRON_FILE" > /dev/null << 'CRON_EOF'
# ALICE-DNS blocklist update — daily at 3:00 AM
0 3 * * * root /usr/bin/python3 /etc/alice-dns/update-blocklist.py >> /etc/alice-dns/update.log 2>&1
CRON_EOF

# Stop Pi-hole
if systemctl is-active --quiet pihole-FTL 2>/dev/null; then
    info "Stopping Pi-hole..."
    systemctl stop pihole-FTL
    systemctl disable pihole-FTL
    warn "Pi-hole disabled. To restore: install.sh --uninstall"
fi

# Start ALICE-DNS
info "Starting ALICE-DNS..."
systemctl daemon-reload
systemctl enable alice-dns
systemctl start alice-dns

# Verify
sleep 1
if systemctl is-active --quiet alice-dns; then
    info "ALICE-DNS is running!"
    echo ""
    echo "┌─────────────────────────────────────────────┐"
    echo "│         ALICE-DNS Installed                  │"
    echo "├─────────────────────────────────────────────┤"
    echo "│ Binary:    $ALICE_DNS_BIN"
    echo "│ Config:    $ALICE_DNS_DIR/"
    echo "│ Service:   alice-dns.service"
    echo "│ Cron:      Daily 3:00 AM blocklist update"
    echo "│"
    echo "│ Commands:"
    echo "│   systemctl status alice-dns"
    echo "│   systemctl reload alice-dns     # Reload blocklist"
    echo "│   kill -USR1 \$(pgrep alice-dns)  # Print stats"
    echo "│   install.sh --uninstall         # Restore Pi-hole"
    echo "│"
    echo "│ Test:"
    echo "│   dig @127.0.0.1 doubleclick.net A +short"
    echo "│   # → 0.0.0.0 (blocked)"
    echo "└─────────────────────────────────────────────┘"
else
    error "ALICE-DNS failed to start!"
    systemctl status alice-dns --no-pager
    exit 1
fi
