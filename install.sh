#!/bin/bash
# ALICE-DNS Installer for Raspberry Pi
#
# Usage:
#   ./install.sh              # Install and start
#   ./install.sh --uninstall  # Remove and restore Pi-hole
#
# Prerequisites:
#   - alice-dns binary (cross-compiled for aarch64)
#   - Root access (sudo)

set -euo pipefail

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

# Check for binary
if [ ! -f "./target/aarch64-unknown-linux-gnu/release/alice-dns" ] && [ ! -f "./alice-dns" ]; then
    error "alice-dns binary not found."
    echo "  Build with: cargo build --release --target aarch64-unknown-linux-gnu"
    echo "  Or copy the binary to ./alice-dns"
    exit 1
fi

# Determine binary source
if [ -f "./target/aarch64-unknown-linux-gnu/release/alice-dns" ]; then
    BIN_SRC="./target/aarch64-unknown-linux-gnu/release/alice-dns"
else
    BIN_SRC="./alice-dns"
fi

# Create directories
sudo mkdir -p "$ALICE_DNS_DIR"

# Copy binary
info "Installing binary..."
sudo cp "$BIN_SRC" "$ALICE_DNS_BIN"
sudo chmod 755 "$ALICE_DNS_BIN"

# Copy update script
info "Installing update script..."
sudo cp update-blocklist.py "$UPDATE_SCRIPT"
sudo chmod 755 "$UPDATE_SCRIPT"

# Download initial blocklist
info "Downloading initial blocklist..."
sudo python3 "$UPDATE_SCRIPT"

# Create systemd service
info "Creating systemd service..."
sudo tee "$SYSTEMD_SERVICE" > /dev/null << 'SYSTEMD_EOF'
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
info "Creating cron job..."
sudo tee "$CRON_FILE" > /dev/null << 'CRON_EOF'
# ALICE-DNS blocklist update — daily at 3:00 AM
0 3 * * * root /usr/bin/python3 /etc/alice-dns/update-blocklist.py >> /etc/alice-dns/update.log 2>&1
CRON_EOF

# Stop Pi-hole
info "Stopping Pi-hole..."
sudo systemctl stop pihole-FTL 2>/dev/null || true
sudo systemctl disable pihole-FTL 2>/dev/null || true
warn "Pi-hole disabled. To restore: ./install.sh --uninstall"

# Start ALICE-DNS
info "Starting ALICE-DNS..."
sudo systemctl daemon-reload
sudo systemctl enable alice-dns
sudo systemctl start alice-dns

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
    echo "│   ./install.sh --uninstall       # Restore Pi-hole"
    echo "└─────────────────────────────────────────────┘"
else
    error "ALICE-DNS failed to start!"
    sudo systemctl status alice-dns --no-pager
    exit 1
fi
