#!/usr/bin/env python3
"""
ALICE-DNS Blocklist Updater

Downloads StevenBlack/hosts blocklist and prepares it for alice-dns.
Run via cron: 0 3 * * * /usr/bin/python3 /etc/alice-dns/update-blocklist.py

Replaces Pi-hole's gravity update with a single Python script.
"""

import os
import sys
import signal
import hashlib
import urllib.request
import subprocess
from datetime import datetime
from pathlib import Path

# ── Configuration ──

BLOCKLIST_URLS = [
    # StevenBlack unified hosts (same as current Pi-hole config)
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]

# Additional lists (uncomment to enable)
# BLOCKLIST_URLS += [
#     "https://adaway.org/hosts.txt",
#     "https://v.firebog.net/hosts/AdguardDNS.txt",
#     "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
# ]

ALICE_DNS_DIR = Path("/etc/alice-dns")
BLOCKLIST_PATH = ALICE_DNS_DIR / "blocklist.hosts"
FILTER_BIN_PATH = ALICE_DNS_DIR / "filter.bin"
LOG_PATH = ALICE_DNS_DIR / "update.log"
ALICE_DNS_PID_PATH = Path("/run/alice-dns.pid")

# ── Logging ──

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line)
    try:
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass

# ── Download ──

def download_blocklist(url, timeout=30):
    """Download a blocklist URL, return content as string."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "ALICE-DNS/0.1.0 Blocklist-Updater",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        log(f"  Error downloading {url}: {e}")
        return None

# ── Parse ──

def parse_hosts(content):
    """Parse hosts-format content into set of domains."""
    domains = set()
    skip = {
        "localhost", "localhost.localdomain", "local", "broadcasthost",
        "ip6-localhost", "ip6-loopback", "ip6-localnet",
        "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
        "ip6-allhosts", "0.0.0.0",
    }

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue

        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            domain = parts[1].strip().lower()
        elif len(parts) == 1 and "." in parts[0]:
            domain = parts[0].strip().lower()
        else:
            continue

        if domain and domain not in skip and "." in domain and len(domain) <= 253:
            domains.add(domain)

    return domains

# ── Main ──

def main():
    log("ALICE-DNS blocklist update started")

    # Ensure directory exists
    ALICE_DNS_DIR.mkdir(parents=True, exist_ok=True)

    # Download all lists
    all_domains = set()
    for url in BLOCKLIST_URLS:
        log(f"  Downloading: {url}")
        content = download_blocklist(url)
        if content:
            domains = parse_hosts(content)
            log(f"  Parsed: {len(domains)} domains")
            all_domains.update(domains)
        else:
            log(f"  FAILED: {url}")

    if not all_domains:
        log("ERROR: No domains downloaded. Keeping existing blocklist.")
        sys.exit(1)

    # Sort for deterministic output
    sorted_domains = sorted(all_domains)

    # Write hosts-format blocklist
    log(f"  Writing {len(sorted_domains)} domains to {BLOCKLIST_PATH}")
    content = (
        f"# ALICE-DNS Blocklist\n"
        f"# Updated: {datetime.now().isoformat()}\n"
        f"# Sources: {len(BLOCKLIST_URLS)} lists\n"
        f"# Domains: {len(sorted_domains)}\n"
        f"#\n"
    )
    for domain in sorted_domains:
        content += f"0.0.0.0 {domain}\n"

    # Atomic write (write to temp, then rename)
    tmp_path = BLOCKLIST_PATH.with_suffix(".tmp")
    with open(tmp_path, "w") as f:
        f.write(content)
    os.replace(tmp_path, BLOCKLIST_PATH)

    # Remove old binary filter (alice-dns will regenerate on reload)
    if FILTER_BIN_PATH.exists():
        FILTER_BIN_PATH.unlink()
        log("  Removed old binary filter (will be regenerated)")

    # Calculate checksum
    sha256 = hashlib.sha256(content.encode()).hexdigest()[:16]
    log(f"  Checksum: {sha256}")

    # Signal alice-dns to reload (SIGHUP)
    pid = get_alice_dns_pid()
    if pid:
        try:
            os.kill(pid, signal.SIGHUP)
            log(f"  Sent SIGHUP to alice-dns (PID {pid})")
        except OSError as e:
            log(f"  Warning: Could not signal alice-dns: {e}")
    else:
        log("  alice-dns not running (no PID file)")

    log(f"Update complete: {len(sorted_domains)} domains")

def get_alice_dns_pid():
    """Get alice-dns PID from pidfile or pgrep."""
    # Try pidfile
    if ALICE_DNS_PID_PATH.exists():
        try:
            pid = int(ALICE_DNS_PID_PATH.read_text().strip())
            # Verify process exists
            os.kill(pid, 0)
            return pid
        except (ValueError, OSError):
            pass

    # Try pgrep
    try:
        result = subprocess.run(
            ["pgrep", "-f", "alice-dns"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            pids = result.stdout.strip().split("\n")
            if pids and pids[0]:
                return int(pids[0])
    except (subprocess.SubprocessError, ValueError):
        pass

    return None

if __name__ == "__main__":
    main()
