//! ALICE-DNS — Bloom Filter DNS Ad-Blocker for Raspberry Pi
//!
//! Replaces Pi-hole with a 2MB Rust binary.
//!
//! Usage:
//!   alice-dns                          # Start with default blocklist
//!   alice-dns --blocklist /path/to/hosts  # Custom blocklist
//!   alice-dns --port 5353              # Custom listen port
//!   alice-dns --upstream 9.9.9.9:53   # Custom upstream DNS

use std::net::UdpSocket;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use alice_dns::{
    DnsBloomEngine, DnsAction, DnsStats, UpstreamForwarder, NullServer,
    blocklist, dns, upstream::UpstreamResolver,
};

/// Default blocklist path.
const DEFAULT_BLOCKLIST: &str = "/etc/alice-dns/blocklist.hosts";
/// Default binary filter path (for hot-reload).
const DEFAULT_FILTER_BIN: &str = "/etc/alice-dns/filter.bin";
/// Default listen address.
const DEFAULT_LISTEN: &str = "0.0.0.0:53";
/// Maximum UDP packet size (4096 for EDNS support).
const MAX_PACKET_SIZE: usize = 4096;
/// Stats print interval (queries).
const STATS_INTERVAL: u64 = 10_000;

/// Default whitelist path.
const DEFAULT_WHITELIST: &str = "/etc/alice-dns/whitelist.hosts";
/// Default HTTP null server port.
const DEFAULT_NULL_HTTP_PORT: u16 = 80;
/// Default HTTPS null server port.
const DEFAULT_NULL_HTTPS_PORT: u16 = 443;
/// Default TLS certificate path.
const DEFAULT_TLS_CERT: &str = "/etc/alice-dns/tls.crt";
/// Default TLS key path.
const DEFAULT_TLS_KEY: &str = "/etc/alice-dns/tls.key";

/// DNS blocking mode.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockMode {
    /// Traditional: return 0.0.0.0 for blocked domains.
    Block,
    /// Neutralize: return Pi's IP + serve empty HTTP content.
    /// Anti-adblock bypass: DNS resolves, clicks are prevented.
    Neutralize,
}

struct Config {
    listen_addr: String,
    blocklist_path: PathBuf,
    filter_bin_path: PathBuf,
    whitelist_path: PathBuf,
    spoof_ip: [u8; 4],
    upstream_resolvers: Vec<UpstreamResolver>,
    block_mode: BlockMode,
    null_http_port: u16,
    null_https_port: u16,
    tls_cert_path: String,
    tls_key_path: String,
}

fn parse_args() -> Config {
    let args: Vec<String> = std::env::args().collect();
    let mut config = Config {
        listen_addr: DEFAULT_LISTEN.into(),
        blocklist_path: PathBuf::from(DEFAULT_BLOCKLIST),
        filter_bin_path: PathBuf::from(DEFAULT_FILTER_BIN),
        whitelist_path: PathBuf::from(DEFAULT_WHITELIST),
        spoof_ip: [192, 168, 11, 7], // Default: Raspberry Pi's LAN IP
        upstream_resolvers: vec![
            UpstreamResolver { addr: "1.1.1.1:53".into(), name: "Cloudflare".into() },
            UpstreamResolver { addr: "8.8.8.8:53".into(), name: "Google".into() },
        ],
        block_mode: BlockMode::Block,
        null_http_port: DEFAULT_NULL_HTTP_PORT,
        null_https_port: DEFAULT_NULL_HTTPS_PORT,
        tls_cert_path: DEFAULT_TLS_CERT.into(),
        tls_key_path: DEFAULT_TLS_KEY.into(),
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                i += 1;
                if i < args.len() {
                    config.listen_addr = format!("0.0.0.0:{}", args[i]);
                }
            }
            "--blocklist" | "-b" => {
                i += 1;
                if i < args.len() {
                    config.blocklist_path = PathBuf::from(&args[i]);
                }
            }
            "--whitelist" | "-w" => {
                i += 1;
                if i < args.len() {
                    config.whitelist_path = PathBuf::from(&args[i]);
                }
            }
            "--upstream" | "-u" => {
                i += 1;
                if i < args.len() {
                    config.upstream_resolvers = args[i]
                        .split(',')
                        .enumerate()
                        .map(|(idx, addr)| {
                            let addr = if addr.contains(':') {
                                addr.to_string()
                            } else {
                                format!("{}:53", addr)
                            };
                            UpstreamResolver {
                                addr,
                                name: format!("Custom-{}", idx),
                            }
                        })
                        .collect();
                }
            }
            "--spoof-ip" | "-s" => {
                i += 1;
                if i < args.len() {
                    let parts: Vec<&str> = args[i].split('.').collect();
                    if parts.len() == 4 {
                        if let (Ok(a), Ok(b), Ok(c), Ok(d)) = (
                            parts[0].parse::<u8>(), parts[1].parse::<u8>(),
                            parts[2].parse::<u8>(), parts[3].parse::<u8>(),
                        ) {
                            config.spoof_ip = [a, b, c, d];
                        }
                    }
                }
            }
            "--mode" | "-m" => {
                i += 1;
                if i < args.len() {
                    config.block_mode = match args[i].as_str() {
                        "neutralize" | "n" => BlockMode::Neutralize,
                        "block" | "b" => BlockMode::Block,
                        other => {
                            eprintln!("Unknown mode: '{}'. Use 'block' or 'neutralize'.", other);
                            std::process::exit(1);
                        }
                    };
                }
            }
            "--null-port" => {
                i += 1;
                if i < args.len() {
                    config.null_http_port = args[i].parse().unwrap_or(DEFAULT_NULL_HTTP_PORT);
                }
            }
            "--null-https-port" => {
                i += 1;
                if i < args.len() {
                    config.null_https_port = args[i].parse().unwrap_or(DEFAULT_NULL_HTTPS_PORT);
                }
            }
            "--tls-cert" => {
                i += 1;
                if i < args.len() {
                    config.tls_cert_path = args[i].clone();
                }
            }
            "--tls-key" => {
                i += 1;
                if i < args.len() {
                    config.tls_key_path = args[i].clone();
                }
            }
            "--version" | "-V" => {
                println!("alice-dns {}", alice_dns::VERSION);
                std::process::exit(0);
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                print_help();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    config
}

fn print_help() {
    println!("ALICE-DNS — Bloom Filter DNS Ad-Blocker");
    println!();
    println!("Usage: alice-dns [OPTIONS]");
    println!();
    println!("Options:");
    println!("  -p, --port <PORT>          Listen port (default: 53)");
    println!("  -b, --blocklist <PATH>     Blocklist file path (hosts format)");
    println!("  -w, --whitelist <PATH>     Whitelist file path (one domain per line)");
    println!("  -u, --upstream <ADDR,...>   Upstream DNS (default: 1.1.1.1,8.8.8.8)");
    println!("  -s, --spoof-ip <IP>        Spoof IP for anti-adblock bypass (default: 192.168.11.7)");
    println!("  -m, --mode <MODE>          block (default) or neutralize");
    println!("      --null-port <PORT>     HTTP null server port for neutralize mode (default: 80)");
    println!("      --null-https-port <PORT>  HTTPS null server port (default: 443)");
    println!("      --tls-cert <PATH>      TLS certificate for HTTPS null server");
    println!("      --tls-key <PATH>       TLS private key for HTTPS null server");
    println!("  -V, --version              Print version");
    println!("  -h, --help                 Print help");
    println!();
    println!("Modes:");
    println!("  block       Return 0.0.0.0 for blocked domains (traditional, may break anti-adblock)");
    println!("  neutralize  Return Pi's IP + HTTP null server (anti-adblock bypass, click prevention)");
    println!();
    println!("Signals:");
    println!("  SIGHUP   Reload blocklist (hot-reload, zero downtime)");
    println!("  SIGUSR1  Print statistics to stdout");
    println!();
    println!("Files:");
    println!("  /etc/alice-dns/blocklist.hosts  Default blocklist (hosts format)");
    println!("  /etc/alice-dns/whitelist.hosts  Default whitelist (one domain per line)");
    println!("  /etc/alice-dns/filter.bin       Binary Bloom filter (auto-generated)");
}

fn load_blocklist(engine: &mut DnsBloomEngine, config: &Config) {
    // Try binary filter first (faster load)
    if config.filter_bin_path.exists() {
        match std::fs::read(&config.filter_bin_path) {
            Ok(data) => {
                if engine.load_from_binary(&data).is_ok() {
                    println!("  Loaded binary filter: {} domains ({} KB)",
                        engine.domain_count(),
                        engine.bloom_size_bytes() / 1024);
                    return;
                }
            }
            Err(e) => eprintln!("  Warning: Failed to read binary filter: {}", e),
        }
    }

    // Fall back to text blocklist
    if config.blocklist_path.exists() {
        match std::fs::read_to_string(&config.blocklist_path) {
            Ok(content) => {
                let domains = blocklist::parse_hosts(&content);
                let count = domains.len();
                engine.load_domains(&domains);

                // Save binary filter for faster future loads
                let binary = engine.to_binary();
                if let Err(e) = std::fs::write(&config.filter_bin_path, &binary) {
                    eprintln!("  Warning: Could not save binary filter: {}", e);
                }

                println!("  Loaded blocklist: {} domains from {:?}", count, config.blocklist_path);
                println!("  Bloom filter: {} KB", engine.bloom_size_bytes() / 1024);
            }
            Err(e) => {
                eprintln!("  Error: Failed to read blocklist: {}", e);
                eprintln!("  Running with empty blocklist (forwarding only)");
            }
        }
    } else {
        eprintln!("  Warning: No blocklist found at {:?}", config.blocklist_path);
        eprintln!("  Running with empty blocklist (forwarding only)");
        eprintln!("  Run: update-blocklist.py to download StevenBlack/hosts");
    }
}

fn load_whitelist(engine: &mut DnsBloomEngine, config: &Config) {
    if config.whitelist_path.exists() {
        match std::fs::read_to_string(&config.whitelist_path) {
            Ok(content) => {
                let domains: Vec<String> = content
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(|l| l.to_lowercase())
                    .collect();
                let count = domains.len();
                engine.load_whitelist(&domains);
                println!("  Whitelist: {} domains from {:?}", count, config.whitelist_path);
            }
            Err(e) => eprintln!("  Warning: Failed to read whitelist: {}", e),
        }
    } else {
        println!("  Whitelist: none (no file at {:?})", config.whitelist_path);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_args();

    println!("╔═════════════════════════════════════════════╗");
    println!("║           ALICE-DNS v{}                  ║", alice_dns::VERSION);
    println!("║  Bloom Filter DNS Ad-Blocker                ║");
    println!("╚═════════════════════════════════════════════╝");
    println!();

    // ── Initialize Bloom Engine ──
    println!("━━━ Loading Blocklist ━━━");
    let mut bloom_engine = DnsBloomEngine::new();
    load_blocklist(&mut bloom_engine, &config);
    load_whitelist(&mut bloom_engine, &config);
    println!();

    // ── Initialize Upstream Forwarder ──
    println!("━━━ Upstream DNS ━━━");
    let mut forwarder = UpstreamForwarder::with_resolvers(config.upstream_resolvers.clone())?;
    for resolver in &config.upstream_resolvers {
        println!("  {} ({})", resolver.addr, resolver.name);
    }
    println!();

    // ── Initialize Stats ──
    let mut stats = DnsStats::new();

    // ── Bind UDP Socket ──
    println!("━━━ Listening ━━━");
    let socket = UdpSocket::bind(&config.listen_addr)?;
    println!("  Bound to {}", config.listen_addr);
    println!();

    // ── Signal Handling ──
    let reload_flag = Arc::new(AtomicBool::new(false));
    let stats_flag = Arc::new(AtomicBool::new(false));
    let shutdown_flag = Arc::new(AtomicBool::new(false));

    // SIGHUP → reload blocklist
    {
        let flag = reload_flag.clone();
        unsafe {
            register_signal(SIG_HUP, move || {
                flag.store(true, Ordering::Relaxed);
            });
        }
    }
    // SIGUSR1 → print stats
    {
        let flag = stats_flag.clone();
        unsafe {
            register_signal(SIG_USR1, move || {
                flag.store(true, Ordering::Relaxed);
            });
        }
    }
    // SIGTERM/SIGINT → shutdown
    {
        let flag = shutdown_flag.clone();
        unsafe {
            register_signal(SIG_TERM, move || {
                flag.store(true, Ordering::Relaxed);
            });
        }
    }

    // ── Start Null HTTP/HTTPS Server (neutralize mode only) ──
    if config.block_mode == BlockMode::Neutralize {
        println!("━━━ Null Server (Ad Neutralization) ━━━");

        // Try to create with TLS if cert/key exist
        let null_server = if std::path::Path::new(&config.tls_cert_path).exists()
            && std::path::Path::new(&config.tls_key_path).exists()
        {
            match NullServer::with_tls(
                config.null_http_port,
                config.null_https_port,
                &config.tls_cert_path,
                &config.tls_key_path,
            ) {
                Ok(server) => {
                    println!("  TLS: cert={} key={}", config.tls_cert_path, config.tls_key_path);
                    server
                }
                Err(e) => {
                    eprintln!("  Warning: TLS setup failed: {}", e);
                    eprintln!("  Falling back to HTTP only");
                    NullServer::new(config.null_http_port)
                }
            }
        } else {
            println!("  TLS: disabled (no cert/key at {} / {})", config.tls_cert_path, config.tls_key_path);
            NullServer::new(config.null_http_port)
        };

        match null_server.start_background() {
            Ok(()) => {}
            Err(e) => {
                eprintln!("  Error: Failed to start null server: {}", e);
                eprintln!("  Ports {}/{} may be in use.", config.null_http_port, config.null_https_port);
                return Err(e.into());
            }
        }
        println!();
    }

    let mode_str = match config.block_mode {
        BlockMode::Block => "block (0.0.0.0)",
        BlockMode::Neutralize => "neutralize (spoof IP + HTTP null)",
    };
    println!("ALICE-DNS is ready. {} blocked, {} whitelisted, mode: {}, spoof IP: {}.{}.{}.{}",
        bloom_engine.domain_count(), bloom_engine.whitelist_count(), mode_str,
        config.spoof_ip[0], config.spoof_ip[1], config.spoof_ip[2], config.spoof_ip[3]);
    println!("Send SIGHUP to reload, SIGUSR1 for stats, SIGTERM to stop.");
    println!();

    // ── Main Loop ──
    let mut buf = [0u8; MAX_PACKET_SIZE];

    loop {
        // Check signals
        if shutdown_flag.load(Ordering::Relaxed) {
            println!("\nShutting down...");
            stats.print_summary();
            break;
        }

        if reload_flag.load(Ordering::Relaxed) {
            reload_flag.store(false, Ordering::Relaxed);
            println!("\nReloading blocklist + whitelist...");
            load_blocklist(&mut bloom_engine, &config);
            load_whitelist(&mut bloom_engine, &config);
            println!("Reload complete. {} blocked, {} whitelisted.",
                bloom_engine.domain_count(), bloom_engine.whitelist_count());
        }

        if stats_flag.load(Ordering::Relaxed) {
            stats_flag.store(false, Ordering::Relaxed);
            stats.print_summary();
        }

        // Receive DNS query
        let (size, src) = match socket.recv_from(&mut buf) {
            Ok(result) => result,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue; // Signal interrupted recv — check flags
                }
                eprintln!("recv error: {}", e);
                continue;
            }
        };

        let packet = &buf[..size];
        let query_start = Instant::now();

        // Parse DNS query
        let query = match dns::parse_query(packet) {
            Some(q) => q,
            None => continue, // Malformed — drop silently
        };

        // Block DDR (Discovery of Designated Resolvers, RFC 9462)
        // Prevents iOS/macOS from discovering upstream DoH/DoT and bypassing local DNS
        let response = if query.qname.ends_with("_dns.resolver.arpa") || query.qname == "_dns.resolver.arpa" {
            let latency = query_start.elapsed().as_micros() as u64;
            stats.record_query(&query.qname, true, latency);
            dns::build_nxdomain_response(packet, &query)
        } else {
            match bloom_engine.check_domain(&query.qname) {
                DnsAction::Block => {
                    let latency = query_start.elapsed().as_micros() as u64;
                    stats.record_query(&query.qname, true, latency);
                    if query.qtype == dns::QTYPE_A || query.qtype == dns::QTYPE_AAAA {
                        if config.block_mode == BlockMode::Neutralize {
                            // NEUTRALIZE → spoof to Pi's IP (HTTP null server handles requests)
                            dns::build_spoof_response(packet, &query, config.spoof_ip)
                        } else {
                            // BLOCK → 0.0.0.0 / :: (traditional)
                            dns::build_blocked_response(packet, &query)
                        }
                    } else {
                        dns::build_nxdomain_response(packet, &query)
                    }
                }
                DnsAction::Spoof => {
                    // SPOOFED → return Pi's IP (anti-adblock bypass)
                    let latency = query_start.elapsed().as_micros() as u64;
                    stats.record_query(&query.qname, true, latency);
                    if query.qtype == dns::QTYPE_A || query.qtype == dns::QTYPE_AAAA {
                        dns::build_spoof_response(packet, &query, config.spoof_ip)
                    } else {
                        dns::build_nxdomain_response(packet, &query)
                    }
                }
                DnsAction::Allow => {
                    // ALLOWED → forward to upstream (with cache)
                    match forwarder.forward(packet, &query.qname, query.qtype) {
                        Some(resp) => {
                            let latency = query_start.elapsed().as_micros() as u64;
                            stats.record_query(&query.qname, false, latency);
                            stats.cache_hits = forwarder.cache_hits;
                            stats.cache_misses = forwarder.cache_misses;
                            stats.upstream_errors = forwarder.upstream_errors;
                            resp
                        }
                        None => {
                            stats.upstream_errors += 1;
                            continue; // All upstreams failed — drop
                        }
                    }
                }
            }
        };

        // Send response
        let _ = socket.send_to(&response, src);

        // Periodic stats
        if stats.queries_total % STATS_INTERVAL == 0 && stats.queries_total > 0 {
            println!(
                "[{}] queries={} blocked={} ({:.1}%) cache_hit={:.1}%",
                stats.queries_total,
                stats.queries_total,
                stats.queries_blocked,
                stats.block_rate() * 100.0,
                forwarder.cache_hit_rate() * 100.0,
            );
        }
    }

    Ok(())
}

// ─── Minimal Signal Handling (no libc crate dependency) ──────────────

const SIG_HUP: i32 = 1;
const SIG_USR1: i32 = 10;
const SIG_TERM: i32 = 15;

/// Register a signal handler using raw syscall.
///
/// SAFETY: The callback must be safe to call from a signal context
/// (only atomic operations, no allocations).
unsafe fn register_signal<F: Fn() + Send + Sync + 'static>(sig: i32, handler: F) {
    use std::sync::OnceLock;

    // Store handler in static to ensure it lives forever
    static HANDLERS: OnceLock<std::sync::Mutex<Vec<Box<dyn Fn() + Send + Sync>>>> = OnceLock::new();
    let handlers = HANDLERS.get_or_init(|| std::sync::Mutex::new(Vec::new()));

    let mut guard = handlers.lock().unwrap_or_else(|e| e.into_inner());
    let idx = guard.len();
    guard.push(Box::new(handler));
    drop(guard);

    // We use a simple approach: store flag index in a global array
    // and use a single C signal handler that dispatches.
    static FLAGS: [AtomicBool; 32] = {
        const INIT: AtomicBool = AtomicBool::new(false);
        [INIT; 32]
    };

    extern "C" fn sig_handler(sig: i32) {
        if (sig as usize) < 32 {
            FLAGS[sig as usize].store(true, Ordering::Relaxed);
        }
    }

    // Register the C handler
    libc::signal(sig, sig_handler as libc::sighandler_t);

    // Spawn a thread to poll the flag and call the Rust handler
    let sig_copy = sig;
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if FLAGS[sig_copy as usize].swap(false, Ordering::Relaxed) {
                let handlers = HANDLERS.get().unwrap();
                let guard = handlers.lock().unwrap_or_else(|e| e.into_inner());
                if idx < guard.len() {
                    (guard[idx])();
                }
            }
        }
    });
}

// Bring libc signal function
#[allow(non_camel_case_types)]
mod libc {
    pub type sighandler_t = usize;
    extern "C" {
        pub fn signal(sig: i32, handler: sighandler_t) -> sighandler_t;
    }
}
