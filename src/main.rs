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
    DnsBloomEngine, DnsStats, UpstreamForwarder,
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

struct Config {
    listen_addr: String,
    blocklist_path: PathBuf,
    filter_bin_path: PathBuf,
    upstream_resolvers: Vec<UpstreamResolver>,
}

fn parse_args() -> Config {
    let args: Vec<String> = std::env::args().collect();
    let mut config = Config {
        listen_addr: DEFAULT_LISTEN.into(),
        blocklist_path: PathBuf::from(DEFAULT_BLOCKLIST),
        filter_bin_path: PathBuf::from(DEFAULT_FILTER_BIN),
        upstream_resolvers: vec![
            UpstreamResolver { addr: "1.1.1.1:53".into(), name: "Cloudflare".into() },
            UpstreamResolver { addr: "8.8.8.8:53".into(), name: "Google".into() },
        ],
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
    println!("  -u, --upstream <ADDR,...>   Upstream DNS (default: 1.1.1.1,8.8.8.8)");
    println!("  -V, --version              Print version");
    println!("  -h, --help                 Print help");
    println!();
    println!("Signals:");
    println!("  SIGHUP   Reload blocklist (hot-reload, zero downtime)");
    println!("  SIGUSR1  Print statistics to stdout");
    println!();
    println!("Files:");
    println!("  /etc/alice-dns/blocklist.hosts  Default blocklist (hosts format)");
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

    println!("ALICE-DNS is ready. {} domains blocked.", bloom_engine.domain_count());
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
            println!("\nReloading blocklist...");
            load_blocklist(&mut bloom_engine, &config);
            println!("Reload complete. {} domains.", bloom_engine.domain_count());
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
        } else if bloom_engine.should_block(&query.qname) {
            // BLOCKED
            let latency = query_start.elapsed().as_micros() as u64;
            stats.record_query(&query.qname, true, latency);
            // A → 0.0.0.0, AAAA → ::, other types → NXDOMAIN
            if query.qtype == dns::QTYPE_A || query.qtype == dns::QTYPE_AAAA {
                dns::build_blocked_response(packet, &query)
            } else {
                dns::build_nxdomain_response(packet, &query)
            }
        } else {
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

    let mut guard = handlers.lock().unwrap();
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
                let guard = handlers.lock().unwrap();
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
