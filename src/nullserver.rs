//! HTTP Null Server — Ad Neutralization
//!
//! Lightweight HTTP server that serves "neutralized" content for DNS-spoofed ad domains.
//!
//! When ALICE-DNS runs in `--mode neutralize`, blocked domains resolve to the Pi's IP
//! instead of 0.0.0.0. This HTTP server (port 80) responds with:
//!
//! | Request Type    | Response                                  |
//! |-----------------|-------------------------------------------|
//! | JavaScript      | `(function(){})()` (no-op)                |
//! | Image           | 1x1 transparent GIF (43 bytes)            |
//! | CSS             | Empty stylesheet                          |
//! | HTML / iframe   | Click-prevention page (preventDefault)    |
//! | JSON            | `{}`                                      |
//! | XML             | `<?xml version="1.0"?><r/>`               |
//! | OPTIONS         | CORS preflight (204)                      |
//! | Other           | 204 No Content                            |
//!
//! # Anti-Adblock Bypass
//!
//! Many sites detect ad blockers by checking if ad domains resolve (DNS check).
//! With neutralize mode:
//! 1. DNS resolves to Pi's IP → anti-adblock DNS check passes
//! 2. HTTP returns valid (but empty) responses → no script errors
//! 3. Click events in ad iframes are trapped → no navigation
//!
//! # Architecture
//!
//! ```text
//! [Browser] → GET http://ads.example.com/ad.js → [Pi :80 Null Server]
//!                                                       │
//!                                                  detect content:
//!                                                  .js  → empty script
//!                                                  .gif → transparent pixel
//!                                                  .html → click trap
//!                                                  *    → 204
//! ```

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

#[cfg(feature = "tls")]
use std::sync::Arc;

#[cfg(feature = "tls")]
use rustls::ServerConfig;

// ─── Static Response Bodies ─────────────────────────────────────────

/// 1x1 transparent GIF89a (43 bytes).
///
/// Smallest valid GIF that renders as a fully transparent pixel.
/// Used for all image requests (gif, png, jpg, webp, ico, svg).
const TRANSPARENT_GIF: &[u8] = &[
    // Header: GIF89a
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61,
    // Logical Screen Descriptor: 1x1, GCT with 2 colors
    0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
    // Global Color Table: color 0 = white, color 1 = black
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00,
    // Graphic Control Extension: transparent, delay=0, index=0
    0x21, 0xF9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
    // Image Descriptor: (0,0) 1x1, no local color table
    0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    // Image Data: LZW min code size=2, 2-byte sub-block
    0x02, 0x02, 0x44, 0x01, 0x00,
    // GIF Trailer
    0x3B,
];

/// Empty JavaScript — no-op IIFE.
const EMPTY_JS: &[u8] = b"(function(){})()";

/// Click-neutralization HTML page.
///
/// Captures all click/touch/pointer events at the document level (capture phase)
/// and calls preventDefault + stopPropagation. This prevents:
/// - `<a>` link clicks in ad iframes
/// - `window.open()` popups
/// - Form submissions
/// - Touch-tap navigation on mobile
const NEUTRALIZE_HTML: &[u8] = b"<!DOCTYPE html>\
<html><head><script>\
(function(){\
var b=function(e){e.preventDefault();e.stopPropagation();e.stopImmediatePropagation();return false};\
['click','mousedown','touchstart','pointerdown','submit'].forEach(function(t){\
document.addEventListener(t,b,true)});\
window.open=function(){return null};\
})();\
</script></head><body></body></html>";

/// Empty JSON.
const EMPTY_JSON: &[u8] = b"{}";

/// Empty XML.
const EMPTY_XML: &[u8] = b"<?xml version=\"1.0\"?><r/>";

/// CORS headers — included in all responses.
///
/// Allows cross-origin ad resource loading (scripts, images, iframes)
/// without triggering CORS errors that anti-adblock scripts might detect.
const CORS_HEADERS: &str = "\
Access-Control-Allow-Origin: *\r\n\
Access-Control-Allow-Methods: GET, POST, OPTIONS, HEAD\r\n\
Access-Control-Allow-Headers: *\r\n\
Access-Control-Max-Age: 86400\r\n";

/// Connection read/write timeout (500ms — enough for local LAN).
const CONN_TIMEOUT: Duration = Duration::from_millis(500);

// ─── Content Detection ──────────────────────────────────────────────

/// Detected content kind from HTTP request.
enum ContentKind {
    /// CORS preflight (OPTIONS request)
    Preflight,
    /// JavaScript (.js, .mjs, Accept: application/javascript)
    JavaScript,
    /// CSS (.css, Accept: text/css)
    Css,
    /// Image (.gif, .png, .jpg, .webp, .ico, .svg, .avif, Accept: image/*)
    Image,
    /// HTML (.html, .htm, Accept: text/html)
    Html,
    /// JSON (.json, Accept: application/json)
    Json,
    /// XML (.xml, Accept: application/xml)
    Xml,
    /// Unknown — returns 204 No Content
    Other,
}

// ─── Null Server ────────────────────────────────────────────────────

/// HTTP Null Server for ad neutralization.
///
/// Runs on a background thread, accepts TCP connections on the specified port,
/// and returns neutralized content based on the request type.
///
/// Optionally supports TLS (HTTPS) on a second port when compiled with the
/// `tls` feature. Without TLS the server handles HTTP only on `port`.
pub struct NullServer {
    /// HTTP listen port.
    port: u16,
    /// Optional TLS configuration: (https_port, ServerConfig).
    ///
    /// Present only when `tls` feature is enabled and `with_tls()` was used.
    #[cfg(feature = "tls")]
    tls: Option<(u16, Arc<ServerConfig>)>,
}

impl NullServer {
    /// Create a new null server bound to the given port (HTTP only).
    pub fn new(port: u16) -> Self {
        Self {
            port,
            #[cfg(feature = "tls")]
            tls: None,
        }
    }

    /// Create a null server with both HTTP and HTTPS support.
    ///
    /// Reads a PEM-encoded certificate chain and private key from disk and
    /// configures a `rustls::ServerConfig`. Returns an error if the files are
    /// missing, malformed, or the TLS handshake configuration fails.
    ///
    /// # Arguments
    ///
    /// * `http_port`  - Port for plaintext HTTP (typically 80).
    /// * `https_port` - Port for TLS HTTPS (typically 443).
    /// * `cert_path`  - Path to PEM certificate chain (server + intermediates).
    /// * `key_path`   - Path to PEM private key (RSA or ECDSA).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the cert/key cannot be read or parsed, or if `rustls`
    /// rejects the key material.
    #[cfg(feature = "tls")]
    pub fn with_tls(
        http_port: u16,
        https_port: u16,
        cert_path: &str,
        key_path: &str,
    ) -> std::io::Result<Self> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls_pemfile::{certs, private_key};

        // ── Load certificate chain ──
        let cert_file = std::fs::File::open(cert_path).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("Failed to open TLS certificate '{}': {}", cert_path, e),
            )
        })?;
        let mut cert_reader = std::io::BufReader::new(cert_file);
        let cert_chain: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to parse PEM certificates from '{}': {}", cert_path, e),
                )
            })?;

        if cert_chain.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("No certificates found in '{}'", cert_path),
            ));
        }

        // ── Load private key ──
        let key_file = std::fs::File::open(key_path).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("Failed to open TLS private key '{}': {}", key_path, e),
            )
        })?;
        let mut key_reader = std::io::BufReader::new(key_file);
        let private_key: PrivateKeyDer<'static> =
            private_key(&mut key_reader)
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to parse PEM private key from '{}': {}", key_path, e),
                    )
                })?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("No private key found in '{}'", key_path),
                    )
                })?;

        // ── Build rustls ServerConfig ──
        let tls_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to build TLS server config: {}", e),
                )
            })?;

        Ok(Self {
            port: http_port,
            tls: Some((https_port, Arc::new(tls_config))),
        })
    }

    /// Start the null server on background thread(s).
    ///
    /// Always starts an HTTP listener on `self.port`.
    /// When `tls` feature is enabled and TLS was configured via `with_tls()`,
    /// also starts a TLS listener on the HTTPS port.
    ///
    /// Binds to `0.0.0.0:{port}` and spawns a listener thread.
    /// Each connection is handled in its own thread with a 500ms timeout.
    ///
    /// Returns immediately after binding (non-blocking).
    pub fn start_background(self) -> std::io::Result<()> {
        // ── HTTP listener ──
        let http_listener = TcpListener::bind(format!("0.0.0.0:{}", self.port))?;
        println!("  Listening on 0.0.0.0:{} (HTTP null responses)", self.port);

        thread::Builder::new()
            .name("null-http".into())
            .spawn(move || {
                for stream in http_listener.incoming() {
                    if let Ok(stream) = stream {
                        thread::spawn(move || {
                            Self::handle_connection(stream);
                        });
                    }
                }
            })?;

        // ── HTTPS listener (TLS feature only) ──
        #[cfg(feature = "tls")]
        if let Some((https_port, tls_config)) = self.tls {
            let https_listener = TcpListener::bind(format!("0.0.0.0:{}", https_port))
                .map_err(|e| {
                    std::io::Error::new(
                        e.kind(),
                        format!("Failed to bind HTTPS port {}: {}", https_port, e),
                    )
                })?;
            println!("  Listening on 0.0.0.0:{} (HTTPS null responses)", https_port);

            thread::Builder::new()
                .name("null-https".into())
                .spawn(move || {
                    for stream in https_listener.incoming() {
                        if let Ok(tcp_stream) = stream {
                            let cfg = Arc::clone(&tls_config);
                            thread::spawn(move || {
                                Self::handle_tls_connection(tcp_stream, cfg);
                            });
                        }
                    }
                })?;
        }

        Ok(())
    }

    /// Handle a single TLS (HTTPS) connection.
    ///
    /// Performs the TLS handshake, reads the HTTP request, sends a null
    /// response, and closes the connection.
    ///
    /// Uses `rustls::Stream` which requires `&mut TcpStream` for both read and
    /// write via the same mutable reference.
    ///
    /// TODO: For production use, consider wrapping in a proper bidirectional
    /// adapter (e.g. `tokio-rustls` or a split `try_clone` approach) to
    /// support concurrent read/write on the TLS stream.
    /// See: https://docs.rs/rustls/latest/rustls/struct.Stream.html
    #[cfg(feature = "tls")]
    fn handle_tls_connection(mut tcp_stream: TcpStream, tls_config: Arc<ServerConfig>) {
        use rustls::ServerConnection;

        let _ = tcp_stream.set_read_timeout(Some(CONN_TIMEOUT));
        let _ = tcp_stream.set_write_timeout(Some(CONN_TIMEOUT));

        // Build a TLS server connection from the accepted TCP stream.
        let mut conn = match ServerConnection::new(tls_config) {
            Ok(c) => c,
            Err(_) => return,
        };

        // rustls::Stream<ServerConnection, TcpStream> provides Read + Write by
        // interleaving TLS record reads/writes on the underlying socket.
        let mut stream = rustls::Stream::new(&mut conn, &mut tcp_stream);

        // Read the HTTP request (2 KB is sufficient for headers).
        let mut buf = [0u8; 2048];
        let n = match stream.read(&mut buf) {
            Ok(n) if n > 0 => n,
            _ => return,
        };

        let request = &buf[..n];
        let kind = Self::detect_content_kind(request);
        let response = Self::build_response(&kind);

        let _ = stream.write_all(&response);
        let _ = stream.flush();
    }

    /// Handle a single HTTP connection.
    ///
    /// Reads the request, detects content kind, sends response, closes.
    fn handle_connection(mut stream: TcpStream) {
        let _ = stream.set_read_timeout(Some(CONN_TIMEOUT));
        let _ = stream.set_write_timeout(Some(CONN_TIMEOUT));

        // Read request (2KB is enough for HTTP headers)
        let mut buf = [0u8; 2048];
        let n = match stream.read(&mut buf) {
            Ok(n) if n > 0 => n,
            _ => return,
        };

        let request = &buf[..n];
        let kind = Self::detect_content_kind(request);
        let response = Self::build_response(&kind);

        let _ = stream.write_all(&response);
        let _ = stream.flush();
    }

    /// Detect what kind of content the client expects.
    ///
    /// Priority: HTTP method → URL extension → Accept header → fallback to 204.
    fn detect_content_kind(request: &[u8]) -> ContentKind {
        let req = match std::str::from_utf8(request) {
            Ok(s) => s,
            Err(_) => return ContentKind::Other,
        };

        // OPTIONS → CORS preflight
        if req.starts_with("OPTIONS ") {
            return ContentKind::Preflight;
        }

        // Extract URL path: "GET /path?query HTTP/1.1"
        let path = req.split_whitespace()
            .nth(1)
            .unwrap_or("/")
            .split('?')       // strip query string
            .next()
            .unwrap_or("/")
            .to_ascii_lowercase();

        // ── Check file extension (most reliable) ──

        if path.ends_with(".js") || path.ends_with(".mjs") {
            return ContentKind::JavaScript;
        }
        if path.ends_with(".css") {
            return ContentKind::Css;
        }
        if path.ends_with(".gif") || path.ends_with(".png")
            || path.ends_with(".jpg") || path.ends_with(".jpeg")
            || path.ends_with(".webp") || path.ends_with(".svg")
            || path.ends_with(".ico") || path.ends_with(".avif")
        {
            return ContentKind::Image;
        }
        if path.ends_with(".html") || path.ends_with(".htm") {
            return ContentKind::Html;
        }
        if path.ends_with(".json") {
            return ContentKind::Json;
        }
        if path.ends_with(".xml") {
            return ContentKind::Xml;
        }

        // ── Fall back to Accept header ──

        for line in req.lines().skip(1) {
            let lower = line.to_ascii_lowercase();
            if !lower.starts_with("accept:") {
                continue;
            }
            if lower.contains("text/html") || lower.contains("application/xhtml") {
                return ContentKind::Html;
            }
            if lower.contains("image/") {
                return ContentKind::Image;
            }
            if lower.contains("javascript") || lower.contains("ecmascript") {
                return ContentKind::JavaScript;
            }
            if lower.contains("text/css") {
                return ContentKind::Css;
            }
            if lower.contains("application/json") {
                return ContentKind::Json;
            }
            break; // only check first Accept header
        }

        ContentKind::Other
    }

    /// Build an HTTP response for the detected content kind.
    ///
    /// All responses include CORS headers and `Connection: close`.
    fn build_response(kind: &ContentKind) -> Vec<u8> {
        match kind {
            ContentKind::Preflight => {
                format!(
                    "HTTP/1.1 204 No Content\r\n\
                     {CORS_HEADERS}\
                     Content-Length: 0\r\n\
                     Connection: close\r\n\r\n"
                ).into_bytes()
            }
            ContentKind::JavaScript => {
                let mut resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     {CORS_HEADERS}\
                     Content-Type: application/javascript; charset=utf-8\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    EMPTY_JS.len()
                ).into_bytes();
                resp.extend_from_slice(EMPTY_JS);
                resp
            }
            ContentKind::Css => {
                format!(
                    "HTTP/1.1 200 OK\r\n\
                     {CORS_HEADERS}\
                     Content-Type: text/css; charset=utf-8\r\n\
                     Content-Length: 0\r\n\
                     Connection: close\r\n\r\n"
                ).into_bytes()
            }
            ContentKind::Image => {
                let mut resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     {CORS_HEADERS}\
                     Content-Type: image/gif\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    TRANSPARENT_GIF.len()
                ).into_bytes();
                resp.extend_from_slice(TRANSPARENT_GIF);
                resp
            }
            ContentKind::Html => {
                let mut resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     {CORS_HEADERS}\
                     Content-Type: text/html; charset=utf-8\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    NEUTRALIZE_HTML.len()
                ).into_bytes();
                resp.extend_from_slice(NEUTRALIZE_HTML);
                resp
            }
            ContentKind::Json => {
                let mut resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     {CORS_HEADERS}\
                     Content-Type: application/json; charset=utf-8\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    EMPTY_JSON.len()
                ).into_bytes();
                resp.extend_from_slice(EMPTY_JSON);
                resp
            }
            ContentKind::Xml => {
                let mut resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     {CORS_HEADERS}\
                     Content-Type: application/xml; charset=utf-8\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    EMPTY_XML.len()
                ).into_bytes();
                resp.extend_from_slice(EMPTY_XML);
                resp
            }
            ContentKind::Other => {
                format!(
                    "HTTP/1.1 204 No Content\r\n\
                     {CORS_HEADERS}\
                     Connection: close\r\n\r\n"
                ).into_bytes()
            }
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(method: &str, path: &str, accept: &str) -> Vec<u8> {
        format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: ads.example.com\r\n\
             Accept: {accept}\r\n\r\n"
        ).into_bytes()
    }

    // ── Content detection tests ──

    #[test]
    fn test_detect_js_by_extension() {
        let req = make_request("GET", "/ads/tracker.js", "*/*");
        assert!(matches!(NullServer::detect_content_kind(&req), ContentKind::JavaScript));
    }

    #[test]
    fn test_detect_mjs_by_extension() {
        let req = make_request("GET", "/module.mjs", "*/*");
        assert!(matches!(NullServer::detect_content_kind(&req), ContentKind::JavaScript));
    }

    #[test]
    fn test_detect_image_by_extension() {
        for ext in &[".gif", ".png", ".jpg", ".jpeg", ".webp", ".svg", ".ico", ".avif"] {
            let path = format!("/pixel{}", ext);
            let req = make_request("GET", &path, "*/*");
            assert!(matches!(NullServer::detect_content_kind(&req), ContentKind::Image),
                "Failed for extension: {}", ext);
        }
    }

    #[test]
    fn test_detect_html_by_extension() {
        let req = make_request("GET", "/ad-frame.html", "*/*");
        assert!(matches!(NullServer::detect_content_kind(&req), ContentKind::Html));
    }

    #[test]
    fn test_detect_css_by_extension() {
        let req = make_request("GET", "/style.css", "*/*");
        assert!(matches!(NullServer::detect_content_kind(&req), ContentKind::Css));
    }

    #[test]
    fn test_detect_json_by_extension() {
        let req = make_request("GET", "/config.json", "*/*");
        assert!(matches!(NullServer::detect_content_kind(&req), ContentKind::Json));
    }

    #[test]
    fn test_detect_xml_by_extension() {
        let req = make_request("GET", "/feed.xml", "*/*");
        assert!(matches!(NullServer::detect_content_kind(&req), ContentKind::Xml));
    }

    #[test]
    fn test_detect_with_query_string() {
        let req = make_request("GET", "/ads/tracker.js?v=123&t=abc", "*/*");
        assert!(matches!(NullServer::detect_content_kind(&req), ContentKind::JavaScript));
    }

    // ── Accept header fallback tests ──

    #[test]
    fn test_detect_html_by_accept() {
        let req = make_request("GET", "/some/path", "text/html, application/xhtml+xml");
        assert!(matches!(NullServer::detect_content_kind(&req), ContentKind::Html));
    }

    #[test]
    fn test_detect_image_by_accept() {
        let req = make_request("GET", "/some/path", "image/webp, image/*");
        assert!(matches!(NullServer::detect_content_kind(&req), ContentKind::Image));
    }

    #[test]
    fn test_detect_js_by_accept() {
        let req = make_request("GET", "/some/path", "application/javascript");
        assert!(matches!(NullServer::detect_content_kind(&req), ContentKind::JavaScript));
    }

    #[test]
    fn test_detect_css_by_accept() {
        let req = make_request("GET", "/some/path", "text/css");
        assert!(matches!(NullServer::detect_content_kind(&req), ContentKind::Css));
    }

    // ── Method tests ──

    #[test]
    fn test_options_preflight() {
        let req = make_request("OPTIONS", "/path", "*/*");
        assert!(matches!(NullServer::detect_content_kind(&req), ContentKind::Preflight));
    }

    #[test]
    fn test_unknown_content() {
        let req = make_request("GET", "/unknown", "*/*");
        assert!(matches!(NullServer::detect_content_kind(&req), ContentKind::Other));
    }

    #[test]
    fn test_post_with_extension() {
        let req = make_request("POST", "/beacon.gif", "*/*");
        assert!(matches!(NullServer::detect_content_kind(&req), ContentKind::Image));
    }

    // ── Response body tests ──

    #[test]
    fn test_transparent_gif_valid() {
        assert_eq!(&TRANSPARENT_GIF[..6], b"GIF89a");
        assert_eq!(TRANSPARENT_GIF[TRANSPARENT_GIF.len() - 1], 0x3B);
        assert_eq!(TRANSPARENT_GIF.len(), 43);
    }

    #[test]
    fn test_response_contains_cors() {
        let resp = NullServer::build_response(&ContentKind::JavaScript);
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("Access-Control-Allow-Origin: *"));
        assert!(resp_str.contains("Access-Control-Allow-Methods:"));
    }

    #[test]
    fn test_response_js_body() {
        let resp = NullServer::build_response(&ContentKind::JavaScript);
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("(function(){})()"));
        assert!(resp_str.contains("application/javascript"));
    }

    #[test]
    fn test_response_html_click_prevention() {
        let resp = NullServer::build_response(&ContentKind::Html);
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("preventDefault"));
        assert!(resp_str.contains("stopPropagation"));
        assert!(resp_str.contains("stopImmediatePropagation"));
        assert!(resp_str.contains("touchstart"));
        assert!(resp_str.contains("window.open=function(){return null}"));
    }

    #[test]
    fn test_response_image_is_gif() {
        let resp = NullServer::build_response(&ContentKind::Image);
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("Content-Type: image/gif"));
        // Check GIF data is present after headers
        let header_end = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(&resp[header_end..header_end + 6], b"GIF89a");
    }

    #[test]
    fn test_response_204_for_other() {
        let resp = NullServer::build_response(&ContentKind::Other);
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.starts_with("HTTP/1.1 204 No Content"));
    }

    #[test]
    fn test_response_json() {
        let resp = NullServer::build_response(&ContentKind::Json);
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("application/json"));
        assert!(resp_str.ends_with("{}"));
    }

    #[test]
    fn test_response_xml() {
        let resp = NullServer::build_response(&ContentKind::Xml);
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("application/xml"));
        assert!(resp_str.contains("<?xml"));
    }

    #[test]
    fn test_response_preflight_204() {
        let resp = NullServer::build_response(&ContentKind::Preflight);
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.starts_with("HTTP/1.1 204"));
        assert!(resp_str.contains("Content-Length: 0"));
    }

    #[test]
    fn test_all_responses_have_connection_close() {
        let kinds = [
            ContentKind::Preflight,
            ContentKind::JavaScript,
            ContentKind::Css,
            ContentKind::Image,
            ContentKind::Html,
            ContentKind::Json,
            ContentKind::Xml,
            ContentKind::Other,
        ];
        for kind in &kinds {
            let resp = NullServer::build_response(kind);
            let resp_str = String::from_utf8_lossy(&resp);
            assert!(resp_str.contains("Connection: close"),
                "Missing Connection: close for {:?}", std::mem::discriminant(kind));
        }
    }
}
