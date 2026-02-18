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
pub struct NullServer {
    port: u16,
}

impl NullServer {
    /// Create a new null server bound to the given port.
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    /// Start the null server on a background thread.
    ///
    /// Binds to `0.0.0.0:{port}` and spawns a listener thread.
    /// Each connection is handled in its own thread with a 500ms timeout.
    ///
    /// Returns immediately after binding (non-blocking).
    pub fn start_background(self) -> std::io::Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port))?;
        println!("  Listening on 0.0.0.0:{} (HTTP null responses)", self.port);

        thread::Builder::new()
            .name("null-http".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    if let Ok(stream) = stream {
                        thread::spawn(move || {
                            Self::handle_connection(stream);
                        });
                    }
                }
            })?;

        Ok(())
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
