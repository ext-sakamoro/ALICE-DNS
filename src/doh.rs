//! DNS-over-HTTPS (`DoH`) クライアント
//!
//! RFC 8484 準拠の `DoH` クエリ送信。
//! DNS ワイヤフォーマットを HTTP リクエストに変換。

use alloc::string::String;
use alloc::vec::Vec;

/// `DoH` 設定。
#[derive(Debug, Clone)]
pub struct DohConfig {
    /// `DoH` エンドポイント URL (例: `https://1.1.1.1/dns-query`)。
    pub endpoint: String,
    /// タイムアウト (ミリ秒)。
    pub timeout_ms: u64,
    /// Accept ヘッダーのコンテントタイプ。
    pub accept: DohContentType,
    /// パディング有効。
    pub padding: bool,
}

impl Default for DohConfig {
    fn default() -> Self {
        Self {
            endpoint: String::from("https://1.1.1.1/dns-query"),
            timeout_ms: 5000,
            accept: DohContentType::DnsMessage,
            padding: true,
        }
    }
}

/// `DoH` コンテントタイプ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohContentType {
    /// `application/dns-message` (ワイヤフォーマット)。
    DnsMessage,
    /// `application/dns-json` (JSON フォーマット)。
    DnsJson,
}

impl DohContentType {
    /// MIME タイプ文字列。
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::DnsMessage => "application/dns-message",
            Self::DnsJson => "application/dns-json",
        }
    }
}

impl core::fmt::Display for DohContentType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// `DoH` リクエスト (HTTP POST)。
#[derive(Debug, Clone)]
pub struct DohRequest {
    /// エンドポイント URL。
    pub url: String,
    /// HTTP メソッド。
    pub method: DohMethod,
    /// Content-Type ヘッダー。
    pub content_type: DohContentType,
    /// DNS ワイヤフォーマットボディ。
    pub body: Vec<u8>,
}

/// HTTP メソッド。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohMethod {
    /// GET (Base64url エンコード)。
    Get,
    /// POST (バイナリボディ)。
    Post,
}

impl core::fmt::Display for DohMethod {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Post => write!(f, "POST"),
        }
    }
}

impl DohRequest {
    /// POST リクエストを構築。
    #[must_use]
    pub fn post(config: &DohConfig, dns_wire: Vec<u8>) -> Self {
        Self {
            url: config.endpoint.clone(),
            method: DohMethod::Post,
            content_type: config.accept,
            body: dns_wire,
        }
    }

    /// GET リクエストを構築 (Base64url エンコード)。
    #[must_use]
    pub fn get(config: &DohConfig, dns_wire: &[u8]) -> Self {
        let encoded = base64url_encode(dns_wire);
        let url = if config.endpoint.contains('?') {
            alloc::format!("{}&dns={encoded}", config.endpoint)
        } else {
            alloc::format!("{}?dns={encoded}", config.endpoint)
        };

        Self {
            url,
            method: DohMethod::Get,
            content_type: config.accept,
            body: Vec::new(),
        }
    }

    /// リクエストボディサイズ。
    #[must_use]
    pub const fn body_size(&self) -> usize {
        self.body.len()
    }
}

/// `DoH` レスポンス。
#[derive(Debug, Clone)]
pub struct DohResponse {
    /// HTTP ステータスコード。
    pub status: u16,
    /// DNS ワイヤフォーマットボディ。
    pub body: Vec<u8>,
    /// TTL (Cache-Control ヘッダーから)。
    pub cache_ttl: Option<u64>,
}

impl DohResponse {
    /// レスポンスが成功か。
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// DNS パケットサイズ。
    #[must_use]
    pub const fn dns_size(&self) -> usize {
        self.body.len()
    }

    /// HTTP レスポンスから `DohResponse` を構築。
    #[must_use]
    pub const fn from_http(status: u16, body: Vec<u8>, cache_ttl: Option<u64>) -> Self {
        Self {
            status,
            body,
            cache_ttl,
        }
    }
}

/// `DoH` クライアント。
#[derive(Debug)]
pub struct DohClient {
    /// 設定。
    config: DohConfig,
    /// クエリ送信数。
    queries_sent: u64,
    /// エラー数。
    errors: u64,
}

impl DohClient {
    /// 新しいクライアントを作成。
    #[must_use]
    pub const fn new(config: DohConfig) -> Self {
        Self {
            config,
            queries_sent: 0,
            errors: 0,
        }
    }

    /// 設定への参照。
    #[must_use]
    pub const fn config(&self) -> &DohConfig {
        &self.config
    }

    /// DNS ワイヤフォーマットから POST リクエストを構築。
    #[must_use]
    pub fn build_post_request(&self, dns_wire: Vec<u8>) -> DohRequest {
        DohRequest::post(&self.config, dns_wire)
    }

    /// DNS ワイヤフォーマットから GET リクエストを構築。
    #[must_use]
    pub fn build_get_request(&self, dns_wire: &[u8]) -> DohRequest {
        DohRequest::get(&self.config, dns_wire)
    }

    /// レスポンスを処理し統計を更新。
    ///
    /// # Errors
    ///
    /// HTTP エラーまたは空レスポンスの場合。
    pub const fn process_response(&mut self, response: &DohResponse) -> Result<(), DohError> {
        self.queries_sent += 1;

        if !response.is_success() {
            self.errors += 1;
            return Err(DohError::HttpError(response.status));
        }

        if response.body.is_empty() {
            self.errors += 1;
            return Err(DohError::EmptyResponse);
        }

        Ok(())
    }

    /// 送信クエリ数。
    #[must_use]
    pub const fn queries_sent(&self) -> u64 {
        self.queries_sent
    }

    /// エラー数。
    #[must_use]
    pub const fn errors(&self) -> u64 {
        self.errors
    }
}

/// DNS パディング (RFC 8467)。
///
/// パケットサイズを 128 バイト境界にパディング。
#[must_use]
pub fn pad_dns_query(wire: &[u8]) -> Vec<u8> {
    let target_size = wire.len().div_ceil(128) * 128;
    let mut padded = Vec::with_capacity(target_size);
    padded.extend_from_slice(wire);
    padded.resize(target_size, 0);
    padded
}

/// Base64url エンコード (パディングなし、RFC 4648 Section 5)。
#[must_use]
pub fn base64url_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = String::with_capacity((data.len() * 4).div_ceil(3));
    let mut i = 0;

    while i + 2 < data.len() {
        let n = (u32::from(data[i]) << 16) | (u32::from(data[i + 1]) << 8) | u32::from(data[i + 2]);
        result.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        result.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        result.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        result.push(TABLE[(n & 0x3F) as usize] as char);
        i += 3;
    }

    let remaining = data.len() - i;
    if remaining == 2 {
        let n = (u32::from(data[i]) << 16) | (u32::from(data[i + 1]) << 8);
        result.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        result.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        result.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
    } else if remaining == 1 {
        let n = u32::from(data[i]) << 16;
        result.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        result.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
    }

    result
}

/// `DoH` エラー。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DohError {
    /// HTTP エラーステータス。
    HttpError(u16),
    /// 空レスポンス。
    EmptyResponse,
    /// タイムアウト。
    Timeout,
    /// 接続エラー。
    ConnectionError,
}

impl core::fmt::Display for DohError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HttpError(code) => write!(f, "HTTP error: {code}"),
            Self::EmptyResponse => write!(f, "Empty DNS response"),
            Self::Timeout => write!(f, "DoH query timeout"),
            Self::ConnectionError => write!(f, "Connection error"),
        }
    }
}

impl std::error::Error for DohError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = DohConfig::default();
        assert_eq!(config.endpoint, "https://1.1.1.1/dns-query");
        assert_eq!(config.timeout_ms, 5000);
        assert!(config.padding);
    }

    #[test]
    fn content_type_str() {
        assert_eq!(
            DohContentType::DnsMessage.as_str(),
            "application/dns-message"
        );
        assert_eq!(DohContentType::DnsJson.as_str(), "application/dns-json");
    }

    #[test]
    fn content_type_display() {
        assert_eq!(
            DohContentType::DnsMessage.to_string(),
            "application/dns-message"
        );
    }

    #[test]
    fn method_display() {
        assert_eq!(DohMethod::Get.to_string(), "GET");
        assert_eq!(DohMethod::Post.to_string(), "POST");
    }

    #[test]
    fn post_request() {
        let config = DohConfig::default();
        let dns_wire = vec![0x12, 0x34, 0x01, 0x00];
        let req = DohRequest::post(&config, dns_wire.clone());
        assert_eq!(req.method, DohMethod::Post);
        assert_eq!(req.body, dns_wire);
        assert_eq!(req.body_size(), 4);
    }

    #[test]
    fn get_request_encodes_dns() {
        let config = DohConfig::default();
        let dns_wire = vec![0x12, 0x34];
        let req = DohRequest::get(&config, &dns_wire);
        assert_eq!(req.method, DohMethod::Get);
        assert!(req.url.contains("?dns="));
        assert!(req.body.is_empty());
    }

    #[test]
    fn response_success() {
        let resp = DohResponse::from_http(200, vec![0x12], None);
        assert!(resp.is_success());
        assert_eq!(resp.dns_size(), 1);
    }

    #[test]
    fn response_error() {
        let resp = DohResponse::from_http(503, vec![], None);
        assert!(!resp.is_success());
    }

    #[test]
    fn client_stats() {
        let config = DohConfig::default();
        let mut client = DohClient::new(config);
        assert_eq!(client.queries_sent(), 0);
        assert_eq!(client.errors(), 0);

        let ok_resp = DohResponse::from_http(200, vec![0x01], None);
        client.process_response(&ok_resp).unwrap();
        assert_eq!(client.queries_sent(), 1);

        let err_resp = DohResponse::from_http(500, vec![], None);
        assert!(client.process_response(&err_resp).is_err());
        assert_eq!(client.errors(), 1);
    }

    #[test]
    fn client_empty_response_error() {
        let mut client = DohClient::new(DohConfig::default());
        let resp = DohResponse::from_http(200, vec![], None);
        assert_eq!(client.process_response(&resp), Err(DohError::EmptyResponse));
    }

    #[test]
    fn base64url_encode_test() {
        assert_eq!(base64url_encode(b""), "");
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"fo"), "Zm8");
        assert_eq!(base64url_encode(b"foo"), "Zm9v");
        assert_eq!(base64url_encode(b"foob"), "Zm9vYg");
    }

    #[test]
    fn pad_dns_query_test() {
        let wire = vec![0u8; 50];
        let padded = pad_dns_query(&wire);
        assert_eq!(padded.len(), 128);
        assert_eq!(&padded[..50], &wire[..]);

        let exact = vec![0u8; 128];
        assert_eq!(pad_dns_query(&exact).len(), 128);
    }

    #[test]
    fn doh_error_display() {
        assert_eq!(DohError::HttpError(404).to_string(), "HTTP error: 404");
        assert_eq!(DohError::EmptyResponse.to_string(), "Empty DNS response");
        assert_eq!(DohError::Timeout.to_string(), "DoH query timeout");
    }
}
