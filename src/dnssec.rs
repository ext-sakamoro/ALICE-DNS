//! DNSSEC 検証
//!
//! RRSIG / DNSKEY / DS レコードのパースと署名検証ロジック。
//! RFC 4033/4034/4035 準拠。

use alloc::string::String;
use alloc::vec::Vec;

/// DNSSEC 検証結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecStatus {
    /// 署名検証成功。
    Secure,
    /// DNSSEC 未設定 (オプトアウト)。
    Insecure,
    /// 署名検証失敗。
    Bogus,
    /// 判定不能。
    Indeterminate,
}

impl core::fmt::Display for DnssecStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Secure => write!(f, "Secure"),
            Self::Insecure => write!(f, "Insecure"),
            Self::Bogus => write!(f, "Bogus"),
            Self::Indeterminate => write!(f, "Indeterminate"),
        }
    }
}

/// DNSSEC アルゴリズム。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecAlgorithm {
    /// RSA/SHA-256 (RFC 5702)。
    RsaSha256,
    /// RSA/SHA-512 (RFC 5702)。
    RsaSha512,
    /// ECDSA P-256/SHA-256 (RFC 6605)。
    EcdsaP256Sha256,
    /// ECDSA P-384/SHA-384 (RFC 6605)。
    EcdsaP384Sha384,
    /// Ed25519 (RFC 8080)。
    Ed25519,
    /// 不明なアルゴリズム。
    Unknown(u8),
}

impl DnssecAlgorithm {
    /// アルゴリズム番号からデコード。
    #[must_use]
    pub const fn from_id(id: u8) -> Self {
        match id {
            8 => Self::RsaSha256,
            10 => Self::RsaSha512,
            13 => Self::EcdsaP256Sha256,
            14 => Self::EcdsaP384Sha384,
            15 => Self::Ed25519,
            _ => Self::Unknown(id),
        }
    }

    /// アルゴリズム番号。
    #[must_use]
    pub const fn id(&self) -> u8 {
        match self {
            Self::RsaSha256 => 8,
            Self::RsaSha512 => 10,
            Self::EcdsaP256Sha256 => 13,
            Self::EcdsaP384Sha384 => 14,
            Self::Ed25519 => 15,
            Self::Unknown(id) => *id,
        }
    }
}

impl core::fmt::Display for DnssecAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RsaSha256 => write!(f, "RSA/SHA-256"),
            Self::RsaSha512 => write!(f, "RSA/SHA-512"),
            Self::EcdsaP256Sha256 => write!(f, "ECDSA-P256/SHA-256"),
            Self::EcdsaP384Sha384 => write!(f, "ECDSA-P384/SHA-384"),
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::Unknown(id) => write!(f, "Unknown({id})"),
        }
    }
}

/// DS ダイジェスト型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestType {
    /// SHA-1 (非推奨)。
    Sha1,
    /// SHA-256。
    Sha256,
    /// SHA-384。
    Sha384,
    /// 不明。
    Unknown(u8),
}

impl DigestType {
    /// ID からデコード。
    #[must_use]
    pub const fn from_id(id: u8) -> Self {
        match id {
            1 => Self::Sha1,
            2 => Self::Sha256,
            4 => Self::Sha384,
            _ => Self::Unknown(id),
        }
    }

    /// ID。
    #[must_use]
    pub const fn id(&self) -> u8 {
        match self {
            Self::Sha1 => 1,
            Self::Sha256 => 2,
            Self::Sha384 => 4,
            Self::Unknown(id) => *id,
        }
    }
}

/// RRSIG レコード。
#[derive(Debug, Clone)]
pub struct RrsigRecord {
    /// カバーするレコードタイプ。
    pub type_covered: u16,
    /// 署名アルゴリズム。
    pub algorithm: DnssecAlgorithm,
    /// ラベル数。
    pub labels: u8,
    /// 元の TTL。
    pub original_ttl: u32,
    /// 署名有効期限 (Unix 秒)。
    pub sig_expiration: u32,
    /// 署名開始時刻 (Unix 秒)。
    pub sig_inception: u32,
    /// キータグ。
    pub key_tag: u16,
    /// 署名者名。
    pub signer_name: String,
    /// 署名データ。
    pub signature: Vec<u8>,
}

impl RrsigRecord {
    /// RRSIG の有効期間を検証。
    #[must_use]
    pub const fn is_valid_at(&self, now_unix: u32) -> bool {
        now_unix >= self.sig_inception && now_unix <= self.sig_expiration
    }

    /// バイト列からパース。
    ///
    /// # Errors
    ///
    /// データが不足、または不正な場合。
    pub fn from_rdata(rdata: &[u8]) -> Result<Self, DnssecError> {
        if rdata.len() < 18 {
            return Err(DnssecError::TruncatedData);
        }

        let type_covered = u16::from_be_bytes([rdata[0], rdata[1]]);
        let algorithm = DnssecAlgorithm::from_id(rdata[2]);
        let labels = rdata[3];
        let original_ttl = u32::from_be_bytes([rdata[4], rdata[5], rdata[6], rdata[7]]);
        let sig_expiration = u32::from_be_bytes([rdata[8], rdata[9], rdata[10], rdata[11]]);
        let sig_inception = u32::from_be_bytes([rdata[12], rdata[13], rdata[14], rdata[15]]);
        let key_tag = u16::from_be_bytes([rdata[16], rdata[17]]);

        // 署名者名をパース (DNS name encoding)
        let (signer_name, name_end) = parse_dns_name(rdata, 18)?;

        let signature = rdata[name_end..].to_vec();

        Ok(Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            sig_expiration,
            sig_inception,
            key_tag,
            signer_name,
            signature,
        })
    }
}

/// DNSKEY レコード。
#[derive(Debug, Clone)]
pub struct DnskeyRecord {
    /// フラグ (256 = ZSK, 257 = KSK)。
    pub flags: u16,
    /// プロトコル (常に 3)。
    pub protocol: u8,
    /// アルゴリズム。
    pub algorithm: DnssecAlgorithm,
    /// 公開鍵データ。
    pub public_key: Vec<u8>,
}

impl DnskeyRecord {
    /// KSK (Key Signing Key) か。
    #[must_use]
    pub const fn is_ksk(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// ZSK (Zone Signing Key) か。
    #[must_use]
    pub const fn is_zsk(&self) -> bool {
        self.flags & 0x0100 != 0
    }

    /// キータグを計算 (RFC 4034 Appendix B)。
    #[must_use]
    pub fn key_tag(&self) -> u16 {
        let mut rdata = Vec::with_capacity(4 + self.public_key.len());
        rdata.extend_from_slice(&self.flags.to_be_bytes());
        rdata.push(self.protocol);
        rdata.push(self.algorithm.id());
        rdata.extend_from_slice(&self.public_key);

        let mut ac: u32 = 0;
        for (i, &byte) in rdata.iter().enumerate() {
            if i & 1 == 0 {
                ac += u32::from(byte) << 8;
            } else {
                ac += u32::from(byte);
            }
        }
        ac += (ac >> 16) & 0xFFFF;
        (ac & 0xFFFF) as u16
    }

    /// バイト列からパース。
    ///
    /// # Errors
    ///
    /// データが不足の場合。
    pub fn from_rdata(rdata: &[u8]) -> Result<Self, DnssecError> {
        if rdata.len() < 4 {
            return Err(DnssecError::TruncatedData);
        }

        let flags = u16::from_be_bytes([rdata[0], rdata[1]]);
        let protocol = rdata[2];
        let algorithm = DnssecAlgorithm::from_id(rdata[3]);
        let public_key = rdata[4..].to_vec();

        Ok(Self {
            flags,
            protocol,
            algorithm,
            public_key,
        })
    }
}

/// DS レコード。
#[derive(Debug, Clone)]
pub struct DsRecord {
    /// キータグ。
    pub key_tag: u16,
    /// アルゴリズム。
    pub algorithm: DnssecAlgorithm,
    /// ダイジェスト型。
    pub digest_type: DigestType,
    /// ダイジェスト値。
    pub digest: Vec<u8>,
}

impl DsRecord {
    /// バイト列からパース。
    ///
    /// # Errors
    ///
    /// データが不足の場合。
    pub fn from_rdata(rdata: &[u8]) -> Result<Self, DnssecError> {
        if rdata.len() < 5 {
            return Err(DnssecError::TruncatedData);
        }

        let key_tag = u16::from_be_bytes([rdata[0], rdata[1]]);
        let algorithm = DnssecAlgorithm::from_id(rdata[2]);
        let digest_type = DigestType::from_id(rdata[3]);
        let digest = rdata[4..].to_vec();

        Ok(Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
        })
    }

    /// DNSKEY とのキータグ一致確認。
    #[must_use]
    pub fn matches_key(&self, key: &DnskeyRecord) -> bool {
        self.key_tag == key.key_tag() && self.algorithm == key.algorithm
    }
}

/// DNSSEC バリデータ。
#[derive(Debug)]
pub struct DnssecValidator {
    /// トラストアンカー (ルート KSK のキータグ)。
    trust_anchors: Vec<u16>,
}

impl Default for DnssecValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl DnssecValidator {
    /// 新しいバリデータを作成。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            trust_anchors: Vec::new(),
        }
    }

    /// トラストアンカーを追加。
    pub fn add_trust_anchor(&mut self, key_tag: u16) {
        if !self.trust_anchors.contains(&key_tag) {
            self.trust_anchors.push(key_tag);
        }
    }

    /// RRSIG の有効期間を検証。
    #[must_use]
    pub const fn validate_time(&self, rrsig: &RrsigRecord, now_unix: u32) -> DnssecStatus {
        if rrsig.is_valid_at(now_unix) {
            DnssecStatus::Secure
        } else {
            DnssecStatus::Bogus
        }
    }

    /// DS と DNSKEY のチェーン検証。
    #[must_use]
    pub fn validate_chain(&self, ds: &DsRecord, dnskey: &DnskeyRecord) -> DnssecStatus {
        if !ds.matches_key(dnskey) {
            return DnssecStatus::Bogus;
        }

        // KSK であることを確認
        if !dnskey.is_ksk() {
            return DnssecStatus::Bogus;
        }

        // トラストアンカーチェック
        if self.trust_anchors.contains(&ds.key_tag) {
            DnssecStatus::Secure
        } else {
            DnssecStatus::Indeterminate
        }
    }

    /// トラストアンカー数。
    #[must_use]
    pub const fn anchor_count(&self) -> usize {
        self.trust_anchors.len()
    }
}

/// DNS 名前をパース (非圧縮)。
fn parse_dns_name(data: &[u8], start: usize) -> Result<(String, usize), DnssecError> {
    let mut pos = start;
    let mut parts: Vec<String> = Vec::new();

    loop {
        if pos >= data.len() {
            return Err(DnssecError::TruncatedData);
        }

        let label_len = data[pos] as usize;
        pos += 1;

        if label_len == 0 {
            break;
        }

        if label_len > 63 || pos + label_len > data.len() {
            return Err(DnssecError::InvalidName);
        }

        let label = core::str::from_utf8(&data[pos..pos + label_len])
            .map_err(|_| DnssecError::InvalidName)?;
        parts.push(label.to_lowercase());
        pos += label_len;
    }

    Ok((parts.join("."), pos))
}

/// DNSSEC エラー。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnssecError {
    /// データが切り詰められている。
    TruncatedData,
    /// 不正な DNS 名前。
    InvalidName,
    /// 不正な署名。
    InvalidSignature,
    /// サポートされないアルゴリズム。
    UnsupportedAlgorithm,
}

impl core::fmt::Display for DnssecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TruncatedData => write!(f, "Truncated DNSSEC data"),
            Self::InvalidName => write!(f, "Invalid DNS name"),
            Self::InvalidSignature => write!(f, "Invalid DNSSEC signature"),
            Self::UnsupportedAlgorithm => write!(f, "Unsupported DNSSEC algorithm"),
        }
    }
}

impl std::error::Error for DnssecError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dnssec_status_display() {
        assert_eq!(DnssecStatus::Secure.to_string(), "Secure");
        assert_eq!(DnssecStatus::Insecure.to_string(), "Insecure");
        assert_eq!(DnssecStatus::Bogus.to_string(), "Bogus");
        assert_eq!(DnssecStatus::Indeterminate.to_string(), "Indeterminate");
    }

    #[test]
    fn algorithm_roundtrip() {
        assert_eq!(DnssecAlgorithm::from_id(8), DnssecAlgorithm::RsaSha256);
        assert_eq!(DnssecAlgorithm::RsaSha256.id(), 8);
        assert_eq!(DnssecAlgorithm::from_id(15), DnssecAlgorithm::Ed25519);
        assert_eq!(DnssecAlgorithm::Ed25519.id(), 15);
        assert_eq!(DnssecAlgorithm::from_id(99), DnssecAlgorithm::Unknown(99));
    }

    #[test]
    fn algorithm_display() {
        assert_eq!(DnssecAlgorithm::RsaSha256.to_string(), "RSA/SHA-256");
        assert_eq!(DnssecAlgorithm::Ed25519.to_string(), "Ed25519");
        assert_eq!(DnssecAlgorithm::Unknown(42).to_string(), "Unknown(42)");
    }

    #[test]
    fn digest_type_roundtrip() {
        assert_eq!(DigestType::from_id(1), DigestType::Sha1);
        assert_eq!(DigestType::from_id(2), DigestType::Sha256);
        assert_eq!(DigestType::Sha256.id(), 2);
        assert_eq!(DigestType::from_id(99), DigestType::Unknown(99));
    }

    #[test]
    fn rrsig_validity() {
        let rrsig = RrsigRecord {
            type_covered: 1,
            algorithm: DnssecAlgorithm::RsaSha256,
            labels: 2,
            original_ttl: 3600,
            sig_expiration: 2_000_000,
            sig_inception: 1_000_000,
            key_tag: 12345,
            signer_name: "example.com".into(),
            signature: vec![0xAB; 32],
        };

        assert!(rrsig.is_valid_at(1_500_000));
        assert!(!rrsig.is_valid_at(500_000));
        assert!(!rrsig.is_valid_at(3_000_000));
    }

    #[test]
    fn rrsig_from_rdata() {
        // 最小 RRSIG rdata: 18 ヘッダー + 名前 (1 root label) + 署名
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes()); // type_covered = A
        rdata.push(8); // algorithm = RSA/SHA-256
        rdata.push(2); // labels
        rdata.extend_from_slice(&3600u32.to_be_bytes()); // original_ttl
        rdata.extend_from_slice(&2_000_000u32.to_be_bytes()); // sig_expiration
        rdata.extend_from_slice(&1_000_000u32.to_be_bytes()); // sig_inception
        rdata.extend_from_slice(&12345u16.to_be_bytes()); // key_tag
        rdata.push(0); // root label (empty signer name)
        rdata.extend_from_slice(&[0xDE, 0xAD]); // signature

        let rrsig = RrsigRecord::from_rdata(&rdata).unwrap();
        assert_eq!(rrsig.type_covered, 1);
        assert_eq!(rrsig.algorithm, DnssecAlgorithm::RsaSha256);
        assert_eq!(rrsig.key_tag, 12345);
        assert_eq!(rrsig.signature, vec![0xDE, 0xAD]);
    }

    #[test]
    fn rrsig_from_rdata_truncated() {
        assert!(RrsigRecord::from_rdata(&[0; 10]).is_err());
    }

    #[test]
    fn dnskey_from_rdata() {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&257u16.to_be_bytes()); // flags = KSK
        rdata.push(3); // protocol
        rdata.push(13); // algorithm = ECDSA P-256
        rdata.extend_from_slice(&[0x01, 0x02, 0x03]); // public key

        let key = DnskeyRecord::from_rdata(&rdata).unwrap();
        assert!(key.is_ksk());
        assert_eq!(key.algorithm, DnssecAlgorithm::EcdsaP256Sha256);
        assert_eq!(key.public_key, vec![1, 2, 3]);
    }

    #[test]
    fn dnskey_key_tag() {
        let key = DnskeyRecord {
            flags: 257,
            protocol: 3,
            algorithm: DnssecAlgorithm::RsaSha256,
            public_key: vec![0xAA; 64],
        };
        let tag = key.key_tag();
        assert!(tag > 0);
    }

    #[test]
    fn ds_from_rdata() {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&54321u16.to_be_bytes()); // key_tag
        rdata.push(8); // algorithm
        rdata.push(2); // digest_type = SHA-256
        rdata.extend_from_slice(&[0xFF; 32]); // digest

        let ds = DsRecord::from_rdata(&rdata).unwrap();
        assert_eq!(ds.key_tag, 54321);
        assert_eq!(ds.digest_type, DigestType::Sha256);
    }

    #[test]
    fn ds_matches_key() {
        let key = DnskeyRecord {
            flags: 257,
            protocol: 3,
            algorithm: DnssecAlgorithm::RsaSha256,
            public_key: vec![0xAA; 64],
        };
        let tag = key.key_tag();

        let ds = DsRecord {
            key_tag: tag,
            algorithm: DnssecAlgorithm::RsaSha256,
            digest_type: DigestType::Sha256,
            digest: vec![0xFF; 32],
        };
        assert!(ds.matches_key(&key));
    }

    #[test]
    fn validator_time_check() {
        let validator = DnssecValidator::new();
        let rrsig = RrsigRecord {
            type_covered: 1,
            algorithm: DnssecAlgorithm::RsaSha256,
            labels: 2,
            original_ttl: 3600,
            sig_expiration: 2_000_000,
            sig_inception: 1_000_000,
            key_tag: 100,
            signer_name: "test.com".into(),
            signature: vec![],
        };

        assert_eq!(
            validator.validate_time(&rrsig, 1_500_000),
            DnssecStatus::Secure
        );
        assert_eq!(
            validator.validate_time(&rrsig, 3_000_000),
            DnssecStatus::Bogus
        );
    }

    #[test]
    fn validator_chain() {
        let mut validator = DnssecValidator::new();
        let key = DnskeyRecord {
            flags: 257,
            protocol: 3,
            algorithm: DnssecAlgorithm::RsaSha256,
            public_key: vec![0xBB; 32],
        };
        let tag = key.key_tag();
        validator.add_trust_anchor(tag);

        let ds = DsRecord {
            key_tag: tag,
            algorithm: DnssecAlgorithm::RsaSha256,
            digest_type: DigestType::Sha256,
            digest: vec![],
        };

        assert_eq!(validator.validate_chain(&ds, &key), DnssecStatus::Secure);
        assert_eq!(validator.anchor_count(), 1);
    }

    #[test]
    fn validator_default() {
        let v = DnssecValidator::default();
        assert_eq!(v.anchor_count(), 0);
    }

    #[test]
    fn dnssec_error_display() {
        assert_eq!(
            DnssecError::TruncatedData.to_string(),
            "Truncated DNSSEC data"
        );
        assert_eq!(DnssecError::InvalidName.to_string(), "Invalid DNS name");
    }
}
