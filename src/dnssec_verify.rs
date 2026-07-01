//! `DNSSEC` (`RFC 4033/4034/4035`) verifier — `Ed25519` signature algorithm.
//!
//! Focuses on the `Ed25519` signing algorithm (`RFC 8080`, algorithm ID
//! `15`) which the wider DNSSEC ecosystem is moving toward. The RSA/SHA-256
//! and ECDSA algorithms defined by `RFC 5702` / `RFC 6605` are out of scope
//! for this pragmatic subset — a future revision can plug them in behind
//! the [`DnssecAlgorithm`] enum.
//!
//! The verifier consumes:
//!
//! - The canonical byte layout of an `RRSIG` record (per `RFC 4034 §3.1.8.1`).
//! - The concatenation of every `RR` in the answer's canonical form
//!   (`RFC 4034 §6`).
//! - A `DNSKEY` public key.
//!
//! It returns `true` when the signature verifies. Trust-chain construction
//! (`DS` → `DNSKEY` walk) is delegated to the caller.

use alice_blockchain::{PublicKey, Signature};

// ---------------------------------------------------------------------------
// DnssecAlgorithm
// ---------------------------------------------------------------------------

/// Subset of DNSSEC signing algorithms currently modelled.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnssecAlgorithm {
    /// `Ed25519` (`RFC 8080`, IANA `15`).
    Ed25519,
    /// `Ed448` (`RFC 8080`, IANA `16`). Recognised but not supported by this
    /// verifier — verifying returns `false` and callers should fall back to
    /// a full DNSSEC library.
    Ed448,
}

impl DnssecAlgorithm {
    /// Map from `IANA` numeric identifier.
    #[must_use]
    pub const fn from_iana(code: u8) -> Option<Self> {
        match code {
            15 => Some(Self::Ed25519),
            16 => Some(Self::Ed448),
            _ => None,
        }
    }

    /// `IANA` numeric identifier.
    #[must_use]
    pub const fn to_iana(self) -> u8 {
        match self {
            Self::Ed25519 => 15,
            Self::Ed448 => 16,
        }
    }
}

// ---------------------------------------------------------------------------
// RrsigCore
// ---------------------------------------------------------------------------

/// The signed portion of an `RRSIG` record (excluding the signature bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrsigCore {
    pub type_covered: u16,
    pub algorithm: DnssecAlgorithm,
    pub labels: u8,
    pub original_ttl: u32,
    pub signature_expiration_unix: u32,
    pub signature_inception_unix: u32,
    pub key_tag: u16,
    pub signer_name: Vec<u8>,
}

impl RrsigCore {
    /// Canonical byte layout used as the `signing_input` prefix per `RFC 4034
    /// §3.1.8.1`.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(18 + self.signer_name.len());
        buf.extend_from_slice(&self.type_covered.to_be_bytes());
        buf.push(self.algorithm.to_iana());
        buf.push(self.labels);
        buf.extend_from_slice(&self.original_ttl.to_be_bytes());
        buf.extend_from_slice(&self.signature_expiration_unix.to_be_bytes());
        buf.extend_from_slice(&self.signature_inception_unix.to_be_bytes());
        buf.extend_from_slice(&self.key_tag.to_be_bytes());
        buf.extend_from_slice(&self.signer_name);
        buf
    }

    /// Whether `unix_seconds` falls inside `[inception, expiration]`.
    #[must_use]
    pub const fn is_valid_at(&self, unix_seconds: u32) -> bool {
        unix_seconds >= self.signature_inception_unix
            && unix_seconds <= self.signature_expiration_unix
    }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Verify a DNSSEC `RRSIG` over the canonicalised `RR` set.
///
/// `key_bytes` is the `DNSKEY` public key material (32 bytes for
/// `Ed25519`). `signature_bytes` is the raw signature (64 bytes for
/// `Ed25519`). `rrset_canonical` is the caller-provided concatenation of
/// canonicalised `RR`s.
#[must_use]
pub fn verify_rrsig(
    core: &RrsigCore,
    rrset_canonical: &[u8],
    key_bytes: &[u8],
    signature_bytes: &[u8],
) -> bool {
    match core.algorithm {
        DnssecAlgorithm::Ed25519 => {
            verify_ed25519(core, rrset_canonical, key_bytes, signature_bytes)
        }
        DnssecAlgorithm::Ed448 => false,
    }
}

fn verify_ed25519(
    core: &RrsigCore,
    rrset_canonical: &[u8],
    key_bytes: &[u8],
    signature_bytes: &[u8],
) -> bool {
    if key_bytes.len() != 32 || signature_bytes.len() != 64 {
        return false;
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(key_bytes);
    let pk = PublicKey(key_arr);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(signature_bytes);
    let sig = Signature(sig_arr);
    let mut signing_input = core.canonical_bytes();
    signing_input.extend_from_slice(rrset_canonical);
    pk.verify(&signing_input, &sig)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alice_blockchain::KeyPair;

    fn sample_core() -> RrsigCore {
        RrsigCore {
            type_covered: 1, // A
            algorithm: DnssecAlgorithm::Ed25519,
            labels: 2,
            original_ttl: 3600,
            signature_expiration_unix: 1_800_000_000,
            signature_inception_unix: 1_700_000_000,
            key_tag: 0x1234,
            signer_name: b"\x07example\x03com\x00".to_vec(),
        }
    }

    #[test]
    fn algorithm_iana_roundtrip() {
        assert_eq!(
            DnssecAlgorithm::from_iana(15),
            Some(DnssecAlgorithm::Ed25519)
        );
        assert_eq!(DnssecAlgorithm::from_iana(16), Some(DnssecAlgorithm::Ed448));
        assert!(DnssecAlgorithm::from_iana(0).is_none());
        assert_eq!(DnssecAlgorithm::Ed25519.to_iana(), 15);
        assert_eq!(DnssecAlgorithm::Ed448.to_iana(), 16);
    }

    #[test]
    fn canonical_bytes_length_covers_static_fields() {
        let core = sample_core();
        let bytes = core.canonical_bytes();
        // 2 + 1 + 1 + 4 + 4 + 4 + 2 = 18 static bytes plus signer name.
        assert_eq!(bytes.len(), 18 + core.signer_name.len());
    }

    #[test]
    fn validity_window_edges() {
        let core = sample_core();
        assert!(core.is_valid_at(core.signature_inception_unix));
        assert!(core.is_valid_at(core.signature_expiration_unix));
        assert!(!core.is_valid_at(core.signature_inception_unix - 1));
        assert!(!core.is_valid_at(core.signature_expiration_unix + 1));
    }

    #[test]
    fn valid_ed25519_signature_verifies() {
        let signer = KeyPair::from_seed([1u8; 32]);
        let core = sample_core();
        let rrset = b"\x03www\x07example\x03com\x00\x00\x01\x00\x01".to_vec();
        let mut signing_input = core.canonical_bytes();
        signing_input.extend_from_slice(&rrset);
        let sig = signer.sign(&signing_input);
        assert!(verify_rrsig(&core, &rrset, &signer.public().0, &sig.0));
    }

    #[test]
    fn tampered_rrset_rejects_signature() {
        let signer = KeyPair::from_seed([1u8; 32]);
        let core = sample_core();
        let rrset = b"payload".to_vec();
        let mut signing_input = core.canonical_bytes();
        signing_input.extend_from_slice(&rrset);
        let sig = signer.sign(&signing_input);
        let mut tampered = rrset.clone();
        tampered[0] ^= 0xFF;
        assert!(!verify_rrsig(&core, &tampered, &signer.public().0, &sig.0));
    }

    #[test]
    fn ed448_algorithm_is_not_yet_supported() {
        let signer = KeyPair::from_seed([1u8; 32]);
        let mut core = sample_core();
        core.algorithm = DnssecAlgorithm::Ed448;
        let rrset = b"payload".to_vec();
        let mut signing_input = core.canonical_bytes();
        signing_input.extend_from_slice(&rrset);
        let sig = signer.sign(&signing_input);
        // Even a technically valid Ed25519 signature is rejected because
        // Ed448 verification is not implemented.
        assert!(!verify_rrsig(&core, &rrset, &signer.public().0, &sig.0));
    }

    #[test]
    fn wrong_key_length_rejects() {
        let core = sample_core();
        assert!(!verify_rrsig(&core, b"payload", &[0u8; 16], &[0u8; 64]));
    }

    #[test]
    fn wrong_signature_length_rejects() {
        let core = sample_core();
        assert!(!verify_rrsig(&core, b"payload", &[0u8; 32], &[0u8; 32]));
    }

    #[test]
    fn wrong_key_material_rejects_signature() {
        let signer = KeyPair::from_seed([1u8; 32]);
        let other = KeyPair::from_seed([2u8; 32]);
        let core = sample_core();
        let rrset = b"payload".to_vec();
        let mut signing_input = core.canonical_bytes();
        signing_input.extend_from_slice(&rrset);
        let sig = signer.sign(&signing_input);
        assert!(!verify_rrsig(&core, &rrset, &other.public().0, &sig.0));
    }
}
