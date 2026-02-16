//! DNS Packet Parsing and Response Generation
//!
//! Minimal DNS implementation — just enough to:
//! 1. Parse incoming UDP queries (extract QNAME)
//! 2. Generate blocked responses (A record → 0.0.0.0)
//! 3. Forward allowed queries to upstream
//!
//! No external DNS library dependencies. Pure byte manipulation.
//!
//! # DNS Packet Format (RFC 1035)
//!
//! ```text
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                      ID                         |  2 bytes
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE    |  2 bytes (flags)
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                    QDCOUNT                       |  2 bytes
//! |                    ANCOUNT                       |  2 bytes
//! |                    NSCOUNT                       |  2 bytes
//! |                    ARCOUNT                       |  2 bytes
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                   Questions ...                  |
//! |                   Answers ...                    |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! ```

/// Minimum DNS header size (12 bytes).
const DNS_HEADER_SIZE: usize = 12;

/// DNS record type: A (IPv4 address).
pub const QTYPE_A: u16 = 1;
/// DNS record type: AAAA (IPv6 address).
pub const QTYPE_AAAA: u16 = 28;
/// DNS record class: IN (Internet).
const QCLASS_IN: u16 = 1;

/// Parsed DNS query.
#[derive(Debug)]
pub struct DnsQuery {
    /// Transaction ID (echoed back in response).
    pub id: u16,
    /// Original flags from the query.
    pub flags: u16,
    /// Queried domain name (e.g., "ads.doubleclick.net").
    pub qname: String,
    /// Query type (1=A, 28=AAAA, etc.).
    pub qtype: u16,
    /// Query class (1=IN).
    pub qclass: u16,
    /// Byte offset where the question section ends (for forwarding).
    pub question_end: usize,
}

/// Parse a DNS query packet.
///
/// Returns `None` if the packet is malformed or not a standard query.
pub fn parse_query(packet: &[u8]) -> Option<DnsQuery> {
    if packet.len() < DNS_HEADER_SIZE {
        return None;
    }

    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);

    // Must be a standard query (QR=0, Opcode=0)
    let qr = (flags >> 15) & 1;
    let opcode = (flags >> 11) & 0xF;
    if qr != 0 || opcode != 0 {
        return None;
    }

    // We only handle single-question queries
    if qdcount == 0 {
        return None;
    }

    // Parse QNAME (sequence of labels)
    let mut pos = DNS_HEADER_SIZE;
    let mut qname_parts: Vec<String> = Vec::new();

    loop {
        if pos >= packet.len() {
            return None;
        }

        let label_len = packet[pos] as usize;
        pos += 1;

        if label_len == 0 {
            break; // Root label — end of QNAME
        }

        // Sanity check: label max 63 bytes, no compression in queries
        if label_len > 63 || pos + label_len > packet.len() {
            return None;
        }

        let label = &packet[pos..pos + label_len];
        // Convert to lowercase during parsing (branchless)
        let mut label_str = String::with_capacity(label_len);
        for &b in label {
            let is_upper = b.wrapping_sub(b'A') < 26;
            let offset = (is_upper as u8) << 5;
            label_str.push((b + offset) as char);
        }
        qname_parts.push(label_str);
        pos += label_len;
    }

    // Parse QTYPE and QCLASS
    if pos + 4 > packet.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    let qclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
    pos += 4;

    let qname = qname_parts.join(".");

    Some(DnsQuery {
        id,
        flags,
        qname,
        qtype,
        qclass,
        question_end: pos,
    })
}

/// Build a DNS response that blocks a domain.
///
/// Returns an A record pointing to 0.0.0.0 (or :: for AAAA).
/// The response echoes back the original question section.
///
/// # Response flags
///
/// - QR=1 (response)
/// - AA=1 (authoritative)
/// - RD=1 (recursion desired, echoed from query)
/// - RA=1 (recursion available)
/// - RCODE=0 (no error)
pub fn build_blocked_response(query_packet: &[u8], query: &DnsQuery) -> Vec<u8> {
    let mut resp = Vec::with_capacity(query.question_end + 16);

    // ── Header ──
    // ID
    resp.extend_from_slice(&query.id.to_be_bytes());
    // Flags: QR=1, AA=1, RD=(from query), RA=1, RCODE=0
    let rd = (query.flags >> 8) & 1;
    let flags: u16 = 0x8000  // QR=1 (response)
        | 0x0400           // AA=1 (authoritative)
        | (rd << 8)        // RD echoed
        | 0x0080;          // RA=1
    resp.extend_from_slice(&flags.to_be_bytes());
    // QDCOUNT=1
    resp.extend_from_slice(&1u16.to_be_bytes());
    // ANCOUNT=1
    resp.extend_from_slice(&1u16.to_be_bytes());
    // NSCOUNT=0, ARCOUNT=0
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());

    // ── Question section (echo original) ──
    resp.extend_from_slice(&query_packet[DNS_HEADER_SIZE..query.question_end]);

    // ── Answer section ──
    // Name: pointer to QNAME in question (compression: 0xC00C = offset 12)
    resp.extend_from_slice(&[0xC0, 0x0C]);

    if query.qtype == QTYPE_AAAA {
        // AAAA record → :: (all zeros)
        resp.extend_from_slice(&QTYPE_AAAA.to_be_bytes()); // TYPE
        resp.extend_from_slice(&QCLASS_IN.to_be_bytes());   // CLASS
        resp.extend_from_slice(&300u32.to_be_bytes());       // TTL = 5 min
        resp.extend_from_slice(&16u16.to_be_bytes());        // RDLENGTH = 16
        resp.extend_from_slice(&[0u8; 16]);                  // :: (IPv6 zero)
    } else {
        // A record → 0.0.0.0
        resp.extend_from_slice(&QTYPE_A.to_be_bytes());     // TYPE
        resp.extend_from_slice(&QCLASS_IN.to_be_bytes());   // CLASS
        resp.extend_from_slice(&300u32.to_be_bytes());       // TTL = 5 min
        resp.extend_from_slice(&4u16.to_be_bytes());         // RDLENGTH = 4
        resp.extend_from_slice(&[0, 0, 0, 0]);              // 0.0.0.0
    }

    resp
}

/// Build an NXDOMAIN response (domain does not exist).
///
/// Used as an alternative to 0.0.0.0 blocking.
pub fn build_nxdomain_response(query_packet: &[u8], query: &DnsQuery) -> Vec<u8> {
    let mut resp = Vec::with_capacity(query.question_end);

    // Header
    resp.extend_from_slice(&query.id.to_be_bytes());
    let rd = (query.flags >> 8) & 1;
    let flags: u16 = 0x8000 | 0x0400 | (rd << 8) | 0x0080 | 0x0003; // RCODE=3 (NXDOMAIN)
    resp.extend_from_slice(&flags.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0

    // Echo question section
    resp.extend_from_slice(&query_packet[DNS_HEADER_SIZE..query.question_end]);

    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query packet for testing.
    fn build_test_query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Header
        pkt.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD=1
        pkt.extend_from_slice(&1u16.to_be_bytes());      // QDCOUNT=1
        pkt.extend_from_slice(&0u16.to_be_bytes());      // ANCOUNT=0
        pkt.extend_from_slice(&0u16.to_be_bytes());      // NSCOUNT=0
        pkt.extend_from_slice(&0u16.to_be_bytes());      // ARCOUNT=0

        // Question: QNAME
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // Root label

        // QTYPE, QCLASS
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());

        pkt
    }

    #[test]
    fn test_parse_query() {
        let pkt = build_test_query("ads.doubleclick.net", QTYPE_A);
        let query = parse_query(&pkt).unwrap();

        assert_eq!(query.id, 0x1234);
        assert_eq!(query.qname, "ads.doubleclick.net");
        assert_eq!(query.qtype, QTYPE_A);
        assert_eq!(query.qclass, QCLASS_IN);
    }

    #[test]
    fn test_parse_query_case_insensitive() {
        let pkt = build_test_query("ADS.DoubleClick.NET", QTYPE_A);
        let query = parse_query(&pkt).unwrap();
        assert_eq!(query.qname, "ads.doubleclick.net");
    }

    #[test]
    fn test_blocked_response() {
        let pkt = build_test_query("ads.example.com", QTYPE_A);
        let query = parse_query(&pkt).unwrap();
        let resp = build_blocked_response(&pkt, &query);

        // Verify response header
        assert_eq!(resp[0], 0x12); // ID high
        assert_eq!(resp[1], 0x34); // ID low
        assert!(resp[2] & 0x80 != 0); // QR=1 (response)

        // ANCOUNT=1
        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        assert_eq!(ancount, 1);

        // Last 4 bytes should be 0.0.0.0
        let rdata = &resp[resp.len() - 4..];
        assert_eq!(rdata, &[0, 0, 0, 0]);
    }

    #[test]
    fn test_aaaa_blocked_response() {
        let pkt = build_test_query("tracker.example.com", QTYPE_AAAA);
        let query = parse_query(&pkt).unwrap();
        let resp = build_blocked_response(&pkt, &query);

        // Last 16 bytes should be all zeros (::)
        let rdata = &resp[resp.len() - 16..];
        assert_eq!(rdata, &[0u8; 16]);
    }

    #[test]
    fn test_nxdomain_response() {
        let pkt = build_test_query("blocked.com", QTYPE_A);
        let query = parse_query(&pkt).unwrap();
        let resp = build_nxdomain_response(&pkt, &query);

        // RCODE should be 3 (NXDOMAIN)
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x000F, 3);

        // ANCOUNT=0
        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        assert_eq!(ancount, 0);
    }

    #[test]
    fn test_malformed_packet() {
        assert!(parse_query(&[]).is_none());
        assert!(parse_query(&[0u8; 5]).is_none());
        // Response packet (QR=1) should be rejected
        let mut pkt = build_test_query("test.com", QTYPE_A);
        pkt[2] |= 0x80; // Set QR=1
        assert!(parse_query(&pkt).is_none());
    }
}
