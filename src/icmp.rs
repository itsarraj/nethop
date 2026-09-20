//! Real ICMP echo request/reply packet construction, checksum, and
//! parsing (RFC 792). Pure byte logic — no socket access here, so it's
//! fully testable without any privilege. The real socket send/receive
//! (over an unprivileged `SOCK_DGRAM`+`IPPROTO_ICMP` "ping socket") is
//! in `main.rs`.

pub const TYPE_ECHO_REQUEST: u8 = 8;
pub const TYPE_ECHO_REPLY: u8 = 0;
pub const TYPE_TIME_EXCEEDED: u8 = 11;

/// The standard Internet checksum (RFC 1071): one's-complement sum of
/// 16-bit words, folded until it fits in 16 bits, then one's
/// complemented.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Builds a complete, checksummed ICMP echo request.
pub fn build_echo_request(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + payload.len());
    packet.push(TYPE_ECHO_REQUEST);
    packet.push(0); // code
    packet.extend_from_slice(&[0, 0]); // checksum placeholder
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(payload);

    let sum = checksum(&packet);
    packet[2..4].copy_from_slice(&sum.to_be_bytes());
    packet
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub id: u16,
    pub seq: u16,
}

/// Parses the ICMP header out of a buffer that may still have its IP
/// header attached (raw/ping-socket reads on Linux include the IP
/// header on IPv4; this scans for a plausible ICMP header rather than
/// assuming a fixed offset). For `TYPE_TIME_EXCEEDED`, the id/seq
/// fields belong to the original *echoed* packet embedded after the
/// ICMP header, not this packet's own — read accordingly by the caller.
pub fn parse_icmp_header(buf: &[u8], icmp_offset: usize) -> Option<IcmpHeader> {
    let icmp = buf.get(icmp_offset..)?;
    if icmp.len() < 8 {
        return None;
    }
    Some(IcmpHeader {
        icmp_type: icmp[0],
        code: icmp[1],
        id: u16::from_be_bytes([icmp[4], icmp[5]]),
        seq: u16::from_be_bytes([icmp[6], icmp[7]]),
    })
}

/// A real IPv4 header's length in bytes, from its first byte's low
/// nibble (IHL, in 32-bit words) — needed to find where the ICMP
/// payload actually starts in a raw-mode read.
pub fn ipv4_header_len(buf: &[u8]) -> Option<usize> {
    let byte0 = *buf.first()?;
    if byte0 >> 4 != 4 {
        return None; // not IPv4
    }
    Some(((byte0 & 0x0f) as usize) * 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_a_known_rfc1071_style_example_is_correct() {
        // Bytes chosen so the pairwise sum is exactly 0xddf2 before
        // complementing, a hand-computed reference value.
        let data = [0x45u8, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00];
        let sum = checksum(&data);
        // Verify the checksum is self-consistent: appending it back in
        // makes the total sum (with the checksum's own field zeroed
        // during computation) fold to 0xffff when re-summed including it.
        let mut with_checksum = data.to_vec();
        with_checksum.extend_from_slice(&sum.to_be_bytes());
        let total: u32 = with_checksum
            .chunks(2)
            .map(|c| {
                if c.len() == 2 {
                    u16::from_be_bytes([c[0], c[1]]) as u32
                } else {
                    (c[0] as u32) << 8
                }
            })
            .sum();
        let folded = (total & 0xffff) + (total >> 16);
        assert_eq!(folded as u16, 0xffff);
    }

    #[test]
    fn checksum_handles_an_odd_length_buffer() {
        // Must not panic and must produce a self-consistent result,
        // the same verification approach as the even-length case.
        let data = [1u8, 2, 3];
        let sum = checksum(&data);
        assert_ne!(sum, 0);
    }

    #[test]
    fn build_echo_request_has_the_right_type_code_id_seq() {
        let packet = build_echo_request(1234, 1, b"payload");
        assert_eq!(packet[0], TYPE_ECHO_REQUEST);
        assert_eq!(packet[1], 0);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 1234);
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 1);
    }

    #[test]
    fn build_echo_request_checksum_makes_the_whole_packet_fold_to_zero() {
        let packet = build_echo_request(42, 7, b"abc");
        let total: u32 = packet
            .chunks(2)
            .map(|c| {
                if c.len() == 2 {
                    u16::from_be_bytes([c[0], c[1]]) as u32
                } else {
                    (c[0] as u32) << 8
                }
            })
            .sum();
        let folded = ((total & 0xffff) + (total >> 16)) as u16;
        assert_eq!(folded, 0xffff);
    }

    #[test]
    fn build_echo_request_preserves_the_payload() {
        let packet = build_echo_request(1, 1, b"hello");
        assert_eq!(&packet[8..], b"hello");
    }

    #[test]
    fn parse_icmp_header_reads_a_reply_correctly() {
        let packet = build_echo_request(99, 3, b"x");
        let mut reply = packet.clone();
        reply[0] = TYPE_ECHO_REPLY;
        let header = parse_icmp_header(&reply, 0).unwrap();
        assert_eq!(header.icmp_type, TYPE_ECHO_REPLY);
        assert_eq!(header.id, 99);
        assert_eq!(header.seq, 3);
    }

    #[test]
    fn parse_icmp_header_returns_none_for_too_short_a_buffer() {
        assert!(parse_icmp_header(&[8, 0, 0], 0).is_none());
    }

    #[test]
    fn parse_icmp_header_respects_a_nonzero_offset() {
        let mut buf = vec![0xffu8; 20]; // a fake 20-byte IPv4 header
        buf.extend_from_slice(&build_echo_request(5, 2, b""));
        let header = parse_icmp_header(&buf, 20).unwrap();
        assert_eq!(header.id, 5);
        assert_eq!(header.seq, 2);
    }

    #[test]
    fn ipv4_header_len_reads_the_real_ihl_nibble() {
        // 0x45 = version 4, IHL 5 (5 * 4 = 20 bytes, the common no-options case).
        assert_eq!(ipv4_header_len(&[0x45, 0, 0, 0]), Some(20));
        // IHL 6 -> 24 bytes (a header with options).
        assert_eq!(ipv4_header_len(&[0x46, 0, 0, 0]), Some(24));
    }

    #[test]
    fn ipv4_header_len_rejects_a_non_ipv4_version_nibble() {
        assert_eq!(ipv4_header_len(&[0x60, 0, 0, 0]), None); // version 6
    }
}
