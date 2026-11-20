#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum QuicPacketKind {
    LongInitial,
    Long0Rtt,
    LongHandshake,
    LongRetry,
    LongOther,
    Short1Rtt,
    Unknown,
}

/// Parse RFC 9000 variable-length integer (varint).
/// Returns (value, number_of_bytes_consumed).
pub fn parse_quic_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    let prefix = first >> 6;
    match prefix {
        0 => Some(((first & 0x3f) as u64, 1)),
        1 => {
            if buf.len() < 2 {
                return None;
            }
            let val = (((first & 0x3f) as u64) << 8) | (buf[1] as u64);
            Some((val, 2))
        }
        2 => {
            if buf.len() < 4 {
                return None;
            }
            let val = (((first & 0x3f) as u64) << 24)
                | ((buf[1] as u64) << 16)
                | ((buf[2] as u64) << 8)
                | (buf[3] as u64);
            Some((val, 4))
        }
        3 => {
            if buf.len() < 8 {
                return None;
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&buf[0..8]);
            bytes[0] &= 0x3f;
            Some((u64::from_be_bytes(bytes), 8))
        }
        _ => unreachable!(),
    }
}

/// Compute the total length in bytes of a Long Header QUIC packet.
/// RFC 9000 section 17.2:
/// Header Form (1), Fixed Bit (1), Type (2), Type-Specific (4), Version (4B),
/// DCID Len (1B), DCID (0..20B), SCID Len (1B), SCID (0..20B),
/// [Token Len (varint) + Token for Initial],
/// Length (varint) representing remainder of packet (Packet Number + Payload).
fn parse_long_header_len(payload: &[u8], packet_type: u8) -> Option<usize> {
    if payload.len() < 7 {
        return None;
    }

    let dcil = payload[5] as usize;
    let scil_offset = 6 + dcil;
    if payload.len() <= scil_offset {
        return None;
    }

    let scil = payload[scil_offset] as usize;
    let mut pos = scil_offset + 1 + scil;
    if payload.len() < pos {
        return None;
    }

    match packet_type {
        0x00 => {
            // Initial: Token Length (varint) + Token + Length (varint)
            let (tok_len, tok_varint_len) = parse_quic_varint(&payload[pos..])?;
            pos += tok_varint_len + tok_len as usize;
            if payload.len() < pos {
                return None;
            }
            let (rem_len, rem_varint_len) = parse_quic_varint(&payload[pos..])?;
            pos += rem_varint_len;
            Some(pos + rem_len as usize)
        }
        0x01 | 0x02 => {
            // 0-RTT (0x01) or Handshake (0x02): Length (varint)
            let (rem_len, rem_varint_len) = parse_quic_varint(&payload[pos..])?;
            pos += rem_varint_len;
            Some(pos + rem_len as usize)
        }
        0x03 => {
            // Retry: consumes remainder of datagram
            Some(payload.len())
        }
        _ => Some(payload.len()),
    }
}

/// Inspect all coalesced QUIC packets inside a single UDP datagram payload.
/// RFC 9000 section 12.2 allows multiple QUIC packets to be coalesced into a single UDP datagram.
/// Cloudflare commonly coalesces Server Initial and Server Handshake into one UDP datagram!
pub fn inspect_all_quic_packets(mut payload: &[u8]) -> Vec<(QuicPacketKind, String)> {
    let mut results = Vec::new();

    while !payload.is_empty() {
        let first_byte = payload[0];

        if (first_byte & 0x80) == 0 {
            // Short Header:
            // Per RFC 9000 Section 12.2: A packet with a short header does not include a length,
            // so it can only be the last packet in a UDP datagram.
            if (first_byte & 0x40) != 0 {
                results.push((
                    QuicPacketKind::Short1Rtt,
                    format!("QUIC 1-RTT Application Data (0x{:02x})", first_byte),
                ));
            } else {
                results.push((
                    QuicPacketKind::Unknown,
                    format!("UDP Non-QUIC / Unknown (0x{:02x})", first_byte),
                ));
            }
            break;
        }

        // Long Header
        let packet_type = (first_byte & 0x30) >> 4;
        let kind = match packet_type {
            0x00 => QuicPacketKind::LongInitial,
            0x01 => QuicPacketKind::Long0Rtt,
            0x02 => QuicPacketKind::LongHandshake,
            0x03 => QuicPacketKind::LongRetry,
            _ => QuicPacketKind::LongOther,
        };

        let desc = match kind {
            QuicPacketKind::LongInitial => format!("QUIC Initial (0x{:02x})", first_byte),
            QuicPacketKind::Long0Rtt => format!("QUIC 0-RTT (0x{:02x})", first_byte),
            QuicPacketKind::LongHandshake => format!("QUIC Handshake (0x{:02x})", first_byte),
            QuicPacketKind::LongRetry => format!("QUIC Retry (0x{:02x})", first_byte),
            _ => format!("QUIC Long (0x{:02x})", first_byte),
        };
        results.push((kind, desc));

        // Determine packet length to advance to the next coalesced packet
        let pkt_len = parse_long_header_len(payload, packet_type);
        match pkt_len {
            Some(len) if len > 0 && len < payload.len() => {
                payload = &payload[len..];
            }
            _ => break,
        }
    }

    if results.is_empty() {
        results.push((QuicPacketKind::Unknown, "Empty".to_string()));
    }

    results
}

/// Backward-compatible inspection of the primary/first QUIC packet in payload.
pub fn inspect_quic_packet(payload: &[u8]) -> (QuicPacketKind, String) {
    inspect_all_quic_packets(payload)
        .into_iter()
        .next()
        .unwrap_or((QuicPacketKind::Unknown, "Empty".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_parsing() {
        assert_eq!(parse_quic_varint(&[25]), Some((25, 1)));
        assert_eq!(parse_quic_varint(&[0x40, 0x16]), Some((22, 2)));
        assert_eq!(parse_quic_varint(&[0x80, 0x00, 0x01, 0x00]), Some((256, 4)));
    }

    #[test]
    fn test_coalesced_initial_and_handshake() {
        // Construct a synthetic coalesced packet: Initial (40 bytes) + Handshake (30 bytes)
        let mut buf = Vec::new();

        // 1. Initial packet:
        // Byte 0: 0xc0 (Long Header, Type 0x00 = Initial)
        // Bytes 1..4: Version 1
        // Byte 5: DCIL = 8
        // Bytes 6..13: DCID (8B)
        // Byte 14: SCIL = 8
        // Bytes 15..22: SCID (8B)
        // Byte 23: Token Len = 0 (1B varint)
        // Byte 24: Length = 15 (1B varint, value = 15 => remainder is 15B)
        // Remainder: 15B (total Initial = 25 + 15 = 40B)
        buf.push(0xc0);
        buf.extend_from_slice(&[0, 0, 0, 1]);
        buf.push(8);
        buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        buf.push(8);
        buf.extend_from_slice(&[9, 10, 11, 12, 13, 14, 15, 16]);
        buf.push(0x00); // Token len = 0
        buf.push(15);   // Length = 15
        buf.extend_from_slice(&[0xaa; 15]);
        assert_eq!(buf.len(), 40);

        // 2. Handshake packet coalesced right behind it:
        // Byte 0: 0xe0 (Long Header, Type 0x02 = Handshake)
        // Bytes 1..4: Version 1
        // Byte 5: DCIL = 8
        // Bytes 6..13: DCID (8B)
        // Byte 14: SCIL = 8
        // Bytes 15..22: SCID (8B)
        // Byte 23: Length = 6 (1B varint, value = 6 => remainder is 6B)
        // Remainder: 6B (total Handshake = 24 + 6 = 30B)
        buf.push(0xe0);
        buf.extend_from_slice(&[0, 0, 0, 1]);
        buf.push(8);
        buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        buf.push(8);
        buf.extend_from_slice(&[9, 10, 11, 12, 13, 14, 15, 16]);
        buf.push(6); // Length = 6
        buf.extend_from_slice(&[0xbb; 6]);
        assert_eq!(buf.len(), 70);

        let parsed = inspect_all_quic_packets(&buf);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, QuicPacketKind::LongInitial);
        assert_eq!(parsed[1].0, QuicPacketKind::LongHandshake);
    }
}
