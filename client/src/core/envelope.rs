use masque_common::{
    build_outbound_camo, FastRng, OutboundEnvelope, INBOUND_STRIP_LEN, OUTBOUND_PREPEND_LEN_V4,
    OUTBOUND_PREPEND_LEN_V6,
};

use crate::core::checksum::{
    calculate_ipv4_checksum, calculate_udp_checksum, calculate_udp_v6_checksum,
};
use crate::core::packet::{ParsedIpv4Udp, ParsedIpv6Udp};

pub struct EnvelopeEngine {
    seq_counter: u32,
    rng: FastRng,
}

impl EnvelopeEngine {
    pub fn new() -> Self {
        Self {
            seq_counter: 1,
            rng: FastRng::new(),
        }
    }

    /// Prepend 16-byte header to outbound IPv4 UDP packet at Layer 3:
    /// Byte 0..8  : Authentic Camouflage Header
    /// Byte 8..12 : Target IPv4 (e.g. 162.159.198.2)
    /// Byte 12..14: Target Port (Big-Endian, e.g. 8095)
    /// Byte 14    : PROTOCOL_ID (1..17)
    /// Byte 15    : AddrType = 0x04
    /// Byte 16..  : 100% Untouched original payload!
    pub fn apply_outbound_envelope_v4(
        &mut self,
        packet: &mut Vec<u8>,
        parsed: &ParsedIpv4Udp,
        relay_ip: [u8; 4],
        relay_port: u16,
        target_ip: [u8; 4],
        target_port: u16,
        proto_id: u8,
    ) -> (usize, usize) {
        let payload_start = parsed.payload_start;
        let payload_len = parsed.payload_len;
        let ihl = parsed.ihl;
        let udp_start = parsed.udp_header_start;
        let src_ip = parsed.src_ip;

        let new_payload_len = payload_len + OUTBOUND_PREPEND_LEN_V4;
        let old_len = packet.len();
        packet.resize(old_len + OUTBOUND_PREPEND_LEN_V4, 0);

        // 1. Shift authentic payload forward by 16 bytes
        packet.copy_within(
            payload_start..payload_start + payload_len,
            payload_start + OUTBOUND_PREPEND_LEN_V4,
        );

        // 2. Build authentic 8-byte camouflage header for chosen protocol
        let camo_hdr = build_outbound_camo(proto_id, self.seq_counter, &mut self.rng);
        self.seq_counter = self.seq_counter.wrapping_add(1);

        // 3. Format 16-byte envelope header
        let env = OutboundEnvelope::new_v4(camo_hdr, target_ip, target_port, proto_id);
        env.encode(&mut packet[payload_start..payload_start + OUTBOUND_PREPEND_LEN_V4]);

        // 4. Update IPv4 Header
        let new_ip_total_len = (ihl + 8 + new_payload_len) as u16;
        packet[2..4].copy_from_slice(&new_ip_total_len.to_be_bytes());
        packet[16..20].copy_from_slice(&relay_ip); // Rewrite Dst IP to Relay

        let new_ip_csum = calculate_ipv4_checksum(&packet[0..ihl]);
        packet[10..12].copy_from_slice(&new_ip_csum.to_be_bytes());

        // 5. Update UDP Header
        packet[udp_start + 2..udp_start + 4].copy_from_slice(&relay_port.to_be_bytes());
        let new_udp_total_len = (8 + new_payload_len) as u16;
        packet[udp_start + 4..udp_start + 6].copy_from_slice(&new_udp_total_len.to_be_bytes());

        let new_udp_csum = calculate_udp_checksum(
            src_ip,
            relay_ip,
            &packet[udp_start..udp_start + 8 + new_payload_len],
        );
        packet[udp_start + 6..udp_start + 8].copy_from_slice(&new_udp_csum.to_be_bytes());

        (new_payload_len, packet.len())
    }

    /// Prepend 28-byte header to outbound IPv6 UDP packet at Layer 3:
    /// Byte 0..8  : Authentic Camouflage Header
    /// Byte 8..24 : Target IPv6 (16 bytes)
    /// Byte 24..26: Target Port (Big-Endian)
    /// Byte 26    : PROTOCOL_ID (1..17)
    /// Byte 27    : AddrType = 0x06
    /// Byte 28..  : 100% Untouched original payload!
    #[allow(dead_code)]
    pub fn apply_outbound_envelope_v6(
        &mut self,
        packet: &mut Vec<u8>,
        parsed: &ParsedIpv6Udp,
        relay_ipv6: [u8; 16],
        relay_port: u16,
        target_ipv6: [u8; 16],
        target_port: u16,
        proto_id: u8,
    ) -> (usize, usize) {
        let payload_start = parsed.payload_start;
        let payload_len = parsed.payload_len;
        let udp_start = parsed.udp_header_start;
        let src_ip = parsed.src_ip;

        let new_payload_len = payload_len + OUTBOUND_PREPEND_LEN_V6;
        let old_len = packet.len();
        packet.resize(old_len + OUTBOUND_PREPEND_LEN_V6, 0);

        // 1. Shift payload forward by 28 bytes
        packet.copy_within(
            payload_start..payload_start + payload_len,
            payload_start + OUTBOUND_PREPEND_LEN_V6,
        );

        // 2. Build authentic 8-byte camouflage header
        let camo_hdr = build_outbound_camo(proto_id, self.seq_counter, &mut self.rng);
        self.seq_counter = self.seq_counter.wrapping_add(1);

        // 3. Format 28-byte envelope header
        let env = OutboundEnvelope::new_v6(camo_hdr, target_ipv6, target_port, proto_id);
        env.encode(&mut packet[payload_start..payload_start + OUTBOUND_PREPEND_LEN_V6]);

        // 4. Update IPv6 Header: PayloadLength = 8 (UDP) + new_payload_len
        let new_ipv6_payload_len = (8 + new_payload_len) as u16;
        packet[4..6].copy_from_slice(&new_ipv6_payload_len.to_be_bytes());
        packet[24..40].copy_from_slice(&relay_ipv6); // Dst IP = Relay IPv6

        // 5. Update UDP Header: Dst Port = Relay Port
        packet[udp_start + 2..udp_start + 4].copy_from_slice(&relay_port.to_be_bytes());
        let new_udp_total_len = (8 + new_payload_len) as u16;
        packet[udp_start + 4..udp_start + 6].copy_from_slice(&new_udp_total_len.to_be_bytes());

        let new_udp_csum = calculate_udp_v6_checksum(
            src_ip,
            relay_ipv6,
            &packet[udp_start..udp_start + 8 + new_payload_len],
        );
        packet[udp_start + 6..udp_start + 8].copy_from_slice(&new_udp_csum.to_be_bytes());

        (new_payload_len, packet.len())
    }

    /// Strip 8-byte camouflage header from inbound IPv4 packet received from Relay
    pub fn apply_inbound_strip_v4(
        &mut self,
        packet: &mut Vec<u8>,
        parsed: &ParsedIpv4Udp,
        target_ip: [u8; 4],
        target_port: u16,
        zero_csum: bool,
    ) -> Option<(usize, usize)> {
        let payload_start = parsed.payload_start;
        let payload_len = parsed.payload_len;
        let ihl = parsed.ihl;
        let udp_start = parsed.udp_header_start;
        let client_ip = parsed.dst_ip;

        if payload_len < INBOUND_STRIP_LEN {
            return None;
        }

        let new_payload_len = payload_len - INBOUND_STRIP_LEN;

        // 1. Shift authentic payload back by 8 bytes
        packet.copy_within(
            payload_start + INBOUND_STRIP_LEN..payload_start + payload_len,
            payload_start,
        );
        let new_total_len = packet.len() - INBOUND_STRIP_LEN;
        packet.truncate(new_total_len);

        // 2. Update IPv4 Header: Source IP -> Target IP (Cloudflare)
        let new_ip_total_len = (ihl + 8 + new_payload_len) as u16;
        packet[2..4].copy_from_slice(&new_ip_total_len.to_be_bytes());
        packet[12..16].copy_from_slice(&target_ip);

        let new_ip_csum = calculate_ipv4_checksum(&packet[0..ihl]);
        packet[10..12].copy_from_slice(&new_ip_csum.to_be_bytes());

        // 3. Update UDP Header: Source Port -> Target Port (Cloudflare)
        packet[udp_start..udp_start + 2].copy_from_slice(&target_port.to_be_bytes());
        let new_udp_total_len = (8 + new_payload_len) as u16;
        packet[udp_start + 4..udp_start + 6].copy_from_slice(&new_udp_total_len.to_be_bytes());

        let new_udp_csum = if zero_csum {
            0u16
        } else {
            calculate_udp_checksum(
                target_ip,
                client_ip,
                &packet[udp_start..udp_start + 8 + new_payload_len],
            )
        };
        packet[udp_start + 6..udp_start + 8].copy_from_slice(&new_udp_csum.to_be_bytes());

        Some((new_payload_len, packet.len()))
    }

    /// Strip 8-byte camouflage header from inbound IPv6 packet received from Relay
    #[allow(dead_code)]
    pub fn apply_inbound_strip_v6(
        &mut self,
        packet: &mut Vec<u8>,
        parsed: &ParsedIpv6Udp,
        target_ipv6: [u8; 16],
        target_port: u16,
    ) -> Option<(usize, usize)> {
        let payload_start = parsed.payload_start;
        let payload_len = parsed.payload_len;
        let udp_start = parsed.udp_header_start;
        let client_ip = parsed.dst_ip;

        if payload_len < INBOUND_STRIP_LEN {
            return None;
        }

        let new_payload_len = payload_len - INBOUND_STRIP_LEN;

        // 1. Shift payload back by 8 bytes
        packet.copy_within(
            payload_start + INBOUND_STRIP_LEN..payload_start + payload_len,
            payload_start,
        );
        let new_total_len = packet.len() - INBOUND_STRIP_LEN;
        packet.truncate(new_total_len);

        // 2. Update IPv6 Header: Source IP -> Target IPv6, PayloadLength = 8 + new_payload_len
        let new_ipv6_payload_len = (8 + new_payload_len) as u16;
        packet[4..6].copy_from_slice(&new_ipv6_payload_len.to_be_bytes());
        packet[8..24].copy_from_slice(&target_ipv6);

        // 3. Update UDP Header: Source Port -> Target Port
        packet[udp_start..udp_start + 2].copy_from_slice(&target_port.to_be_bytes());
        let new_udp_total_len = (8 + new_payload_len) as u16;
        packet[udp_start + 4..udp_start + 6].copy_from_slice(&new_udp_total_len.to_be_bytes());

        let new_udp_csum = calculate_udp_v6_checksum(
            target_ipv6,
            client_ip,
            &packet[udp_start..udp_start + 8 + new_payload_len],
        );
        packet[udp_start + 6..udp_start + 8].copy_from_slice(&new_udp_csum.to_be_bytes());

        Some((new_payload_len, packet.len()))
    }
}
