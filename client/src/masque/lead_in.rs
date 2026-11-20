use std::net::SocketAddr;
use std::time::Duration;

use masque_common::{build_outbound_camo, get_protocol_by_id, FastRng, OutboundEnvelope};
use windivert::{address::WinDivertAddress, prelude::*};

use crate::core::packet::{build_ipv4_udp_packet, ParsedIpUdp};

pub fn send_relay_warmup(
    wd: &WinDivert<NetworkLayer>,
    packet_address: &WinDivertAddress<NetworkLayer>,
    parsed: &ParsedIpUdp,
    relay_ip_v4_bytes: [u8; 4],
    relay_port: u16,
    locked_proto: u8,
    src_port: u16,
    rng: &mut FastRng,
    chrono_fn: impl Fn() -> String,
) {
    let v4 = match parsed {
        ParsedIpUdp::V4(v4) => v4,
        _ => return,
    };

    let proto_info = get_protocol_by_id(locked_proto);
    println!(
        "{} [WARMUP] Client :{} -> 2x 48B Lead-In to Amsterdam Relay [{}]",
        chrono_fn(), src_port, proto_info.key
    );

    for i in 1..=2 {
        let mut p = vec![0u8; 48];
        let camo = build_outbound_camo(locked_proto, i as u32, rng);
        let env = OutboundEnvelope::new_v4(camo, [0, 0, 0, 0], 0, locked_proto);
        env.encode(&mut p);
        rng.fill_bytes(&mut p[16..48]);

        let warmup_raw = build_ipv4_udp_packet(
            v4.src_ip,
            relay_ip_v4_bytes,
            v4.src_port,
            relay_port,
            &p,
        );

        let mut warmup_pkt = WinDivertPacket::<NetworkLayer> {
            address: packet_address.clone(),
            data: std::borrow::Cow::Owned(warmup_raw),
        };
        let _ = warmup_pkt.recalculate_checksums(ChecksumFlags::new());
        let _ = wd.send(&warmup_pkt);
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub fn send_direct_lead_in(
    wd: &WinDivert<NetworkLayer>,
    packet_address: &WinDivertAddress<NetworkLayer>,
    client_ip: [u8; 4],
    client_port: u16,
    target_addr: SocketAddr,
    locked_proto: u8,
    rng: &mut FastRng,
    chrono_fn: impl Fn() -> String,
) {
    let target_ip_bytes = match target_addr {
        SocketAddr::V4(v4) => v4.ip().octets(),
        _ => return,
    };

    let lead_proto = if locked_proto == 2 || locked_proto == 3 {
        7 // Force IPsec ESP if QUIC was selected
    } else {
        locked_proto
    };
    let proto_info = get_protocol_by_id(lead_proto);

    println!(
        "{} [LEAD-IN] Client :{} -> 2x Non-QUIC Lead-In (48B/96B) [{}] -> Direct Cloudflare {}",
        chrono_fn(), client_port, proto_info.key, target_addr
    );

    for (idx, size) in [(1usize, 48usize), (2usize, 96usize)].iter().copied() {
        let lead_payload = masque_common::protocols::build_lead_payload(lead_proto, size, idx, rng);
        let raw_lead_pkt = build_ipv4_udp_packet(
            client_ip,
            target_ip_bytes,
            client_port,
            target_addr.port(),
            &lead_payload,
        );

        let mut lead_addr = packet_address.clone();
        lead_addr.set_outbound(true);

        let mut lead_pkt = WinDivertPacket::<NetworkLayer> {
            address: lead_addr,
            data: std::borrow::Cow::Owned(raw_lead_pkt),
        };
        let _ = lead_pkt.recalculate_checksums(ChecksumFlags::new());
        let _ = wd.send(&lead_pkt);
        std::thread::sleep(Duration::from_millis(10));
    }
}
