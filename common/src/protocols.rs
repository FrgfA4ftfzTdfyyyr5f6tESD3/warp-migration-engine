use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolSpec {
    pub id: u8,
    pub key: &'static str,
    pub name: &'static str,
    pub c_min: usize,
    pub c_max: usize,
    pub s_min: usize,
    pub s_max: usize,
}

pub const PROTOCOLS: &[ProtocolSpec] = &[
    ProtocolSpec { id: 1,  key: "junk",     name: "Classic Random Junk (AmneziaWG)",          c_min: 4, c_max: 8, s_min: 100,  s_max: 950 },
    ProtocolSpec { id: 2,  key: "quic_v1",  name: "QUIC v1 / HTTP/3 Short Header (0x43)",      c_min: 4, c_max: 8, s_min: 1200, s_max: 1250 },
    ProtocolSpec { id: 3,  key: "quic_v2",  name: "QUIC v2 / RFC 9369 Initial Header (0xD0)", c_min: 4, c_max: 8, s_min: 1200, s_max: 1250 },
    ProtocolSpec { id: 4,  key: "webrtc",   name: "WebRTC / SRTP Audio Video Stream (RTP v2)", c_min: 4, c_max: 8, s_min: 64,   s_max: 220 },
    ProtocolSpec { id: 5,  key: "dtls",     name: "DTLS 1.2 Application Data Record",         c_min: 4, c_max: 8, s_min: 180,  s_max: 350 },
    ProtocolSpec { id: 6,  key: "dns",      name: "DNS Query (Standard RFC 1035)",             c_min: 4, c_max: 8, s_min: 42,   s_max: 68 },
    ProtocolSpec { id: 7,  key: "esp",      name: "IPsec NAT-T ESP (Enterprise Tunnel)",       c_min: 4, c_max: 8, s_min: 100,  s_max: 850 },
    ProtocolSpec { id: 8,  key: "utp",      name: "uTP BitTorrent (State Data Packet)",       c_min: 4, c_max: 8, s_min: 60,   s_max: 400 },
    ProtocolSpec { id: 9,  key: "raknet",   name: "RakNet Gaming (Minecraft Bedrock)",        c_min: 4, c_max: 8, s_min: 100,  s_max: 500 },
    ProtocolSpec { id: 10, key: "stun",     name: "STUN / ICE Binding Request (RFC 5389)",     c_min: 4, c_max: 8, s_min: 48,   s_max: 120 },
    ProtocolSpec { id: 11, key: "turn",     name: "TURN ChannelData (Relayed Media)",         c_min: 4, c_max: 8, s_min: 48,   s_max: 100 },
    ProtocolSpec { id: 12, key: "steam",    name: "Steam / Valve Source Query (CS:GO)",       c_min: 4, c_max: 8, s_min: 40,   s_max: 120 },
    ProtocolSpec { id: 13, key: "sdr",      name: "Steam Datagram Relay (CS2 SDR Transport)", c_min: 4, c_max: 8, s_min: 60,   s_max: 150 },
    ProtocolSpec { id: 14, key: "riot",     name: "Riot Games (Valorant / LoL Media)",        c_min: 4, c_max: 8, s_min: 50,   s_max: 120 },
    ProtocolSpec { id: 15, key: "zoom",     name: "Zoom Media Stream (RTP Video / Voice)",    c_min: 4, c_max: 8, s_min: 80,   s_max: 240 },
    ProtocolSpec { id: 16, key: "rdp",      name: "Microsoft RDP over UDP (MS-RDPEUDP)",      c_min: 4, c_max: 8, s_min: 70,   s_max: 200 },
    ProtocolSpec { id: 17, key: "discord",  name: "Discord Voice & Media (Opus Audio)",       c_min: 4, c_max: 8, s_min: 60,   s_max: 160 },
];

/// Tier-1 Golden Protocols for [0] AUTO mode (highest success rate against DPI)
pub const TIER1_PROTO_IDS: &[u8] = &[
    2,  // QUIC v1 (Short Header 0x43)
    3,  // QUIC v2 (RFC 9369)
    4,  // WebRTC / SRTP (PT=96)
    5,  // DTLS 1.2
    7,  // IPsec NAT-T ESP
    10, // STUN / ICE
];

/// Tier-1 Golden Protocols specifically restricted for Mode 2 (QUIC/MASQUE handshake)
pub const MASQUE_TIER1_PROTO_IDS: &[u8] = &[
    7,  // IPsec NAT-T ESP
    10, // STUN / ICE
    4,  // WebRTC / SRTP (PT=96)
    5,  // DTLS 1.2
];

pub fn get_protocol_by_id(id: u8) -> &'static ProtocolSpec {
    PROTOCOLS.iter().find(|p| p.id == id).unwrap_or(&PROTOCOLS[6]) // Default to IPsec ESP (7)
}

pub fn get_protocol_by_key(key: &str) -> &'static ProtocolSpec {
    PROTOCOLS.iter().find(|p| p.key.eq_ignore_ascii_case(key)).unwrap_or(&PROTOCOLS[6])
}

/// Select next auto-rotated protocol from Tier-1 without repeating last chosen
pub fn get_next_auto_proto(last_id: Option<u8>, rng: &mut FastRng) -> u8 {
    let pool = TIER1_PROTO_IDS;
    if pool.is_empty() {
        return 7;
    }
    if let Some(last) = last_id {
        let candidates: Vec<u8> = pool.iter().copied().filter(|&id| id != last).collect();
        if !candidates.is_empty() {
            let idx = (rng.next_u32() as usize) % candidates.len();
            return candidates[idx];
        }
    }
    let idx = (rng.next_u32() as usize) % pool.len();
    pool[idx]
}

/// Select next auto-rotated protocol from Mode 2 MASQUE Tier-1 ([7, 10, 4, 5]) without repeating last chosen
pub fn get_next_masque_auto_proto(last_id: Option<u8>, rng: &mut FastRng) -> u8 {
    let pool = MASQUE_TIER1_PROTO_IDS;
    if let Some(last) = last_id {
        let candidates: Vec<u8> = pool.iter().copied().filter(|&id| id != last).collect();
        if !candidates.is_empty() {
            let idx = (rng.next_u32() as usize) % candidates.len();
            return candidates[idx];
        }
    }
    let idx = (rng.next_u32() as usize) % pool.len();
    pool[idx]
}

/// Simple fast PRNG (xorshift64)
pub struct FastRng {
    state: u64,
}

impl FastRng {
    pub fn new() -> Self {
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Self { state: if t == 0 { 0x517cc1b727220a95 } else { t } }
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x as u32
    }

    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(4) {
            let r = self.next_u32().to_le_bytes();
            let n = chunk.len().min(4);
            chunk[..n].copy_from_slice(&r[..n]);
        }
    }
}

/// Builds an 8-byte authentic protocol camouflage header for outbound QUIC envelopes (Client -> Relay)
pub fn build_outbound_camo(proto_id: u8, seq: u32, rng: &mut FastRng) -> [u8; 8] {
    let mut hdr = [0u8; 8];
    match proto_id {
        1 => {
            // Random Junk
            let r = rng.next_u32().to_be_bytes();
            hdr[0..4].copy_from_slice(&r);
            hdr[4..8].copy_from_slice(&seq.to_be_bytes());
        }
        2 => {
            // QUIC v1 Short Header (0x43, 1-RTT encrypted data bypass)
            hdr[0] = 0x43;
            hdr[1] = 0xAA;
            hdr[2] = 0xBB;
            hdr[3] = 0xCC;
            hdr[4..8].copy_from_slice(&seq.to_be_bytes());
        }
        3 => {
            // QUIC v2 Initial Header (0xD0, RFC 9369)
            hdr[0] = 0xD0;
            hdr[1] = 0x6B;
            hdr[2] = 0x33;
            hdr[3] = 0x43;
            hdr[4] = 0xCF;
            hdr[5] = 0x08;
            let s16 = (seq as u16).to_be_bytes();
            hdr[6..8].copy_from_slice(&s16);
        }
        4 => {
            // WebRTC / SRTP (RTP v2 PT=96 Dynamic)
            hdr[0] = 0x80;
            hdr[1] = 0x60;
            let s16 = (seq as u16).to_be_bytes();
            hdr[2..4].copy_from_slice(&s16);
            let ts = (seq.wrapping_mul(160)).to_be_bytes();
            hdr[4..8].copy_from_slice(&ts);
        }
        5 => {
            // DTLS 1.2 Application Data Record
            hdr[0] = 0x17; // Application Data
            hdr[1] = 0xFE; // DTLS 1.2 high
            hdr[2] = 0xFD; // DTLS 1.2 low
            hdr[3] = 0x00; // Epoch high
            hdr[4] = 0x01; // Epoch low
            hdr[5] = 0x00;
            let s16 = (seq as u16).to_be_bytes();
            hdr[6..8].copy_from_slice(&s16);
        }
        6 => {
            // DNS Query RFC 1035 Standard
            let tx_id = (seq ^ 0xA5A5) as u16;
            hdr[0..2].copy_from_slice(&tx_id.to_be_bytes());
            hdr[2] = 0x01; // Standard query
            hdr[3] = 0x00;
            hdr[4] = 0x00; // QDCOUNT = 1
            hdr[5] = 0x01;
            hdr[6] = 0x00;
            hdr[7] = 0x00;
        }
        7 => {
            // IPsec NAT-T ESP: SPI = 0x19840710, Sequence Number
            hdr[0] = 0x19;
            hdr[1] = 0x84;
            hdr[2] = 0x07;
            hdr[3] = 0x10;
            hdr[4..8].copy_from_slice(&seq.to_be_bytes());
        }
        8 => {
            // uTP BitTorrent State Data
            hdr[0] = 0x21;
            hdr[1] = 0x00;
            hdr[2] = 0x04;
            hdr[3] = 0xD2;
            let s16 = (seq as u16).to_be_bytes();
            hdr[4..6].copy_from_slice(&s16);
            let ack = (seq.saturating_sub(1) as u16).to_be_bytes();
            hdr[6..8].copy_from_slice(&ack);
        }
        9 => {
            // RakNet Gaming
            hdr[0] = 0x84;
            hdr[1] = (seq & 0xFF) as u8;
            hdr[2] = ((seq >> 8) & 0xFF) as u8;
            hdr[3] = ((seq >> 16) & 0xFF) as u8;
            hdr[4] = 0x40;
            hdr[5] = 0x00;
            hdr[6] = 0x04;
            hdr[7] = 0x00;
        }
        10 => {
            // STUN / ICE Binding Request (RFC 5389): Type 0x0001, Cookie 0x2112A442
            hdr[0] = 0x00;
            hdr[1] = 0x01;
            hdr[2] = 0x00;
            hdr[3] = 0x00;
            hdr[4] = 0x21;
            hdr[5] = 0x12;
            hdr[6] = 0xA4;
            hdr[7] = 0x42;
        }
        11 => {
            // TURN ChannelData
            hdr[0] = 0x40;
            hdr[1] = 0x00;
            let s16 = (seq as u16).to_be_bytes();
            hdr[2..4].copy_from_slice(&s16);
            hdr[4..8].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        }
        12 => {
            // Steam Source Query: \xFF\xFF\xFF\xFF + 'T'
            hdr[0..4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
            hdr[4] = 0x54; // 'T'
            hdr[5] = 0x53; // 'S'
            hdr[6] = 0x6F; // 'o'
            hdr[7] = 0x75; // 'u'
        }
        13 => {
            // Steam Datagram Relay (SDR)
            hdr[0] = 0x01;
            hdr[1] = 0x00;
            hdr[2] = 0x01;
            hdr[3] = 0x00;
            hdr[4..8].copy_from_slice(&seq.to_be_bytes());
        }
        14 => {
            // Riot Games Media
            hdr[0] = 0x00;
            hdr[1] = 0x01;
            hdr[2] = 0x02;
            hdr[3] = (seq & 0xFF) as u8;
            hdr[4..8].copy_from_slice(&seq.to_be_bytes());
        }
        15 => {
            // Zoom Media Stream (RTP Video PT=98)
            hdr[0] = 0x80;
            hdr[1] = 0x62;
            let s16 = (seq as u16).to_be_bytes();
            hdr[2..4].copy_from_slice(&s16);
            let ts = (seq.wrapping_mul(3000)).to_be_bytes();
            hdr[4..8].copy_from_slice(&ts);
        }
        16 => {
            // Microsoft RDP over UDP
            hdr[0] = 0xD0;
            hdr[1] = 0x00;
            hdr[2] = 0x00;
            hdr[3] = 0x01;
            hdr[4..8].copy_from_slice(&seq.to_be_bytes());
        }
        17 => {
            // Discord Voice & Media (Opus PT=120)
            hdr[0] = 0x80;
            hdr[1] = 0x78;
            let s16 = (seq as u16).to_be_bytes();
            hdr[2..4].copy_from_slice(&s16);
            let ts = (seq.wrapping_mul(960)).to_be_bytes();
            hdr[4..8].copy_from_slice(&ts);
        }
        _ => {
            hdr[0] = 0x19; hdr[1] = 0x84; hdr[2] = 0x07; hdr[3] = 0x10;
            hdr[4..8].copy_from_slice(&seq.to_be_bytes());
        }
    }
    hdr
}

/// Builds an 8-byte authentic matching camouflage response header (Relay -> Client)
pub fn build_inbound_camo(proto_id: u8, seq: u32) -> [u8; 8] {
    let mut hdr = [0u8; 8];
    match proto_id {
        10 => {
            // STUN Binding Response (RFC 5389): 0x0101, Magic Cookie 0x2112A442
            hdr[0] = 0x01; hdr[1] = 0x01;
            hdr[2] = 0x00; hdr[3] = 0x00;
            hdr[4] = 0x21; hdr[5] = 0x12; hdr[6] = 0xA4; hdr[7] = 0x42;
        }
        6 => {
            // DNS Response RFC 1035: 0x8180 Standard Response
            let tx_id = (seq ^ 0xA5A5) as u16;
            hdr[0..2].copy_from_slice(&tx_id.to_be_bytes());
            hdr[2] = 0x81; hdr[3] = 0x80;
            hdr[4] = 0x00; hdr[5] = 0x01;
            hdr[6] = 0x00; hdr[7] = 0x01;
        }
        5 => {
            // DTLS 1.2 Application Data
            hdr[0] = 0x17; hdr[1] = 0xFE; hdr[2] = 0xFD;
            hdr[3] = 0x00; hdr[4] = 0x01; hdr[5] = 0x00;
            let s16 = (seq as u16).to_be_bytes();
            hdr[6..8].copy_from_slice(&s16);
        }
        4 | 15 | 17 => {
            // Real-Time RTP Voice/Video streams
            hdr[0] = 0x80; hdr[1] = 0x60;
            let s16 = (seq as u16).to_be_bytes();
            hdr[2..4].copy_from_slice(&s16);
            let ts = (seq.wrapping_mul(160)).to_be_bytes();
            hdr[4..8].copy_from_slice(&ts);
        }
        7 | _ => {
            // IPsec NAT-T ESP
            hdr[0] = 0x19; hdr[1] = 0x84; hdr[2] = 0x07; hdr[3] = 0x10;
            hdr[4..8].copy_from_slice(&seq.to_be_bytes());
        }
    }
    hdr
}

/// Helper function to build a full lead-in packet payload (Stateful CPS Chain: I1 / I2)
/// for WireGuard Cover Envelope mode, ported 1:1 from wg_protocols.lua!
pub fn build_lead_payload(proto_id: u8, size: usize, seq: usize, rng: &mut FastRng) -> Vec<u8> {
    let spec = get_protocol_by_id(proto_id);
    let mut buf = Vec::with_capacity(size);

    let ts_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;

    match spec.id {
        1 => {
            // Classic Random Junk (AmneziaWG)
            if seq > 1 && size >= 8 {
                buf.extend_from_slice(&ts_now.to_be_bytes());
                buf.extend_from_slice(&(seq as u32).to_be_bytes());
            }
        }
        2 => {
            // QUIC v1 / HTTP/3 (Short Header 0x43)
            buf.push(0x43);
            let mut dcid = [0u8; 8];
            rng.fill_bytes(&mut dcid);
            buf.extend_from_slice(&dcid);
            buf.extend_from_slice(&(seq as u16).to_be_bytes());
            buf.extend_from_slice(&[0x00, 0x00]);
            let mut token = [0u8; 7];
            rng.fill_bytes(&mut token);
            buf.extend_from_slice(&token);
        }
        3 => {
            // QUIC v2 (RFC 9369)
            buf.extend_from_slice(&[0xD0, 0x6B, 0x33, 0x43, 0xCF, 0x08]);
            let mut dcid = [0u8; 8];
            rng.fill_bytes(&mut dcid);
            buf.extend_from_slice(&dcid);
            buf.extend_from_slice(&[0x00, 0x00, 0x44, 0x50, (seq % 256) as u8]);
        }
        4 => {
            // WebRTC / SRTP
            buf.extend_from_slice(&[0x80, 0x60]);
            buf.extend_from_slice(&(seq as u16).to_be_bytes());
            let ts = ((seq as u32).wrapping_mul(160)).to_be_bytes();
            buf.extend_from_slice(&ts);
            buf.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x00, 0x00]);
            let mut rand_tail = [0u8; 6];
            rng.fill_bytes(&mut rand_tail);
            buf.extend_from_slice(&rand_tail);
        }
        5 => {
            // DTLS 1.2
            let frag_len = (size.saturating_sub(13)) as u16;
            buf.extend_from_slice(&[0x17, 0xFE, 0xFD, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
            buf.extend_from_slice(&(seq as u16).to_be_bytes());
            buf.extend_from_slice(&frag_len.to_be_bytes());
            buf.extend_from_slice(&[0x00, 0x00]);
            let mut rand_tail = [0u8; 5];
            rng.fill_bytes(&mut rand_tail);
            buf.extend_from_slice(&rand_tail);
        }
        6 => {
            // DNS Query RFC 1035
            let tx_id = (rng.next_u32() as u16) ^ (seq as u16);
            buf.extend_from_slice(&tx_id.to_be_bytes());
            buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
            let mut name_tail = [0u8; 8];
            rng.fill_bytes(&mut name_tail);
            buf.extend_from_slice(&name_tail);
            buf.extend_from_slice(&[0x00, 0x01]);
        }
        7 => {
            // IPsec NAT-T ESP
            buf.extend_from_slice(&[0x19, 0x84, 0x07, 0x10]);
            buf.extend_from_slice(&(seq as u32).to_be_bytes());
            buf.extend_from_slice(&[0x00, 0x00]);
            let mut rand_tail = [0u8; 8];
            rng.fill_bytes(&mut rand_tail);
            buf.extend_from_slice(&rand_tail);
            buf.extend_from_slice(&[0x00, 0x00]);
        }
        8 => {
            // uTP BitTorrent
            let ts_us = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_micros() as u32).to_be_bytes();
            buf.extend_from_slice(&[0x21, 0x00, 0x04, 0xD2]);
            buf.extend_from_slice(&ts_us);
            buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00]);
            buf.extend_from_slice(&(seq as u16).to_be_bytes());
            buf.extend_from_slice(&(seq.saturating_sub(1) as u16).to_be_bytes());
        }
        9 => {
            // RakNet
            let body_bytes = size.saturating_sub(7);
            let bit_len = ((body_bytes * 8) % 65536) as u16;
            buf.push(0x84);
            buf.extend_from_slice(&[seq as u8, (seq >> 8) as u8, 0]);
            buf.push(0x40);
            buf.extend_from_slice(&bit_len.to_be_bytes());
            buf.extend_from_slice(&[seq as u8, (seq >> 8) as u8, 0]);
            buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            let mut rand_tail = [0u8; 6];
            rng.fill_bytes(&mut rand_tail);
            buf.extend_from_slice(&rand_tail);
        }
        10 => {
            // STUN / ICE
            let msg_len = (((size.saturating_sub(20)) / 4) * 4) as u16;
            buf.extend_from_slice(&[0x00, 0x01]);
            buf.extend_from_slice(&msg_len.to_be_bytes());
            buf.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // Magic Cookie
            let mut tx_id = [0u8; 12];
            rng.fill_bytes(&mut tx_id);
            buf.extend_from_slice(&tx_id);
        }
        11 => {
            // TURN ChannelData
            let data_len = size.saturating_sub(4) as u16;
            buf.extend_from_slice(&[0x40, 0x00]);
            buf.extend_from_slice(&data_len.to_be_bytes());
            buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            let mut rand_tail = [0u8; 12];
            rng.fill_bytes(&mut rand_tail);
            buf.extend_from_slice(&rand_tail);
        }
        12 => {
            // Steam Source
            buf.extend_from_slice(b"\xFF\xFF\xFF\xFF\x54Source Engine Query\x00");
        }
        13 => {
            // SDR
            buf.extend_from_slice(&[0x01, 0x00, 0x01, 0x00, 0x00]);
            buf.extend_from_slice(&(seq as u32).to_be_bytes());
            buf.extend_from_slice(&[0x00, 0x00]);
            let mut rand_tail = [0u8; 9];
            rng.fill_bytes(&mut rand_tail);
            buf.extend_from_slice(&rand_tail);
        }
        14 => {
            // Riot Games
            buf.extend_from_slice(&[0x00, 0x01, 0x02]);
            buf.extend_from_slice(&(seq as u32).to_be_bytes());
            buf.extend_from_slice(&[0x00, 0x00]);
            let mut rand_tail = [0u8; 11];
            rng.fill_bytes(&mut rand_tail);
            buf.extend_from_slice(&rand_tail);
        }
        15 => {
            // Zoom Media
            buf.extend_from_slice(&[0x80, 0x62]);
            buf.extend_from_slice(&(seq as u16).to_be_bytes());
            let ts = ((seq as u32).wrapping_mul(3000)).to_be_bytes();
            buf.extend_from_slice(&ts);
            buf.extend_from_slice(&[0x4A, 0x53, 0x54, 0x55, 0x00, 0x00]);
            let mut rand_tail = [0u8; 6];
            rng.fill_bytes(&mut rand_tail);
            buf.extend_from_slice(&rand_tail);
        }
        16 => {
            // RDP
            buf.extend_from_slice(&[0xD0, 0x00, 0x00, 0x01]);
            buf.extend_from_slice(&(seq as u32).to_be_bytes());
            buf.extend_from_slice(&[0x00, 0x00]);
            let mut rand_tail = [0u8; 8];
            rng.fill_bytes(&mut rand_tail);
            buf.extend_from_slice(&rand_tail);
            buf.extend_from_slice(&[0x00, 0x00]);
        }
        17 => {
            // Discord
            buf.extend_from_slice(&[0x80, 0x78]);
            buf.extend_from_slice(&(seq as u16).to_be_bytes());
            let ts = ((seq as u32).wrapping_mul(960)).to_be_bytes();
            buf.extend_from_slice(&ts);
            buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00]);
            let mut rand_tail = [0u8; 6];
            rng.fill_bytes(&mut rand_tail);
            buf.extend_from_slice(&rand_tail);
        }
        _ => {
            buf.extend_from_slice(&[0x19, 0x84, 0x07, 0x10]);
            buf.extend_from_slice(&(seq as u32).to_be_bytes());
        }
    }

    // Stateful CPS Chain extension:
    // If seq > 1 and there is room for dynamic timestamp, prepend/inject live timestamp
    let cur_len = buf.len();
    if cur_len < size {
        let pad_len = size - cur_len;
        if seq > 1 && pad_len >= 8 && spec.id != 1 {
            buf.extend_from_slice(&ts_now.to_be_bytes());
            buf.extend_from_slice(&(seq as u32).to_be_bytes());
            let rem = pad_len - 8;
            if rem > 0 {
                let start = buf.len();
                buf.resize(start + rem, 0);
                rng.fill_bytes(&mut buf[start..]);
            }
        } else {
            let start = buf.len();
            buf.resize(start + pad_len, 0);
            rng.fill_bytes(&mut buf[start..]);
        }
    } else if cur_len > size {
        buf.truncate(size);
    }

    buf
}
