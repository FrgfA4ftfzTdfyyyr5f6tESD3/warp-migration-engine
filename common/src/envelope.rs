use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

pub const OUTBOUND_PREPEND_LEN_V4: usize = 16;
pub const OUTBOUND_PREPEND_LEN_V6: usize = 28;
pub const INBOUND_STRIP_LEN: usize = 8;

pub const ADDR_TYPE_IPV4: u8 = 0x04;
pub const ADDR_TYPE_IPV6: u8 = 0x06;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundEnvelope {
    pub camo_hdr: [u8; 8],
    pub target: SocketAddr,
    pub proto_id: u8,
}

impl OutboundEnvelope {
    pub fn new_v4(camo_hdr: [u8; 8], ip: [u8; 4], port: u16, proto_id: u8) -> Self {
        Self {
            camo_hdr,
            target: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)),
            proto_id,
        }
    }

    pub fn new_v6(camo_hdr: [u8; 8], ip: [u8; 16], port: u16, proto_id: u8) -> Self {
        Self {
            camo_hdr,
            target: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0)),
            proto_id,
        }
    }

    pub fn new(camo_hdr: [u8; 8], target: SocketAddr, proto_id: u8) -> Self {
        Self {
            camo_hdr,
            target,
            proto_id,
        }
    }

    #[inline]
    pub fn envelope_len(&self) -> usize {
        match self.target {
            SocketAddr::V4(_) => OUTBOUND_PREPEND_LEN_V4,
            SocketAddr::V6(_) => OUTBOUND_PREPEND_LEN_V6,
        }
    }

    pub fn encode(&self, dest: &mut [u8]) -> usize {
        dest[0..8].copy_from_slice(&self.camo_hdr);
        match self.target {
            SocketAddr::V4(v4) => {
                assert!(dest.len() >= OUTBOUND_PREPEND_LEN_V4);
                dest[8..12].copy_from_slice(&v4.ip().octets());
                dest[12..14].copy_from_slice(&v4.port().to_be_bytes());
                dest[14] = self.proto_id;
                dest[15] = ADDR_TYPE_IPV4;
                OUTBOUND_PREPEND_LEN_V4
            }
            SocketAddr::V6(v6) => {
                assert!(dest.len() >= OUTBOUND_PREPEND_LEN_V6);
                dest[8..24].copy_from_slice(&v6.ip().octets());
                dest[24..26].copy_from_slice(&v6.port().to_be_bytes());
                dest[26] = self.proto_id;
                dest[27] = ADDR_TYPE_IPV6;
                OUTBOUND_PREPEND_LEN_V6
            }
        }
    }

    pub fn decode(src: &[u8]) -> Option<(Self, usize)> {
        if src.len() < OUTBOUND_PREPEND_LEN_V4 {
            return None;
        }

        // Check if IPv6 (28 bytes)
        if src.len() >= OUTBOUND_PREPEND_LEN_V6 && src[27] == ADDR_TYPE_IPV6 {
            let mut camo_hdr = [0u8; 8];
            camo_hdr.copy_from_slice(&src[0..8]);
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&src[8..24]);
            let port = u16::from_be_bytes([src[24], src[25]]);
            let proto_id = src[26];
            let target = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip_bytes), port, 0, 0));
            return Some((
                Self {
                    camo_hdr,
                    target,
                    proto_id,
                },
                OUTBOUND_PREPEND_LEN_V6,
            ));
        }

        // IPv4 (16 bytes)
        let mut camo_hdr = [0u8; 8];
        camo_hdr.copy_from_slice(&src[0..8]);
        let mut ip_bytes = [0u8; 4];
        ip_bytes.copy_from_slice(&src[8..12]);
        let port = u16::from_be_bytes([src[12], src[13]]);
        let proto_id = src[14];
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip_bytes), port));
        Some((
            Self {
                camo_hdr,
                target,
                proto_id,
            },
            OUTBOUND_PREPEND_LEN_V4,
        ))
    }
}
