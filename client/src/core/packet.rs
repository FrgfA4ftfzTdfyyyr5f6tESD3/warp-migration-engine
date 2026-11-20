use crate::core::checksum::{
    calculate_ipv4_checksum, calculate_udp_checksum, calculate_udp_v6_checksum,
};

#[derive(Debug, Clone)]
pub struct ParsedIpv4Udp {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub ihl: usize,
    pub udp_header_start: usize,
    pub payload_start: usize,
    pub payload_len: usize,
}

#[derive(Debug, Clone)]
pub struct ParsedIpv6Udp {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub udp_header_start: usize,
    pub payload_start: usize,
    pub payload_len: usize,
}

#[derive(Debug, Clone)]
pub enum ParsedIpUdp {
    V4(ParsedIpv4Udp),
    V6(ParsedIpv6Udp),
}

impl ParsedIpUdp {
    #[inline]
    pub fn src_port(&self) -> u16 {
        match self {
            Self::V4(p) => p.src_port,
            Self::V6(p) => p.src_port,
        }
    }

    #[inline]
    pub fn dst_port(&self) -> u16 {
        match self {
            Self::V4(p) => p.dst_port,
            Self::V6(p) => p.dst_port,
        }
    }

    #[inline]
    pub fn payload_start(&self) -> usize {
        match self {
            Self::V4(p) => p.payload_start,
            Self::V6(p) => p.payload_start,
        }
    }

    #[inline]
    pub fn payload_len(&self) -> usize {
        match self {
            Self::V4(p) => p.payload_len,
            Self::V6(p) => p.payload_len,
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub fn udp_header_start(&self) -> usize {
        match self {
            Self::V4(p) => p.udp_header_start,
            Self::V6(p) => p.udp_header_start,
        }
    }
}

pub fn parse_ip_udp(data: &[u8]) -> Option<ParsedIpUdp> {
    if data.is_empty() {
        return None;
    }

    let version = data[0] >> 4;
    match version {
        4 => parse_ipv4_udp(data).map(ParsedIpUdp::V4),
        6 => parse_ipv6_udp(data).map(ParsedIpUdp::V6),
        _ => None,
    }
}

pub fn parse_ipv4_udp(data: &[u8]) -> Option<ParsedIpv4Udp> {
    if data.len() < 20 {
        return None;
    }

    let version = data[0] >> 4;
    if version != 4 {
        return None;
    }

    let ihl = (data[0] & 0x0F) as usize * 4;
    if ihl < 20 || data.len() < ihl + 8 {
        return None;
    }

    let protocol = data[9];
    if protocol != 17 {
        return None;
    }

    let src_ip = [data[12], data[13], data[14], data[15]];
    let dst_ip = [data[16], data[17], data[18], data[19]];

    let udp_start = ihl;
    let src_port = u16::from_be_bytes([data[udp_start], data[udp_start + 1]]);
    let dst_port = u16::from_be_bytes([data[udp_start + 2], data[udp_start + 3]]);
    let udp_len = u16::from_be_bytes([data[udp_start + 4], data[udp_start + 5]]) as usize;

    if udp_len < 8 || data.len() < udp_start + udp_len {
        return None;
    }

    let payload_start = udp_start + 8;
    let payload_len = udp_len - 8;

    Some(ParsedIpv4Udp {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        ihl,
        udp_header_start: udp_start,
        payload_start,
        payload_len,
    })
}

pub fn parse_ipv6_udp(data: &[u8]) -> Option<ParsedIpv6Udp> {
    if data.len() < 40 + 8 {
        return None;
    }

    let version = data[0] >> 4;
    if version != 6 {
        return None;
    }

    let next_header = data[6];
    if next_header != 17 {
        return None;
    }

    let mut src_ip = [0u8; 16];
    src_ip.copy_from_slice(&data[8..24]);

    let mut dst_ip = [0u8; 16];
    dst_ip.copy_from_slice(&data[24..40]);

    let udp_start = 40;
    let src_port = u16::from_be_bytes([data[udp_start], data[udp_start + 1]]);
    let dst_port = u16::from_be_bytes([data[udp_start + 2], data[udp_start + 3]]);
    let udp_len = u16::from_be_bytes([data[udp_start + 4], data[udp_start + 5]]) as usize;

    if udp_len < 8 || data.len() < udp_start + udp_len {
        return None;
    }

    let payload_start = udp_start + 8;
    let payload_len = udp_len - 8;

    Some(ParsedIpv6Udp {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        udp_header_start: udp_start,
        payload_start,
        payload_len,
    })
}

pub fn build_ipv4_udp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ihl = 20usize;
    let udp_len = (8 + payload.len()) as u16;
    let total_len = (ihl + 8 + payload.len()) as u16;
    let mut buf = vec![0u8; total_len as usize];

    // IPv4 header (20 bytes)
    buf[0] = 0x45; // Version 4, IHL 5
    buf[1] = 0x00; // DSCP / ECN
    buf[2..4].copy_from_slice(&total_len.to_be_bytes());
    buf[4..6].copy_from_slice(&[0x12, 0x34]); // IP ID
    buf[6..8].copy_from_slice(&[0x40, 0x00]); // Don't fragment
    buf[8] = 64; // TTL
    buf[9] = 17; // UDP
    buf[12..16].copy_from_slice(&src_ip);
    buf[16..20].copy_from_slice(&dst_ip);
    let ip_csum = calculate_ipv4_checksum(&buf[0..ihl]);
    buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // UDP header
    let u_start = ihl;
    buf[u_start..u_start + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[u_start + 2..u_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[u_start + 4..u_start + 6].copy_from_slice(&udp_len.to_be_bytes());
    buf[u_start + 8..].copy_from_slice(payload);

    let udp_csum = calculate_udp_checksum(src_ip, dst_ip, &buf[u_start..]);
    buf[u_start + 6..u_start + 8].copy_from_slice(&udp_csum.to_be_bytes());
    buf
}

#[allow(dead_code)]
pub fn build_ipv6_udp_packet(
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let total_len = 40 + 8 + payload.len();
    let mut buf = vec![0u8; total_len];

    // IPv6 header (40 bytes)
    buf[0] = 0x60; // Version 6
    buf[4..6].copy_from_slice(&udp_len.to_be_bytes()); // Payload Length
    buf[6] = 17; // Next Header = UDP
    buf[7] = 64; // Hop Limit
    buf[8..24].copy_from_slice(&src_ip);
    buf[24..40].copy_from_slice(&dst_ip);

    // UDP header
    let u_start = 40;
    buf[u_start..u_start + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[u_start + 2..u_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[u_start + 4..u_start + 6].copy_from_slice(&udp_len.to_be_bytes());
    buf[u_start + 8..].copy_from_slice(payload);

    let udp_csum = calculate_udp_v6_checksum(src_ip, dst_ip, &buf[u_start..]);
    buf[u_start + 6..u_start + 8].copy_from_slice(&udp_csum.to_be_bytes());
    buf
}
