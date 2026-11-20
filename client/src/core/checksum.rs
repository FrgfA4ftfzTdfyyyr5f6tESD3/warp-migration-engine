pub fn calculate_ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        if i == 10 {
            continue; // Skip checksum field itself
        }
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | (header[i + 1] as u32)
        } else {
            (header[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn calculate_udp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], udp_and_payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: Source IP
    sum = sum.wrapping_add(((src_ip[0] as u32) << 8) | (src_ip[1] as u32));
    sum = sum.wrapping_add(((src_ip[2] as u32) << 8) | (src_ip[3] as u32));

    // Pseudo-header: Destination IP
    sum = sum.wrapping_add(((dst_ip[0] as u32) << 8) | (dst_ip[1] as u32));
    sum = sum.wrapping_add(((dst_ip[2] as u32) << 8) | (dst_ip[3] as u32));

    // Pseudo-header: Protocol (17 for UDP)
    sum = sum.wrapping_add(17);

    // Pseudo-header: UDP Length
    let udp_len = udp_and_payload.len() as u16;
    sum = sum.wrapping_add(udp_len as u32);

    // UDP Header + Payload
    for i in (0..udp_and_payload.len()).step_by(2) {
        if i == 6 {
            continue; // Skip checksum field
        }
        let word = if i + 1 < udp_and_payload.len() {
            ((udp_and_payload[i] as u32) << 8) | (udp_and_payload[i + 1] as u32)
        } else {
            (udp_and_payload[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let result = !(sum as u16);
    if result == 0 {
        0xFFFF
    } else {
        result
    }
}

pub fn calculate_udp_v6_checksum(src_ip: [u8; 16], dst_ip: [u8; 16], udp_and_payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: Source IPv6 (16 bytes)
    for i in (0..16).step_by(2) {
        sum = sum.wrapping_add(((src_ip[i] as u32) << 8) | (src_ip[i + 1] as u32));
    }

    // Pseudo-header: Destination IPv6 (16 bytes)
    for i in (0..16).step_by(2) {
        sum = sum.wrapping_add(((dst_ip[i] as u32) << 8) | (dst_ip[i + 1] as u32));
    }

    // Pseudo-header: Upper-Layer Packet Length (32 bits)
    let udp_len = udp_and_payload.len() as u32;
    sum = sum.wrapping_add(udp_len >> 16);
    sum = sum.wrapping_add(udp_len & 0xFFFF);

    // Pseudo-header: Next Header (17 for UDP)
    sum = sum.wrapping_add(17);

    // UDP Header + Payload
    for i in (0..udp_and_payload.len()).step_by(2) {
        if i == 6 {
            continue; // Skip checksum field
        }
        let word = if i + 1 < udp_and_payload.len() {
            ((udp_and_payload[i] as u32) << 8) | (udp_and_payload[i + 1] as u32)
        } else {
            (udp_and_payload[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let result = !(sum as u16);
    if result == 0 {
        0xFFFF
    } else {
        result
    }
}
