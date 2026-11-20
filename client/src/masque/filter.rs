use std::net::{IpAddr, Ipv4Addr};

#[inline]
pub fn is_cloudflare_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // 162.159.192.0 - 162.159.203.255 (Cloudflare WARP AS13335)
            (o[0] == 162 && o[1] == 159 && (o[2] >= 192 && o[2] <= 203))
            // 188.114.96.0 - 188.114.99.255 (Cloudflare WARP Europe/ME AS13335)
            || (o[0] == 188 && o[1] == 114 && (o[2] >= 96 && o[2] <= 99))
        }
        IpAddr::V6(_) => false,
    }
}

#[inline]
pub fn is_cloudflare_port(port: u16) -> bool {
    matches!(
        port,
        8095 | 8595 | 8642 | 8742 | 8854 | 8886 | 8943
        | 443 | 500 | 1701 | 2408 | 4443 | 4500 | 8443
        | 5200..=5205 | 7152 | 7156 | 7284 | 7559 | 7815
        | 9034 | 9088 | 9389 | 9408 | 9555
    )
}

pub fn build_masque_filter(
    target_ip: Ipv4Addr,
    target_port: u16,
    relay_ip_v4: Ipv4Addr,
    relay_port: u16,
) -> String {
    let custom_target_dst = format!(" or ip.DstAddr == {}", target_ip);
    let custom_target_src = format!(" or ip.SrcAddr == {}", target_ip);

    let ip_dst_match = format!(
        "((ip.DstAddr >= 162.159.192.0 and ip.DstAddr <= 162.159.203.255) or \
          (ip.DstAddr >= 188.114.96.0 and ip.DstAddr <= 188.114.99.255){})",
        custom_target_dst
    );

    let ip_src_match = format!(
        "((ip.SrcAddr >= 162.159.192.0 and ip.SrcAddr <= 162.159.203.255) or \
          (ip.SrcAddr >= 188.114.96.0 and ip.SrcAddr <= 188.114.99.255){})",
        custom_target_src
    );

    let ports_dst = format!(
        "(udp.DstPort == 8095 or udp.DstPort == 8595 or udp.DstPort == 8642 or udp.DstPort == 8742 or \
          udp.DstPort == 8854 or udp.DstPort == 8886 or udp.DstPort == 8943 or udp.DstPort == 443 or \
          udp.DstPort == 2408 or udp.DstPort == 500 or udp.DstPort == 1701 or udp.DstPort == 4443 or \
          udp.DstPort == 4500 or udp.DstPort == 8443 or (udp.DstPort >= 5200 and udp.DstPort <= 5205) or \
          udp.DstPort == 7152 or udp.DstPort == 7156 or udp.DstPort == 7284 or udp.DstPort == 7559 or \
          udp.DstPort == 7815 or udp.DstPort == 9034 or udp.DstPort == 9088 or udp.DstPort == 9389 or \
          udp.DstPort == 9408 or udp.DstPort == 9555 or udp.DstPort == {})",
        target_port
    );

    let ports_src = format!(
        "(udp.SrcPort == 8095 or udp.SrcPort == 8595 or udp.SrcPort == 8642 or udp.SrcPort == 8742 or \
          udp.SrcPort == 8854 or udp.SrcPort == 8886 or udp.SrcPort == 8943 or udp.SrcPort == 443 or \
          udp.SrcPort == 2408 or udp.SrcPort == 500 or udp.SrcPort == 1701 or udp.SrcPort == 4443 or \
          udp.SrcPort == 4500 or udp.SrcPort == 8443 or (udp.SrcPort >= 5200 and udp.SrcPort <= 5205) or \
          udp.SrcPort == 7152 or udp.SrcPort == 7156 or udp.SrcPort == 7284 or udp.SrcPort == 7559 or \
          udp.SrcPort == 7815 or udp.SrcPort == 9034 or udp.SrcPort == 9088 or udp.SrcPort == 9389 or \
          udp.SrcPort == 9408 or udp.SrcPort == 9555 or udp.SrcPort == {})",
        target_port
    );

    let outbound_filter = format!("(outbound and ip and udp and ({}) and ({}))", ip_dst_match, ports_dst);

    let inbound_filter = format!(
        "(inbound and ip and udp and (\
            (ip.SrcAddr == {} and udp.SrcPort == {}) or \
            (({}) and ({}))\
        ))",
        relay_ip_v4, relay_port,
        ip_src_match, ports_src
    );

    format!("{} or {}", outbound_filter, inbound_filter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_cloudflare_ip_ranges_v4() {
        assert!(is_cloudflare_ip(IpAddr::from_str("162.159.192.1").unwrap()));
        assert!(is_cloudflare_ip(IpAddr::from_str("162.159.198.2").unwrap()));
        assert!(is_cloudflare_ip(IpAddr::from_str("162.159.203.254").unwrap()));
        assert!(is_cloudflare_ip(IpAddr::from_str("188.114.96.1").unwrap()));
        assert!(is_cloudflare_ip(IpAddr::from_str("188.114.97.10").unwrap()));
        assert!(is_cloudflare_ip(IpAddr::from_str("188.114.99.250").unwrap()));

        assert!(!is_cloudflare_ip(IpAddr::from_str("162.159.204.1").unwrap()));
        assert!(!is_cloudflare_ip(IpAddr::from_str("188.114.100.1").unwrap()));
        assert!(!is_cloudflare_ip(IpAddr::from_str("8.8.8.8").unwrap()));
        // IPv6 ignored in Method 2
        assert!(!is_cloudflare_ip(IpAddr::from_str("2606:4700:103::2").unwrap()));
    }

    #[test]
    fn test_cloudflare_ports() {
        assert!(is_cloudflare_port(8095));
        assert!(is_cloudflare_port(8595));
        assert!(is_cloudflare_port(8854));
        assert!(is_cloudflare_port(443));
        assert!(is_cloudflare_port(5201));
        assert!(is_cloudflare_port(9555));
        assert!(!is_cloudflare_port(80));
        assert!(!is_cloudflare_port(53));
    }
}
