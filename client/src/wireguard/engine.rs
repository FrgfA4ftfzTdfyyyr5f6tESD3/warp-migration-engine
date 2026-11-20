use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use masque_common::{
    get_next_auto_proto, get_protocol_by_id, FastRng,
};
use windivert::prelude::*;

use crate::core::checksum::{
    calculate_ipv4_checksum, calculate_udp_checksum, calculate_udp_v6_checksum,
};
use crate::core::packet::{parse_ip_udp, ParsedIpUdp};
use crate::wireguard::reverse_rekey::{
    handle_inbound_hs, handle_outbound_hs, handle_outbound_resp, RekeyVerdict,
};
use crate::wireguard::state::{FlowState, FlowTable};

pub struct WireGuardConfig {
    pub proto_id: u8,
    pub reverse_rekey: bool,
    pub verbose: bool,
}

pub fn run_wireguard_engine(
    config: WireGuardConfig,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let filter = "(udp.PayloadLength == 148 and udp.Payload32[0] == 0x01000000) or (udp.PayloadLength == 92 and udp.Payload32[0] == 0x02000000)";

    println!("=========================================================================");
    println!("  WireGuard / UDP Direct Desync Engine (Zero-NAT + Cover Envelope)");
    println!("=========================================================================");
    println!("  Kernel Driver : WinDivert 2.2.2 Signed Driver (Layer 3 WFP Filtering)");
    println!("  Operation Mode: Direct Standalone Desync (Zero Relay Overhead)");
    println!("  Port Strategy : Authentic Client Ephemeral Port Preservation (Zero-NAT)");
    println!("  Reverse Rekey : {}", if config.reverse_rekey { "ENABLED (Noise_IK Role Swap Active)" } else { "DISABLED (Standard Session Lock)" });
    println!("  Initial Mode  : {}", if config.proto_id == 0 { "AUTO (Strict Non-Repeating Tier-1 Golden Protocols)" } else { get_protocol_by_id(config.proto_id).name });
    println!("  Kernel Filter : {}", filter);
    println!("=========================================================================");
    println!("  WinDivert handle active. Intercepting WireGuard handshakes... (Ctrl+C to stop)\n");

    let wd = match WinDivert::network(filter, 0, WinDivertFlags::default()) {
        Ok(d) => Arc::new(d),
        Err(e) => {
            eprintln!("[ERROR] Failed to open WinDivert handle: {:?}", e);
            eprintln!("        Please ensure the program is run as Administrator.");
            return Ok(());
        }
    };

    let wd_ctrlc = wd.clone();
    let r_ctrlc = running.clone();
    let _ = ctrlc::set_handler(move || {
        println!("\n[!] Ctrl+C detected. Shutting down WireGuard engine cleanly...");
        r_ctrlc.store(false, Ordering::SeqCst);
        let _ = wd_ctrlc.shutdown(WinDivertShutdownMode::Both);
    });

    let flow_table = Arc::new(Mutex::new(FlowTable::new()));
    let mut rng = FastRng::new();
    let mut last_auto_id: Option<u8> = None;
    let mut hs_counter: u64 = 0;
    let mut packet_buf = vec![0u8; 65535];

    while running.load(Ordering::SeqCst) {
        let packet = match wd.recv(Some(&mut packet_buf)) {
            Ok(p) => p,
            Err(e) => {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                if config.verbose {
                    eprintln!("[WARN] WinDivert recv error: {:?}", e);
                }
                continue;
            }
        };

        let is_outbound = packet.address.outbound();
        let raw_data = &packet.data;

        let parsed = match parse_ip_udp(raw_data) {
            Some(p) => p,
            None => {
                let _ = wd.send(&packet);
                continue;
            }
        };

        let payload_len = parsed.payload_len();
        let payload_start = parsed.payload_start();
        let payload = &raw_data[payload_start..payload_start + payload_len];

        let (src_addr, dst_addr) = match &parsed {
            ParsedIpUdp::V4(v4) => (
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(v4.src_ip)), v4.src_port),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(v4.dst_ip)), v4.dst_port),
            ),
            ParsedIpUdp::V6(v6) => (
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(v6.src_ip)), v6.src_port),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(v6.dst_ip)), v6.dst_port),
            ),
        };

        let flow_key = FlowTable::get_flow_key(src_addr, dst_addr, !is_outbound);

        // =========================================================================
        // 1. INBOUND PACKET HANDLING (Server -> Client)
        // =========================================================================
        if !is_outbound {
            // Inbound Type 2: WireGuard Handshake Response (92 bytes: 0x02 0x00 0x00 0x00)
            if payload_len == 92 && payload[0] == 2 && payload[1..4] == [0, 0, 0] {
                {
                    let mut table = flow_table.lock().unwrap();
                    table.set_established(&flow_key);
                }

                let time_now = chrono_prefix();
                println!("=========================================================================");
                println!("  WIREGUARD SERVER RESPONSE (Type 2 - 92 B) RECEIVED!");
                println!("-------------------------------------------------------------------------");
                println!("  Time          : {}", time_now);
                println!("  Flow          : {} (Response received)", flow_key);
                println!("  Session State : LOCKED_ESTABLISHED (Connection Successfully Secured)");
                println!("  Zero-Latency  : Passed directly to kernel / Wintun (Noise_IK timer intact)");
                println!("  Desync Engine : Disengaged for this flow. All subsequent packets pass directly.");
                println!("=========================================================================\n");
            }

            // Inbound Type 1: Server-Initiated Rekey (Reverse Rekey Beta: 148 bytes)
            if payload_len == 148 && payload[0] == 1 && payload[1..4] == [0, 0, 0] && config.reverse_rekey {
                let mut table = flow_table.lock().unwrap();
                if let Some(entry) = table.get_entry_mut(&flow_key) {
                    handle_inbound_hs(entry, Instant::now());
                }
            }

            let _ = wd.send(&packet);
            continue;
        }

        // =========================================================================
        // 2. OUTBOUND PACKET HANDLING (Client -> Server)
        // =========================================================================

        // Outbound Type 2: Client Response in Reverse Rekey (92 bytes)
        if payload_len == 92 && payload[0] == 2 && payload[1..4] == [0, 0, 0] && config.reverse_rekey {
            let mut table = flow_table.lock().unwrap();
            if let Some(entry) = table.get_entry_mut(&flow_key) {
                handle_outbound_resp(entry, Instant::now());
            }
            let _ = wd.send(&packet);
            continue;
        }

        // Outbound Type 1: WireGuard Handshake Initiation (148 bytes)
        if payload_len == 148 && payload[0] == 1 && payload[1..4] == [0, 0, 0] {
            let state = {
                let mut table = flow_table.lock().unwrap();
                table.get_state(&flow_key)
            };

            // Case 1: Session is already established (Re-keying)
            if state == Some(FlowState::Established) {
                if config.reverse_rekey {
                    let mut table = flow_table.lock().unwrap();
                    if let Some(entry) = table.get_entry_mut(&flow_key) {
                        let verdict = handle_outbound_hs(entry, Instant::now());
                        if verdict == RekeyVerdict::Drop {
                            continue; // Suppressed for reverse rekey
                        }
                    }
                }

                println!(
                    "  [SESSION LOCKED] Re-keying on active flow {} ---> Direct Passthrough",
                    flow_key
                );
                let _ = wd.send(&packet);
                continue;
            }

            // Case 2: Duplicate handshake on an unestablished, already-tried flow
            if state == Some(FlowState::Tried) {
                println!(
                    "  [DUPLICATE HANDSHAKE DROPPED] Retried on unestablished flow {} ---> DROPPED",
                    flow_key
                );
                println!("  Reason: Forcing client (Windscribe/WireGuard) to rotate to a fresh ephemeral port immediately.\n");
                continue; // VERDICT_DROP
            }

            // Case 3: Fresh flow key (Attempt 1 on new ephemeral port)
            let start_time = Instant::now();
            hs_counter += 1;
            {
                let mut table = flow_table.lock().unwrap();
                table.register_attempt(&flow_key, hs_counter);
            }

            // Select protocol spec
            let (active_proto_id, is_auto) = if config.proto_id == 0 {
                let picked = get_next_auto_proto(last_auto_id, &mut rng);
                last_auto_id = Some(picked);
                (picked, true)
            } else {
                (config.proto_id, false)
            };

            let spec = get_protocol_by_id(active_proto_id);
            let time_now = chrono_prefix();
            let tier_label = if is_auto { " [Tier-1 Auto-Selected]" } else { "" };

            println!("=========================================================================");
            println!("  WIREGUARD HANDSHAKE #{} DETECTED (Fresh Ephemeral Port)", hs_counter);
            println!("-------------------------------------------------------------------------");
            println!("  Time          : {}", time_now);
            println!("  Flow (Wire)   : {}", flow_key);
            println!("  Framing Mode  : Dual-Phase Cover Envelope ({}){}", spec.name, tier_label);
            println!("  Envelope Plan : LEAD-IN (I1 Signature + I2 Timestamp) ➔ HANDSHAKE (148B Authentic) ➔ DUAL TRAIL (60ms, 180ms)");
            println!("  Port Strategy : Authentic Client Ephemeral Port (Zero-NAT)");
            println!("-------------------------------------------------------------------------");

            // Execute Dual-Phase Cover Envelope
            let jc = if spec.c_min == spec.c_max {
                spec.c_min
            } else {
                spec.c_min + (rng.next_u32() as usize % (spec.c_max - spec.c_min + 1))
            };

            let total_window_ms = 1800 + (rng.next_u32() as u64 % 600); // 1.8s - 2.4s
            let interval_ms = total_window_ms / (jc as u64);

            // Phase 1: Lead-In (I1 Signature + I2 Dynamic Timestamps)
            for i in 1..=jc {
                let cur_size = if spec.s_min == spec.s_max {
                    spec.s_min
                } else {
                    spec.s_min + (rng.next_u32() as usize % (spec.s_max - spec.s_min + 1))
                };

                let lead_payload = masque_common::protocols::build_lead_payload(
                    active_proto_id,
                    cur_size,
                    i,
                    &mut rng,
                );

                let dummy_packet_data = build_raw_ip_udp_packet(&parsed, &lead_payload);
                let mut dummy_win_packet = WinDivertPacket {
                    address: packet.address.clone(),
                    data: std::borrow::Cow::Owned(dummy_packet_data),
                };
                let _ = dummy_win_packet.recalculate_checksums(ChecksumFlags::new());
                let _ = wd.send(&dummy_win_packet);

                let cur_t = start_time.elapsed().as_millis();
                let stage_label = if i == 1 { "I1: SIGNATURE" } else { "I2: TIMESTAMP" };
                println!(
                    "    [LEAD-IN {}/{} ({})] -> Size: {:4} B   [SENT at t+{}ms]",
                    i, jc, stage_label, lead_payload.len(), cur_t
                );

                thread::sleep(Duration::from_millis(interval_ms));
            }

            // Phase 2: Authentic 148-Byte WireGuard Handshake Released
            let addr_trail = packet.address.clone();
            let _ = wd.send(&packet);
            let hs_t = start_time.elapsed().as_millis();
            println!(
                "    [HANDSHAKE]     -> Size:  148 B   [SENT at t+{}ms] ---> [PASSED]",
                hs_t
            );

            // Phase 3: Dual Non-Blocking Trail Cover Packets
            let wd_trail = Arc::clone(&wd);
            let parsed_trail = parsed.clone();
            let s_min = spec.s_min;
            let s_max = spec.s_max;

            thread::spawn(move || {
                let mut trail_rng = FastRng::new();

                // Trail 1 at +60ms
                thread::sleep(Duration::from_millis(60));
                let cur_size_1 = if s_min == s_max { s_min } else { s_min + (trail_rng.next_u32() as usize % (s_max - s_min + 1)) };
                let trail_payload_1 = masque_common::protocols::build_lead_payload(active_proto_id, cur_size_1, jc + 1, &mut trail_rng);
                let dummy_1 = build_raw_ip_udp_packet(&parsed_trail, &trail_payload_1);
                let mut win_pkt_1 = WinDivertPacket {
                    address: addr_trail.clone(),
                    data: std::borrow::Cow::Owned(dummy_1),
                };
                let _ = win_pkt_1.recalculate_checksums(ChecksumFlags::new());
                let _ = wd_trail.send(&win_pkt_1);

                let t1 = start_time.elapsed().as_millis();
                println!("    [TRAIL 1/2]     -> Size: {:4} B   [SENT at t+{}ms] ---> [RETURN PATH SHIELD]", trail_payload_1.len(), t1);

                // Trail 2 at +180ms (+120ms after trail 1)
                thread::sleep(Duration::from_millis(120));
                let cur_size_2 = if s_min == s_max { s_min } else { s_min + (trail_rng.next_u32() as usize % (s_max - s_min + 1)) };
                let trail_payload_2 = masque_common::protocols::build_lead_payload(active_proto_id, cur_size_2, jc + 2, &mut trail_rng);
                let dummy_2 = build_raw_ip_udp_packet(&parsed_trail, &trail_payload_2);
                let mut win_pkt_2 = WinDivertPacket {
                    address: addr_trail,
                    data: std::borrow::Cow::Owned(dummy_2),
                };
                let _ = win_pkt_2.recalculate_checksums(ChecksumFlags::new());
                let _ = wd_trail.send(&win_pkt_2);

                let t2 = start_time.elapsed().as_millis();
                println!("    [TRAIL 2/2]     -> Size: {:4} B   [SENT at t+{}ms] ---> [FLOW WARM ACTIVE]", trail_payload_2.len(), t2);

                let total_elapsed = start_time.elapsed().as_secs_f32();
                println!("-------------------------------------------------------------------------");
                println!("  Envelope Cycle Completed at t+{:.2}s | Status: SECURED", total_elapsed);
                println!("=========================================================================\n");
            });

            continue;
        }

        // Passthrough other packets
        let _ = wd.send(&packet);
    }

    println!("[*] WireGuard engine shut down cleanly.");
    Ok(())
}

fn chrono_prefix() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now();
    let duration = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = duration.as_secs();
    let hours = (secs / 3600) % 24;
    let mins = (secs / 60) % 60;
    let s = secs % 60;
    format!("[{:02}:{:02}:{:02}]", hours, mins, s)
}

fn build_raw_ip_udp_packet(parsed: &ParsedIpUdp, payload: &[u8]) -> Vec<u8> {
    match parsed {
        ParsedIpUdp::V4(v4) => {
            let ihl = v4.ihl;
            let udp_len = (8 + payload.len()) as u16;
            let total_len = (ihl + 8 + payload.len()) as u16;
            let mut buf = vec![0u8; total_len as usize];

            // IPv4 header (first 20 bytes or ihl)
            buf[0] = 0x45; // Version 4, IHL 5
            buf[1] = 0x00; // DSCP / ECN
            buf[2..4].copy_from_slice(&total_len.to_be_bytes());
            buf[4..6].copy_from_slice(&[0x12, 0x34]); // IP ID
            buf[6..8].copy_from_slice(&[0x40, 0x00]); // Don't fragment
            buf[8] = 64; // TTL
            buf[9] = 17; // UDP
            buf[12..16].copy_from_slice(&v4.src_ip);
            buf[16..20].copy_from_slice(&v4.dst_ip);
            let ip_csum = calculate_ipv4_checksum(&buf[0..ihl]);
            buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

            // UDP header
            let u_start = ihl;
            buf[u_start..u_start + 2].copy_from_slice(&v4.src_port.to_be_bytes());
            buf[u_start + 2..u_start + 4].copy_from_slice(&v4.dst_port.to_be_bytes());
            buf[u_start + 4..u_start + 6].copy_from_slice(&udp_len.to_be_bytes());
            buf[u_start + 8..].copy_from_slice(payload);

            let udp_csum = calculate_udp_checksum(v4.src_ip, v4.dst_ip, &buf[u_start..]);
            buf[u_start + 6..u_start + 8].copy_from_slice(&udp_csum.to_be_bytes());
            buf
        }
        ParsedIpUdp::V6(v6) => {
            let udp_len = (8 + payload.len()) as u16;
            let total_len = 40 + 8 + payload.len();
            let mut buf = vec![0u8; total_len];

            // IPv6 header (40 bytes)
            buf[0] = 0x60; // Version 6
            buf[4..6].copy_from_slice(&udp_len.to_be_bytes()); // Payload Length
            buf[6] = 17; // Next Header = UDP
            buf[7] = 64; // Hop Limit
            buf[8..24].copy_from_slice(&v6.src_ip);
            buf[24..40].copy_from_slice(&v6.dst_ip);

            // UDP header
            let u_start = 40;
            buf[u_start..u_start + 2].copy_from_slice(&v6.src_port.to_be_bytes());
            buf[u_start + 2..u_start + 4].copy_from_slice(&v6.dst_port.to_be_bytes());
            buf[u_start + 4..u_start + 6].copy_from_slice(&udp_len.to_be_bytes());
            buf[u_start + 8..].copy_from_slice(payload);

            let udp_csum = calculate_udp_v6_checksum(v6.src_ip, v6.dst_ip, &buf[u_start..]);
            buf[u_start + 6..u_start + 8].copy_from_slice(&udp_csum.to_be_bytes());
            buf
        }
    }
}
