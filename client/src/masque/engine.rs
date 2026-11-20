use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use masque_common::{get_next_masque_auto_proto, get_protocol_by_id, FastRng};
use windivert::prelude::*;

use crate::core::envelope::EnvelopeEngine;
use crate::core::packet::{parse_ip_udp, ParsedIpUdp};
use crate::core::session::{MigrationAction, SessionTable};
use crate::masque::filter::{build_masque_filter, is_cloudflare_ip, is_cloudflare_port};
use crate::masque::lead_in::{send_direct_lead_in, send_relay_warmup};
use crate::protocols::quic::migration::{inspect_all_quic_packets, inspect_quic_packet, QuicPacketKind};

pub struct MasqueConfig {
    pub proto_id: u8,
    pub target_ip: String,
    pub target_port: u16,
    pub relay_ip: String,
    pub relay_port: u16,
    pub zero_csum: bool,
    pub verbose: bool,
}

pub fn run_masque_engine(
    config: MasqueConfig,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let target_ip_v4 = Ipv4Addr::from_str(&config.target_ip).unwrap_or(Ipv4Addr::new(162, 159, 198, 2));
    let relay_ip_v4 = Ipv4Addr::from_str(&config.relay_ip).unwrap_or(Ipv4Addr::new(172, 99, 188, 64));
    let relay_ip_v4_bytes = relay_ip_v4.octets();
    let relay_port = config.relay_port;

    // Strict IPv4 Multi-Range WinDivert Kernel Filter (No IPv6)
    let filter = build_masque_filter(target_ip_v4, config.target_port, relay_ip_v4, relay_port);

    println!("=========================================================================");
    println!("  WinDivert QUIC / MASQUE Modular Tunnel Engine (Rust Native v4.5)");
    println!("=========================================================================");
    println!("  Kernel Layer   : Layer 3 Network (WFP / WinDivert 2.2.2 Signed Driver)");
    println!("  Relay Server   : {}:{} (Amsterdam Musl Relay)", relay_ip_v4, relay_port);
    println!("  Target Service : Cloudflare WARP IPv4 (162.159.192.0..203.255 & 188.114.96.0..99.255)");
    println!("  Default Target : {}:{}", target_ip_v4, config.target_port);
    println!("  Initial Mask   : {}", if config.proto_id == 0 { "AUTO (Tier-1: ESP, STUN, WebRTC, DTLS)" } else { get_protocol_by_id(config.proto_id).name });
    println!("  Envelope Mode  : 16B Dynamic Prepend Envelope + Untouched QUIC Payload");
    println!("  Route Mode     : 1st Migration Instant Lock + Direct Wire-Speed (Press [ENTER] to Re-Arm)");
    println!("=========================================================================");
    println!("  WinDivert handle active. Intercepting QUIC traffic... (Ctrl+C to stop)\n");

    let wd = match WinDivert::network(&filter, 0, WinDivertFlags::default()) {
        Ok(d) => Arc::new(d),
        Err(e) => {
            eprintln!("\n=========================================================================");
            eprintln!("  [ERROR] Failed to open WinDivert kernel driver: {:?}", e);
            eprintln!("=========================================================================");
            eprintln!("  1. Please ensure you Run as Administrator (Right click -> Run as admin).");
            eprintln!("  2. Ensure WinDivert.dll and WinDivert64.sys are in the same folder.");
            eprintln!("=========================================================================\n");
            println!("Press Enter to exit...");
            let mut dummy = String::new();
            let _ = std::io::stdin().read_line(&mut dummy);
            return Ok(());
        }
    };

    let wd_ctrlc = wd.clone();
    let r_ctrlc = running.clone();
    let _ = ctrlc::set_handler(move || {
        println!("\n[!] Ctrl+C detected. Shutting down MASQUE engine cleanly...");
        r_ctrlc.store(false, Ordering::SeqCst);
        let _ = wd_ctrlc.shutdown(WinDivertShutdownMode::Both);
    });

    let relay_locked = Arc::new(AtomicBool::new(false));

    // Stdin listener thread for re-arming relay with [Enter]
    {
        let relay_locked_rearm = relay_locked.clone();
        let running_rearm = running.clone();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut line = String::new();
            while running_rearm.load(Ordering::SeqCst) {
                line.clear();
                if stdin.read_line(&mut line).is_ok() {
                    if relay_locked_rearm.swap(false, Ordering::SeqCst) {
                        println!("\n{} [RELAY ARMED] Ready for next handshake migration...\n", chrono_prefix());
                    } else {
                        println!("\n{} [RELAY ALREADY ARMED] Ready for handshake migration.\n", chrono_prefix());
                    }
                }
            }
        });
    }

    let mut envelope_engine = EnvelopeEngine::new();
    let session_table = Arc::new(Mutex::new(SessionTable::new()));
    let mut rng = FastRng::new();
    let mut last_auto_id: Option<u8> = None;
    let mut packet_buf = vec![0u8; 65535];

    while running.load(Ordering::SeqCst) {
        let mut packet = match wd.recv(Some(&mut packet_buf)) {
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

        // Strictly process IPv4 packets; bypass any other packet untouched
        let v4 = match &parsed {
            ParsedIpUdp::V4(v4) => v4,
            _ => {
                let _ = wd.send(&packet);
                continue;
            }
        };

        let src_port = parsed.src_port();
        let dst_port = parsed.dst_port();
        let payload_len = parsed.payload_len();
        let payload_start = parsed.payload_start();
        let payload = &raw_data[payload_start..payload_start + payload_len];

        // 1. OUTBOUND PACKETS (Client -> Cloudflare Target)
        if is_outbound {
            let dst_ip = IpAddr::V4(Ipv4Addr::from(v4.dst_ip));
            let is_cf = is_cloudflare_ip(dst_ip) || dst_ip == IpAddr::V4(target_ip_v4);
            let port_match = is_cloudflare_port(dst_port) || dst_port == config.target_port;
            let target_addr = SocketAddr::new(dst_ip, dst_port);

            if is_cf && port_match {
                // FAST-PATH: If this client session is already migrated and sending Short 1-RTT Data (not Long Header 0x80),
                // pass it straight to direct wire-speed without inspection or logging!
                let is_short_migrated = {
                    let table = session_table.lock().unwrap();
                    table.is_migrated(src_port) && (!payload.is_empty() && (payload[0] & 0x80) == 0)
                };

                if is_short_migrated {
                    let _ = packet.recalculate_checksums(ChecksumFlags::new());
                    let _ = wd.send(&packet);
                    continue;
                }

                let (quic_kind, _quic_desc) = inspect_quic_packet(payload);

                // Auto-protocol resolution strictly restricted to Mode 2 Tier-1 ([7, 10, 4, 5])
                let chosen_proto = if config.proto_id == 0 {
                    let picked = get_next_masque_auto_proto(last_auto_id, &mut rng);
                    last_auto_id = Some(picked);
                    picked
                } else {
                    config.proto_id
                };

                let (locked_proto, needs_warmup, action) = {
                    let mut table = session_table.lock().unwrap();
                    let (proto, _) = table.get_or_create(src_port, target_addr, chosen_proto);
                    let warmup = quic_kind == QuicPacketKind::LongInitial && !table.is_warmup_done(src_port);
                    if warmup {
                        table.mark_warmup_done(src_port);
                    }
                    let act = table.handle_outbound_migration(src_port, quic_kind);
                    (proto, warmup, act)
                };

                // If relay is isolated after 1st migration, drop unmigrated packets aiming for relay (VERDICT_DROP)
                if let MigrationAction::SendRelayInitial { .. } = action {
                    if relay_locked.load(Ordering::SeqCst) {
                        // Drop competing / secondary packets so zero bytes reach Amsterdam Relay
                        continue;
                    }
                }

                // Warm-Up Lead-In (2x 48B packets 10ms apart to prime NAT/DPI before heavy Initial packets to Relay)
                if needs_warmup && !relay_locked.load(Ordering::SeqCst) {
                    send_relay_warmup(
                        &wd,
                        &packet.address,
                        &parsed,
                        relay_ip_v4_bytes,
                        relay_port,
                        locked_proto,
                        src_port,
                        &mut rng,
                        chrono_prefix,
                    );
                }

                // Handle Migration Actions
                match action {
                    MigrationAction::TriggerInitialMigration { short_pkn } => {
                        send_direct_lead_in(
                            &wd,
                            &packet.address,
                            v4.src_ip,
                            src_port,
                            target_addr,
                            locked_proto,
                            &mut rng,
                            chrono_prefix,
                        );

                        println!(
                            "{} [MIGRATED -> DIRECT] Client :{} -> Direct Cloudflare {} (Backup Cushion {} Pkts, Permanent Direct)",
                            chrono_prefix(), src_port, target_addr, short_pkn
                        );

                        if !relay_locked.swap(true, Ordering::SeqCst) {
                            println!(
                                "{} [RELAY LOCKED] 1st session migrated. Relay immediately isolated. Press [ENTER] to re-arm...",
                                chrono_prefix()
                            );
                        }

                        let _ = packet.recalculate_checksums(ChecksumFlags::new());
                        let _ = wd.send(&packet);
                        continue;
                    }
                    MigrationAction::SendDirect => {
                        let _ = packet.recalculate_checksums(ChecksumFlags::new());
                        let _ = wd.send(&packet);
                        continue;
                    }
                    MigrationAction::SendRelayInitial { short_pkn } => {
                        // Prepend 16B Dynamic Envelope and route to Amsterdam Relay
                        let mut mod_packet = raw_data.to_vec();
                        let (new_payload_len, _) = envelope_engine.apply_outbound_envelope_v4(
                            &mut mod_packet,
                            v4,
                            relay_ip_v4_bytes,
                            relay_port,
                            v4.dst_ip,
                            v4.dst_port,
                            locked_proto,
                        );

                        let count = {
                            let mut table = session_table.lock().unwrap();
                            table.inc_outbound()
                        };

                        let proto_spec = get_protocol_by_id(locked_proto);

                        // Concise, meaningful handshake logging:
                        if quic_kind == QuicPacketKind::LongInitial {
                            if count <= 2 || count % 10 == 0 {
                                println!(
                                    "{} [HANDSHAKE] Client :{} -> Initial ({}) [Mask: {}] -> Relay -> {}",
                                    chrono_prefix(), src_port, payload_len, proto_spec.key, target_addr
                                );
                            }
                        } else if quic_kind == QuicPacketKind::LongHandshake {
                            println!(
                                "{} [HANDSHAKE] Client :{} -> Handshake ({}) [Mask: {}] -> Relay -> {}",
                                chrono_prefix(), src_port, payload_len, proto_spec.key, target_addr
                            );
                        } else if quic_kind == QuicPacketKind::Short1Rtt {
                            // Only log key milestones during the backup transit to avoid terminal spam
                            if short_pkn == 1 || short_pkn == 10 || short_pkn == 19 {
                                println!(
                                    "{} [1-RTT TRANSIT] Client :{} -> Packet {}/20 via Relay -> {} (Awaiting 2nd Handshake Confirm)",
                                    chrono_prefix(), src_port, short_pkn, target_addr
                                );
                            }
                        } else if config.verbose {
                            println!(
                                "{} [OUTBOUND #{} | PREPEND 16B] Client :{} -> Mask [{}] ({}B + 16B = {}B) -> Relay",
                                chrono_prefix(), count, src_port, proto_spec.key, payload_len, new_payload_len
                            );
                        }

                        let mut send_packet = WinDivertPacket {
                            address: packet.address,
                            data: std::borrow::Cow::Owned(mod_packet),
                        };
                        let _ = send_packet.recalculate_checksums(ChecksumFlags::new());
                        if let Err(e) = wd.send(&send_packet) {
                            eprintln!("{} [ERROR] Failed to send outbound packet: {:?}", chrono_prefix(), e);
                        }
                        continue;
                    }
                }
            }
        } else {
            // 2. INBOUND PACKETS (From Relay or Direct Cloudflare -> Client)
            let is_from_relay = v4.src_ip == relay_ip_v4_bytes && v4.src_port == relay_port;

            if is_from_relay {
                let (target_restore, _locked_proto) = {
                    let table = session_table.lock().unwrap();
                    if let Some(session) = table.get_session(dst_port) {
                        (session.target, session.proto_id)
                    } else {
                        (SocketAddr::new(IpAddr::V4(target_ip_v4), config.target_port), config.proto_id)
                    }
                };

                let mut mod_packet = raw_data.to_vec();
                let t_ip = match target_restore {
                    SocketAddr::V4(v4_addr) => v4_addr.ip().octets(),
                    _ => target_ip_v4.octets(),
                };

                let stripped_res = envelope_engine.apply_inbound_strip_v4(
                    &mut mod_packet,
                    v4,
                    t_ip,
                    target_restore.port(),
                    config.zero_csum,
                );

                if let Some((new_payload_len, _)) = stripped_res {
                    let _ = {
                        let mut table = session_table.lock().unwrap();
                        table.inc_inbound()
                    };

                    let stripped_slice = &mod_packet[parsed.payload_start()..parsed.payload_start() + new_payload_len];
                    let quic_packets = inspect_all_quic_packets(stripped_slice);

                    // 1. Chronological logging: first log all stripped packets in this datagram
                    let mut handshake_count = 0usize;
                    for (kind, desc) in &quic_packets {
                        if desc.contains("Initial") || desc.contains("Retry") || desc.contains("Handshake") {
                            println!(
                                "{} [HANDSHAKE] Relay -> Stripped [{}] -> Client :{} ({})",
                                chrono_prefix(), desc, dst_port, target_restore
                            );
                        } else if config.verbose {
                            println!(
                                "{} [INBOUND | STRIP 8B] Relay -> Stripped [{}] ({}B - 8B = {}B) -> Client :{}",
                                chrono_prefix(), desc, payload_len, new_payload_len, dst_port
                            );
                        }

                        if *kind == QuicPacketKind::LongHandshake {
                            handshake_count += 1;
                        }
                    }

                    // 2. Primary Trigger: Record Handshake packet(s), including any coalesced ones
                    let mut should_migrate = false;
                    if handshake_count > 0 && !relay_locked.load(Ordering::SeqCst) {
                        let mut table = session_table.lock().unwrap();
                        for _ in 0..handshake_count {
                            if table.record_inbound_handshake(dst_port) {
                                should_migrate = true;
                                break;
                            }
                        }
                    }

                    // 3. Immediately trigger Direct Migration upon 2nd server handshake confirmation
                    if should_migrate {
                        send_direct_lead_in(
                            &wd,
                            &packet.address,
                            v4.dst_ip,
                            dst_port,
                            target_restore,
                            _locked_proto,
                            &mut rng,
                            chrono_prefix,
                        );

                        println!(
                            "{} [MIGRATED -> DIRECT] Client :{} -> Direct Cloudflare {} (2nd Server Handshake Confirmed, Permanent Direct)",
                            chrono_prefix(), dst_port, target_restore
                        );

                        if !relay_locked.swap(true, Ordering::SeqCst) {
                            println!(
                                "{} [RELAY LOCKED] 1st session migrated. Relay immediately isolated. Press [ENTER] to re-arm...",
                                chrono_prefix()
                            );
                        }
                    }

                    let mut send_packet = WinDivertPacket {
                        address: packet.address,
                        data: std::borrow::Cow::Owned(mod_packet),
                    };
                    let _ = send_packet.recalculate_checksums(ChecksumFlags::new());
                    if let Err(e) = wd.send(&send_packet) {
                        eprintln!("{} [ERROR] Failed to send inbound packet: {:?}", chrono_prefix(), e);
                    }
                    continue;
                }
            } else {
                // Direct 1-RTT inbound from Cloudflare IPv4
                let src_ip = IpAddr::V4(Ipv4Addr::from(v4.src_ip));
                let is_direct_cf = (is_cloudflare_ip(src_ip) || src_ip == IpAddr::V4(target_ip_v4))
                    && (is_cloudflare_port(src_port) || src_port == config.target_port);

                if is_direct_cf {
                    let _ = {
                        let mut table = session_table.lock().unwrap();
                        table.inc_direct_inbound()
                    };
                    // In direct mode: zero log noise per packet, full wire-speed!
                    let _ = wd.send(&packet);
                    continue;
                }
            }
        }

        let _ = wd.send(&packet);
    }

    println!("[*] MASQUE engine shut down cleanly.");
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
