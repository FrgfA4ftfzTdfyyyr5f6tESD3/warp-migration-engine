mod core;
mod masque;
mod protocols;
mod wireguard;

use std::{
    io::{self, Write},
    sync::{
        atomic::AtomicBool,
        Arc,
    },
};

use clap::Parser;
use masque::engine::{run_masque_engine, MasqueConfig};
use serde::{Deserialize, Serialize};
use wireguard::engine::{run_wireguard_engine, WireGuardConfig};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct AppConfig {
    relay_ip: Option<String>,
    relay_port: Option<u16>,
}

const CONFIG_FILE: &str = "config.json";

fn load_config() -> AppConfig {
    if let Ok(content) = std::fs::read_to_string(CONFIG_FILE) {
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        AppConfig::default()
    }
}

fn save_config(cfg: &AppConfig) {
    if let Ok(json) = serde_json::to_string_pretty(cfg) {
        let _ = std::fs::write(CONFIG_FILE, json);
    }
}

#[derive(Parser, Debug, Clone)]
#[command(name = "masque-client")]
#[command(
    about = "Unified Kernel Layer 3 Network Engine (WireGuard Direct Desync & QUIC / MASQUE Relay)",
    version = "4.5.0"
)]
struct Args {
    /// Engine Mode: "wg" / "wireguard" for Direct Desync, "masque" / "quic" for Relay Handshake Migration
    #[arg(short = 'm', long)]
    mode: Option<String>,

    /// Camouflage Protocol ID (0..17, default: 0 for AUTO)
    #[arg(short = 'p', long)]
    proto: Option<u8>,

    /// Enable Beta Reverse Rekey (Noise_IK Role Swap) for WireGuard Mode
    #[arg(long)]
    reverse_rekey: bool,

    /// Default Target Cloudflare IP address (MASQUE Mode)
    #[arg(long, default_value = "162.159.198.2")]
    target_ip: String,

    /// Default Target Cloudflare UDP Port (MASQUE Mode)
    #[arg(long, default_value = "8095")]
    target_port: u16,

    /// External Relay IP address (MASQUE Mode)
    #[arg(long)]
    relay_ip: Option<String>,

    /// External Relay UDP Port (MASQUE Mode)
    #[arg(long)]
    relay_port: Option<u16>,

    /// Force zero UDP checksum on inbound packets (MASQUE Mode)
    #[arg(long)]
    zero_csum: bool,

    /// Disable automatic QUIC Connection Migration on 1-RTT phase (MASQUE Mode)
    #[arg(long)]
    no_migration: bool,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

fn print_engine_menu() {
    println!("=========================================================================");
    println!("  Unified Kernel Layer 3 Network Engine (Rust Native v4.2)");
    println!("=========================================================================");
    println!("  Select Engine Architecture Mode:");
    println!("-------------------------------------------------------------------------");
    println!("  [1] WireGuard / UDP Direct Desync Engine (Zero-NAT + Cover Envelope)");
    println!("      * Direct standalone desync without external relay.");
    println!("      * Stateful CPS Framing (I1 Signature + I2 Dynamic Timestamps).");
    println!("      * Authentic Client Ephemeral Port Preservation (Zero-NAT).");
    println!("      * Dead-Port Rapid Rotation (VERDICT_DROP on duplicates).");
    println!("      * Beta Noise_IK Reverse Rekey & Role Swap Engine.");
    println!("      * Compatible with Windscribe, WARP WireGuard, Official WireGuard.");
    println!();
    println!("  [2] QUIC / MASQUE Handshake Migration Engine (Amsterdam Relay + 1-RTT)");
    println!("      * Handshake tunneled via Amsterdam Relay with 1-RTT Direct Migration.");
    println!("      * Dual-Stack Dynamic Envelope (16B IPv4 / 28B IPv6) + Untouched Payload.");
    println!("      * Zero server overhead after handshake completion.");
    println!("=========================================================================");
}

fn print_protocol_menu() {
    println!("=========================================================================");
    println!("  Select Camouflage Protocol [0..17]:");
    println!("-------------------------------------------------------------------------");
    println!("  [0]  AUTO (Auto-rotate across 6 Golden Protocols) [RECOMMENDED]");
    println!("  [1]  Classic Random Junk (AmneziaWG)");
    println!("  [2]  QUIC v1 / HTTP/3 Short Header (0x43)");
    println!("  [3]  QUIC v2 / RFC 9369 Initial Header (0xD0)");
    println!("  [4]  WebRTC / SRTP Audio Video Stream (RTP v2)");
    println!("  [5]  DTLS 1.2 Application Data Record");
    println!("  [6]  DNS Query (Standard RFC 1035)");
    println!("  [7]  IPsec NAT-T ESP (Enterprise Tunnel)");
    println!("  [8]  uTP BitTorrent (State Data Packet)");
    println!("  [9]  RakNet Gaming (Minecraft Bedrock)");
    println!("  [10] STUN / ICE Binding Request (RFC 5389)");
    println!("  [11] TURN ChannelData (Relayed Media)");
    println!("  [12] Steam / Valve Source Query (CS:GO)");
    println!("  [13] Steam Datagram Relay (CS2 SDR Transport)");
    println!("  [14] Riot Games (Valorant / LoL Media)");
    println!("  [15] Zoom Media Stream (RTP Video / Voice)");
    println!("  [16] Microsoft RDP over UDP (MS-RDPEUDP)");
    println!("  [17] Discord Voice & Media (Opus Audio)");
    println!("=========================================================================");
}

fn prompt_line(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or_default();
    input.trim().to_string()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // 1. Resolve Engine Mode
    let chosen_mode = if let Some(ref m) = args.mode {
        match m.to_lowercase().as_str() {
            "wg" | "wireguard" | "1" => 1,
            "masque" | "quic" | "2" => 2,
            _ => 1,
        }
    } else {
        print_engine_menu();
        let ans = prompt_line("Select Engine Mode [Press 1 for WireGuard, 2 for QUIC MASQUE (Default: 1)]: ");
        if ans == "2" {
            2
        } else {
            1
        }
    };

    // 2. Resolve Protocol
    let proto_id = if let Some(p) = args.proto {
        p
    } else {
        print_protocol_menu();
        let default_choice = if chosen_mode == 1 { "0" } else { "7" };
        let ans = prompt_line(&format!(
            "Select Camouflage Protocol [Press Enter for {}]: ",
            if default_choice == "0" { "AUTO (0)" } else { "IPsec ESP (7)" }
        ));
        if ans.is_empty() {
            if default_choice == "0" { 0 } else { 7 }
        } else {
            ans.parse::<u8>().unwrap_or(0)
        }
    };

    let running = Arc::new(AtomicBool::new(true));

    if chosen_mode == 1 {
        // WireGuard Mode
        let rev_rekey = if args.reverse_rekey {
            true
        } else if args.mode.is_none() {
            let ans = prompt_line("Enable Beta Reverse-Handshake (Role Swap Engine)? [y/N (Default: N)]: ");
            ans.eq_ignore_ascii_case("y") || ans.eq_ignore_ascii_case("yes")
        } else {
            false
        };

        let wg_config = WireGuardConfig {
            proto_id,
            reverse_rekey: rev_rekey,
            verbose: args.verbose,
        };
        run_wireguard_engine(wg_config, running)
    } else {
        // QUIC / MASQUE Mode (Handshake via External Relay -> 1-RTT Direct Wire-Speed)
        let (relay_ip, relay_port) = if let (Some(ref ip), Some(p)) = (&args.relay_ip, args.relay_port) {
            (ip.clone(), p)
        } else {
            let mut cfg = load_config();
            let current_ip = args.relay_ip.clone().or_else(|| cfg.relay_ip.clone());
            let current_port = args.relay_port.or(cfg.relay_port).unwrap_or(2632);

            let final_addr = if let Some(ref ip) = current_ip {
                println!("=========================================================================");
                println!("  Relay Server Configuration:");
                println!("-------------------------------------------------------------------------");
                let ans = prompt_line(&format!(
                    "  Use saved relay [{}:{}]? (Press Enter to keep, or enter new IP:PORT): ",
                    ip, current_port
                ));
                if ans.is_empty() {
                    format!("{}:{}", ip, current_port)
                } else {
                    ans
                }
            } else {
                println!("=========================================================================");
                println!("  Relay Server Configuration (First Run):");
                println!("-------------------------------------------------------------------------");
                println!("  Enter your Relay Server address (IP:Port).");
                println!("  (This will be saved to config.json and can be edited anytime)");
                let mut ans = prompt_line("  Relay Server [e.g. 198.51.100.1:2632]: ");
                while ans.is_empty() {
                    ans = prompt_line("  [!] Please enter a valid Relay Server [IP:PORT]: ");
                }
                ans
            };

            let (ip, port) = if let Some(idx) = final_addr.rfind(':') {
                let (ip_part, port_part) = final_addr.split_at(idx);
                let p = port_part[1..].parse::<u16>().unwrap_or(2632);
                (ip_part.trim().to_string(), p)
            } else {
                (final_addr.trim().to_string(), 2632)
            };

            cfg.relay_ip = Some(ip.clone());
            cfg.relay_port = Some(port);
            save_config(&cfg);
            println!("  [*] Saved relay configuration to {}", CONFIG_FILE);
            println!("=========================================================================\n");

            (ip, port)
        };

        let masque_config = MasqueConfig {
            proto_id,
            target_ip: args.target_ip,
            target_port: args.target_port,
            relay_ip,
            relay_port,
            zero_csum: args.zero_csum,
            verbose: args.verbose,
        };
        run_masque_engine(masque_config, running)
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use windivert::prelude::*;

    fn check_filter(filter: &str) -> Result<(), (String, u32)> {
        let c_filter = CString::new(filter).unwrap();
        let mut err_str: *const std::os::raw::c_char = std::ptr::null();
        let mut err_pos: u32 = 0;
        let ok = unsafe {
            WinDivertHelperCompileFilter(
                c_filter.as_ptr(),
                WinDivertLayer::Network,
                std::ptr::null_mut(),
                0,
                &mut err_str,
                &mut err_pos,
            )
        };
        if ok.as_bool() {
            Ok(())
        } else {
            let msg = if !err_str.is_null() {
                unsafe { std::ffi::CStr::from_ptr(err_str).to_string_lossy().into_owned() }
            } else {
                "Unknown syntax error".to_string()
            };
            Err((msg, err_pos))
        }
    }

    #[test]
    fn test_wireguard_filter() {
        let filter = "(udp.PayloadLength == 148 and udp.Payload32[0] == 0x01000000) or (udp.PayloadLength == 92 and udp.Payload32[0] == 0x02000000)";
        match check_filter(filter) {
            Ok(_) => println!("WireGuard filter compiled successfully!"),
            Err((err, pos)) => panic!("WireGuard filter failed at {}: {}", pos, err),
        }
    }

    #[test]
    fn test_masque_ipv4_filter() {
        use std::net::Ipv4Addr;
        use std::str::FromStr;
        use crate::masque::filter::build_masque_filter;

        let target_ip = Ipv4Addr::from_str("162.159.198.2").unwrap();
        let target_port = 8095;
        let relay_ip_v4 = Ipv4Addr::from_str("172.99.188.64").unwrap();
        let relay_port = 2632;

        let filter = build_masque_filter(target_ip, target_port, relay_ip_v4, relay_port);
        println!("Generated filter:\n{}", filter);

        match check_filter(&filter) {
            Ok(_) => println!("MASQUE IPv4 filter compiled successfully!"),
            Err((err, pos)) => panic!("MASQUE filter failed at {}: {}", pos, err),
        }
    }
}

