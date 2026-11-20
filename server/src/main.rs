mod server;
mod session;

use std::env;
use server::RelayServer;
use session::SESSION_TIMEOUT_SECS;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let port: u16 = if args.len() > 1 {
        args[1].parse().unwrap_or(2632)
    } else {
        2632
    };

    println!("=========================================================================");
    println!("  masque-relay v4.3 (Rust Tokio Dual-Stack IPv4/IPv6 Modular Relay)");
    println!("=========================================================================");
    println!("  Envelope Format    : Dynamic Length (16B IPv4 / 28B IPv6) + Untouched Payload");
    println!("  Return Camouflage  : 8 Bytes Authentic Dynamic Matching Camo Header");
    println!("  Dual-Stack Upstream: Direct Native IPv4 & IPv6 Cloudflare Fast-Path");
    println!("  Session TTL        : {} seconds inactivity auto-purge", SESSION_TIMEOUT_SECS);
    println!("=========================================================================");

    let server = RelayServer::bind(port)?;
    println!(
        "  Relay engine successfully initialized on port {} (IPv6 Dual-Stack Active: {}).",
        server.port(),
        server.has_ipv6()
    );
    println!("=========================================================================");

    server.run().await
}
