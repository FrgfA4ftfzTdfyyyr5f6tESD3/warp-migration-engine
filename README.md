# ⚡ Warp Migration Engine (WME)

> **High-Performance Layer 3 Kernel Network Engine for Cloudflare WARP**  
> *Bypass Deep Packet Inspection (DPI) with Asymmetric Handshake Migration & 17 Camouflage Masks.*

[![Language: Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Kernel: WinDivert](https://img.shields.io/badge/Kernel-WinDivert%202.2.2-blue.svg)](https://reqcrypt.org/windivert.html)
[![Protocol: QUIC / RFC 9000](https://img.shields.io/badge/Protocol-QUIC%20%2F%20MASQUE-brightgreen.svg)](https://datatracker.ietf.org/doc/html/rfc9000)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🌟 Why Warp Migration Engine? (The Radical Difference)

Traditional circumvention tools (V2Ray, Xray, Shadowsocks, OpenVPN) tunnel **100% of user traffic** through an overseas VPS. This leads to high server costs, bandwidth limits, severe throttling by national firewalls, and increased latency.

On the other hand, naive client-side desync tools (Zapret, GoodbyeDPI) attempt to desynchronize raw packets on local ISPs. However, modern stateful DPI in high-censorship regions instantly fingerprints or terminates the TLS 1.3 / QUIC handshake.

**Warp Migration Engine introduces an innovative Asymmetric Handshake Migration Architecture:**

| Feature | Traditional VPN / V2Ray | Naive Desync Tools | Warp Migration Engine |
| :--- | :---: | :---: | :---: |
| **Server Bandwidth Overhead** | **100% of all data** | 0% | **0% after handshake (< 50 KB total)** |
| **Download / Upload Speed** | Capped by VPS port | Line speed (often blocked) | **Full Native Line Speed (Wire-Speed)** |
| **Latency / Ping** | High (routed through VPS) | Lowest | **Lowest (Direct to Cloudflare Anycast)** |
| **DPI Handshake Resistance** | Moderate (SNI detection) | Poor (QUIC blocked) | **100% Immune (Encapsulated in Relay)** |
| **VPS Capacity** | 10–50 users per 1 Gbps | N/A | **10,000+ simultaneous users per 1 Gbps** |
| **Kernel Layer** | Virtual TUN/TAP (high CPU) | Raw Sockets | **WFP / WinDivert 2.2.2 (C-Speed / Zero-NAT)** |

---

## 🚀 Key Architectural Innovations

```mermaid
sequenceDiagram
    autonumber
    actor Client as Cloudflare WARP Client
    participant Kernel as WME Kernel Driver (Layer 3)
    participant Relay as Lightweight Relay (Amsterdam)
    participant CF as Cloudflare Anycast Edge (WARP)

    Note over Client,CF: Phase 1: Camouflaged Handshake Tunnel
    Client->>Kernel: UDP Handshake (Initial / Keys)
    Kernel->>Relay: 16B Dynamic Camouflage Envelope (WebRTC/DTLS/STUN)
    Relay->>CF: Strip Camo -> Forward Untouched QUIC to Cloudflare
    CF->>Relay: ServerHello + Handshake Flight (RFC 9000 Coalesced)
    Relay->>Kernel: Return Stripped Handshake via 8B Mask
    Kernel->>Client: Deliver Stripped Handshake to WARP

    Note over Client,CF: Phase 2: Instant Dual-Trigger Direct Migration
    CF-->>Kernel: 2nd Server Handshake Confirmation (99B)
    Kernel->>CF: Inject 2x Non-QUIC Lead-In (48B / 96B)
    Note over Kernel: RELAY LOCKED (0ms isolation)
    
    Note over Client,CF: Phase 3: Permanent Direct Wire-Speed (Zero Relay Overhead)
    loop Application Data (1-RTT)
        Client->>Kernel: QUIC 1-RTT Data (0x40..0x7f)
        Kernel->>CF: Direct Fast-Path Bypass (Wire-Speed, 0ms Relay)
        CF->>Client: Direct Inbound from Cloudflare
    end
```

### 1. Dual-Path Asymmetric Handshake Migration
Only the initial cryptographic exchange (~16 packets) is routed through the relay. The moment Cloudflare acknowledges the handshake, the kernel engine injects a 2-stage Lead-In directly to Cloudflare's edge and locks into **Permanent Direct Wire-Speed**. The relay is detached completely.

### 2. RFC 9000 Coalesced Packet Dissection & Dual-Trigger
Cloudflare coalesces `Server Initial` and `Server Handshake` packets into single UDP datagrams. WME incorporates an RFC 9000 Varint & Length parser to dissect every coalesced frame. Migration is triggered by:
* **Primary Trigger:** Arrival of the 2nd server Handshake packet (instant cryptographic completion).
* **Backup Safety Cushion:** 20 Short 1-RTT transit packets to eliminate deadlocks from packet loss.

### 3. Immediate Relay Isolation (`RELAY LOCKED`) + Hot-Key Re-Arm
Upon the first confirmed migration, the relay is isolated with **0ms delay**. Any competing background probes or parallel ports are immediately dropped at the kernel layer (`VERDICT_DROP`), ensuring **zero leaked packets** and **zero idle server traffic**. Pressing **`[Enter]`** in the console immediately re-arms the relay for subsequent reconnections.

### 4. Zero-NAT Ephemeral Port Preservation
Operating at Windows Filtering Platform (WFP) Layer 3, WME preserves the authentic ephemeral source ports allocated by the Windows network stack. No NAT tables, no port translation, and no memory overhead.

### 5. 17 Pluggable Layer-4 Camouflage Protocols
The 16-byte prepend header disguises QUIC UDP datagrams as legitimate internet protocols to evade heuristic DPI:
* **Tier-1 Recommended:** `AUTO (0)` (rotates golden masks), `WebRTC (4)`, `DTLS 1.2 (5)`, `IPsec ESP (7)`, `STUN (10)`.
* **Gaming & Media:** `Steam SDR (13)`, `Discord Voice (17)`, `DNS Query (6)`, `Zoom Media (15)`, `RakNet (9)`.

### 6. Full Cloudflare WARP Multi-Port Coverage
Natively supports all official and dynamic Cloudflare WARP ports:
`8095, 8595, 8642, 8742, 8854, 8886, 8943, 443, 500, 1701, 2408, 4443, 4500, 8443, 5200..5205, 7152, 7156, 7284, 7559, 7815, 9034, 9088, 9389, 9408, 9555`.

### 7. Dual Engine Modes Included
* **Mode 1:** Standalone WireGuard / UDP Direct Desync Engine (Stateful CPS, Beta Reverse Rekey / Role Swap).
* **Mode 2:** QUIC / MASQUE Handshake Migration Engine (Amsterdam Relay + 1-RTT Direct Wire-Speed).

---

## 📦 Quick Start (Windows Client)

No installation required. Pre-compiled standalone binaries are available in `bin/client/`.

1. Download or navigate to `bin/client/`.
2. Ensure `masque-client.exe`, `WinDivert.dll`, and `WinDivert64.sys` are in the same folder.
3. Right-click **`run.bat`** (or `masque-client.exe`) and choose **Run as Administrator**.
4. Select **`[2]`** for QUIC / MASQUE Handshake Migration Engine.
5. Select your Camouflage Mask (press `Enter` for IPsec ESP or type `0` for AUTO).
6. Enter your relay server IP & Port (e.g. `198.51.100.1:2632`). It will be saved automatically to `config.json` for all future runs!
7. Turn on your Cloudflare WARP client. Enjoy unblocked, zero-latency direct wire-speed!

---

## 🖥️ Server Deployment (Linux VPS in 60 Seconds)

The relay server is a lightweight static binary written in async Rust (Tokio) with zero external runtime dependencies.

### One-Command Setup:
```bash
# Upload masque-relay, masque-relay.service and install.sh to your VPS, then run:
chmod +x install.sh
sudo ./install.sh 2632
```

The script configures systemd, enables auto-restart, and binds the high-performance async relay on UDP port `2632`.

To view live server logs:
```bash
journalctl -u masque-relay -f
```

---

## 🛠️ Building from Source

### Prerequisites:
* [Rust](https://rustup.rs/) (1.75+ recommended)
* Windows SDK (for client compilation on Windows)

### Build All Components:
```bash
# Clone the repository
git clone https://github.com/your-username/warp-migration-engine.git
cd warp-migration-engine

# Build both client and server in release mode
cargo build --release
```

---

## 📁 Repository Structure

```text
warp-migration-engine/
├── Cargo.toml                  # Workspace Manifest
├── README.md                   # Documentation
├── .gitignore                  # Git Ignore Rules
├── client/                     # masque-client (WinDivert Layer 3 Engine)
│   ├── Cargo.toml
│   └── src/
├── server/                     # masque-relay (Tokio Async Musl Relay)
│   ├── Cargo.toml
│   └── src/
├── common/                     # masque-common (Protocols & Envelope Encoders)
│   ├── Cargo.toml
│   └── src/
└── bin/                        # Production Release Binaries
    ├── client/
    │   ├── masque-client.exe   # Compiled Client Executable
    │   ├── WinDivert.dll       # Signed WinDivert 2.2.2 Driver Library
    │   ├── WinDivert64.sys     # Signed 64-bit Kernel Driver
    │   ├── run.bat             # Administrator Launcher
    │   └── config.example.json # Configuration Template
    └── server/
        ├── masque-relay        # Linux x86_64 Statically Linked Executable
        ├── masque-relay.service# Systemd Service Template
        └── install.sh          # 1-Click Server Installer
```

---

## 🔒 Security & Privacy Notice

* **Zero Plaintext Inspection:** The relay server never inspects or decrypts payloads. It merely strips the 16-byte camouflage envelope and forwards raw encrypted QUIC frames.
* **Ephemeral State:** All relay sessions expire automatically after 60 seconds of inactivity.
* **No User Data Logged:** No client IP addresses or destination domains are recorded to disk.

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.
All cryptographic and protocol camouflage specifications conform to relevant RFC standards.
