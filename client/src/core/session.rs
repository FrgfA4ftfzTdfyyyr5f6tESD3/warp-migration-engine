use std::{
    collections::HashMap,
    net::SocketAddr,
    time::Instant,
};

use crate::protocols::quic::migration::QuicPacketKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationAction {
    /// Initial handshake or delayed 1-RTT: Prepend envelope, route to Amsterdam Relay.
    SendRelayInitial { short_pkn: u32 },
    /// 16th Short 1-RTT packet reached: Trigger migration (2x lead-in + send direct).
    TriggerInitialMigration { short_pkn: u32 },
    /// Session is permanently locked in Direct mode to Cloudflare.
    SendDirect,
}

#[derive(Debug, Clone)]
pub struct ClientSession {
    pub target: SocketAddr,
    pub proto_id: u8,
    pub migrated: bool,
    pub short_1rtt_count: u32,
    pub server_handshake_count: u8,
    pub warmup_done: bool,
    pub last_seen: Instant,
}

pub struct SessionTable {
    sessions: HashMap<u16, ClientSession>,
    pub outbound_count: u64,
    pub inbound_count: u64,
    #[allow(dead_code)]
    pub direct_outbound_count: u64,
    #[allow(dead_code)]
    pub direct_inbound_count: u64,
}

impl SessionTable {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            outbound_count: 0,
            inbound_count: 0,
            direct_outbound_count: 0,
            direct_inbound_count: 0,
        }
    }

    /// Retrieve or register a client session with Per-Session Protocol Lock
    pub fn get_or_create(
        &mut self,
        client_port: u16,
        target: SocketAddr,
        default_proto: u8,
    ) -> (u8, bool) {
        let now = Instant::now();
        let session = self.sessions.entry(client_port).or_insert_with(|| ClientSession {
            target,
            proto_id: default_proto,
            migrated: false,
            short_1rtt_count: 0,
            server_handshake_count: 0,
            warmup_done: false,
            last_seen: now,
        });

        session.last_seen = now;
        session.target = target;
        (session.proto_id, session.migrated)
    }

    pub fn is_warmup_done(&self, client_port: u16) -> bool {
        self.sessions
            .get(&client_port)
            .map(|s| s.warmup_done)
            .unwrap_or(false)
    }

    pub fn mark_warmup_done(&mut self, client_port: u16) {
        if let Some(session) = self.sessions.get_mut(&client_port) {
            session.warmup_done = true;
        }
    }

    /// Inbound Handshake Marker Trigger:
    /// In Cloudflare QUIC handshakes, Cloudflare sends exactly 2 Handshake packets:
    /// - 1st: TLS ServerHello, EncryptedExtensions, Certificates, Finished (~980B)
    /// - 2nd: Handshake confirmation (~99B) acknowledging client's TLS Finished
    /// When the 2nd server handshake packet arrives, the QUIC cryptographic handshake is 100% complete.
    /// This immediately triggers Direct Migration without waiting for arbitrary packet counts!
    pub fn record_inbound_handshake(&mut self, client_port: u16) -> bool {
        if let Some(session) = self.sessions.get_mut(&client_port) {
            if !session.migrated {
                session.server_handshake_count += 1;
                if session.server_handshake_count >= 2 {
                    session.migrated = true;
                    return true;
                }
            }
        }
        false
    }

    /// Pure One-Way Handshake Migration State Machine:
    /// - Primary Trigger: Inbound 2nd Handshake packet from Cloudflare marks session migrated.
    /// - Fallback Trigger: 20 Short 1-RTT packets through Relay acts as a safety cushion.
    /// - Handshake (Initial, Handshake, Other) always routes through Amsterdam Relay.
    /// - Once migrated, session is permanently locked in Direct Wire-Speed mode (Zero Relay Fallback / Zero Loop).
    /// - Stays Direct until client explicitly disconnects/reconnects (new LongInitial).
    pub fn handle_outbound_migration(
        &mut self,
        client_port: u16,
        quic_kind: QuicPacketKind,
    ) -> MigrationAction {
        let session = match self.sessions.get_mut(&client_port) {
            Some(s) => s,
            None => return MigrationAction::SendRelayInitial { short_pkn: 0 },
        };

        // 1. Initial packets reset session state (client reconnect / port reuse) and go via Relay
        if quic_kind == QuicPacketKind::LongInitial {
            session.migrated = false;
            session.short_1rtt_count = 0;
            session.server_handshake_count = 0;
            return MigrationAction::SendRelayInitial { short_pkn: 0 };
        }

        // 2. If already migrated, session is permanently locked in Direct Wire-Speed mode.
        // Never switches back to relay under any circumstances!
        if session.migrated {
            return MigrationAction::SendDirect;
        }

        // 3. Handshake packets always go via Relay
        if quic_kind == QuicPacketKind::LongHandshake || quic_kind == QuicPacketKind::LongOther {
            return MigrationAction::SendRelayInitial { short_pkn: session.short_1rtt_count };
        }

        // 4. Initial 1-RTT phase (before migration):
        // Safety cushion: up to 20 packets through Amsterdam Relay if 2nd server handshake was coalesced.
        if quic_kind == QuicPacketKind::Short1Rtt {
            session.short_1rtt_count += 1;
            let count = session.short_1rtt_count;

            if count >= 20 {
                session.migrated = true;
                return MigrationAction::TriggerInitialMigration { short_pkn: count };
            } else {
                return MigrationAction::SendRelayInitial { short_pkn: count };
            }
        }

        // Non-QUIC before migration: route via Relay
        MigrationAction::SendRelayInitial { short_pkn: session.short_1rtt_count }
    }

    pub fn get_session(&self, client_port: u16) -> Option<&ClientSession> {
        self.sessions.get(&client_port)
    }

    #[allow(dead_code)]
    pub fn get_session_mut(&mut self, client_port: u16) -> Option<&mut ClientSession> {
        self.sessions.get_mut(&client_port)
    }

    #[allow(dead_code)]
    pub fn is_migrated(&self, client_port: u16) -> bool {
        self.sessions
            .get(&client_port)
            .map(|s| s.migrated)
            .unwrap_or(false)
    }

    pub fn inc_outbound(&mut self) -> u64 {
        self.outbound_count += 1;
        self.outbound_count
    }

    pub fn inc_inbound(&mut self) -> u64 {
        self.inbound_count += 1;
        self.inbound_count
    }

    #[allow(dead_code)]
    pub fn inc_direct_outbound(&mut self) -> u64 {
        self.direct_outbound_count += 1;
        self.direct_outbound_count
    }

    #[allow(dead_code)]
    pub fn inc_direct_inbound(&mut self) -> u64 {
        self.direct_inbound_count += 1;
        self.direct_inbound_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn dummy_target() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(162, 159, 198, 2)), 8095)
    }

    #[test]
    fn test_inbound_2nd_handshake_triggers_migration() {
        let mut table = SessionTable::new();
        let port = 50001;
        let target = dummy_target();
        table.get_or_create(port, target, 7);

        // 1st Server Handshake arrived from Cloudflare
        let trig1 = table.record_inbound_handshake(port);
        assert!(!trig1);
        assert!(!table.is_migrated(port));

        // Client sends 4 short 1-RTT packets via Relay
        for i in 1..=4 {
            let action = table.handle_outbound_migration(port, QuicPacketKind::Short1Rtt);
            assert_eq!(action, MigrationAction::SendRelayInitial { short_pkn: i });
        }

        // 2nd Server Handshake arrived from Cloudflare (Handshake confirmed!)
        let trig2 = table.record_inbound_handshake(port);
        assert!(trig2);
        assert!(table.is_migrated(port));

        // Subsequent outbound packets are immediately SendDirect forever!
        for _ in 5..=50 {
            let action = table.handle_outbound_migration(port, QuicPacketKind::Short1Rtt);
            assert_eq!(action, MigrationAction::SendDirect);
        }
    }

    #[test]
    fn test_backup_20_packet_handshake_to_permanent_direct() {
        let mut table = SessionTable::new();
        let port = 50002;
        let target = dummy_target();
        table.get_or_create(port, target, 7);

        // Packets 1..=19 -> SendRelayInitial
        for i in 1..=19 {
            let action = table.handle_outbound_migration(port, QuicPacketKind::Short1Rtt);
            assert_eq!(action, MigrationAction::SendRelayInitial { short_pkn: i });
        }

        // Packet 20 -> TriggerInitialMigration (Migrated = true!)
        let action = table.handle_outbound_migration(port, QuicPacketKind::Short1Rtt);
        assert_eq!(action, MigrationAction::TriggerInitialMigration { short_pkn: 20 });

        // Packets 21..100 -> Strictly SendDirect forever (Zero Relay Fallback!)
        for _ in 21..=100 {
            let action = table.handle_outbound_migration(port, QuicPacketKind::Short1Rtt);
            assert_eq!(action, MigrationAction::SendDirect);
        }

        let session = table.get_session(port).unwrap();
        assert!(session.migrated);
    }

    #[test]
    fn test_long_initial_resets_session() {
        let mut table = SessionTable::new();
        let port = 50003;
        let target = dummy_target();
        table.get_or_create(port, target, 7);

        for _ in 0..20 {
            table.handle_outbound_migration(port, QuicPacketKind::Short1Rtt);
        }
        assert!(table.is_migrated(port));

        // Reconnect / new handshake arrives -> resets session
        let action = table.handle_outbound_migration(port, QuicPacketKind::LongInitial);
        assert_eq!(action, MigrationAction::SendRelayInitial { short_pkn: 0 });

        let session = table.get_session(port).unwrap();
        assert!(!session.migrated);
        assert_eq!(session.short_1rtt_count, 0);
        assert_eq!(session.server_handshake_count, 0);
    }
}
