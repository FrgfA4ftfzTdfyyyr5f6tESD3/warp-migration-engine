use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    Tried,
    Established,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReverseRekeyStatus {
    Init,
    Suppressing,
    ServerInitiated,
    Done,
    Fallback,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct FlowEntry {
    pub flow_key: String,
    pub state: FlowState,
    pub attempt: u32,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub established_time: Option<Instant>,
    pub hs_id: u64,

    // Reverse Rekey fields
    pub rev_status: ReverseRekeyStatus,
    pub rev_first_suppressed: Option<Instant>,
    pub rev_suppress_count: u32,
    pub rev_c3_warned: bool,
}

pub struct FlowTable {
    entries: HashMap<String, FlowEntry>,
}

impl FlowTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Format symmetric normalized flow key for both IPv4 and IPv6
    pub fn get_flow_key(src: SocketAddr, dst: SocketAddr, is_inbound: bool) -> String {
        if is_inbound {
            format!("{}->{}", dst, src)
        } else {
            format!("{}->{}", src, dst)
        }
    }

    pub fn get_state(&mut self, key: &str) -> Option<FlowState> {
        let now = Instant::now();
        if let Some(entry) = self.entries.get_mut(key) {
            if entry.state == FlowState::Established {
                if now.duration_since(entry.last_seen) < Duration::from_secs(300) {
                    entry.last_seen = now;
                    return Some(FlowState::Established);
                } else {
                    return None;
                }
            }
            return Some(entry.state);
        }
        None
    }

    pub fn get_entry_mut(&mut self, key: &str) -> Option<&mut FlowEntry> {
        self.entries.get_mut(key)
    }

    pub fn register_attempt(&mut self, key: &str, hs_id: u64) {
        self.cleanup();
        let now = Instant::now();
        self.entries.insert(
            key.to_string(),
            FlowEntry {
                flow_key: key.to_string(),
                state: FlowState::Tried,
                attempt: 1,
                first_seen: now,
                last_seen: now,
                established_time: None,
                hs_id,
                rev_status: ReverseRekeyStatus::Init,
                rev_first_suppressed: None,
                rev_suppress_count: 0,
                rev_c3_warned: false,
            },
        );
    }

    pub fn set_established(&mut self, key: &str) {
        let now = Instant::now();
        if let Some(entry) = self.entries.get_mut(key) {
            entry.state = FlowState::Established;
            entry.established_time = Some(now);
            entry.last_seen = now;
        } else {
            self.entries.insert(
                key.to_string(),
                FlowEntry {
                    flow_key: key.to_string(),
                    state: FlowState::Established,
                    attempt: 1,
                    first_seen: now,
                    last_seen: now,
                    established_time: Some(now),
                    hs_id: 0,
                    rev_status: ReverseRekeyStatus::Init,
                    rev_first_suppressed: None,
                    rev_suppress_count: 0,
                    rev_c3_warned: false,
                },
            );
        }
    }

    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let tried_ttl = Duration::from_secs(30);
        let est_ttl = Duration::from_secs(360);
        self.entries.retain(|_, v| match v.state {
            FlowState::Tried => now.duration_since(v.last_seen) < tried_ttl,
            FlowState::Established => now.duration_since(v.last_seen) < est_ttl,
        });
    }
}
