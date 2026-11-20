use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use masque_common::{build_inbound_camo, get_protocol_by_id, INBOUND_STRIP_LEN};
use tokio::{net::UdpSocket, sync::Mutex};

use crate::server::DualStackListener;

pub const SESSION_TIMEOUT_SECS: u64 = 60;
pub type OutboundMsg = (SocketAddr, u8, Vec<u8>);

#[derive(Clone)]
pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<SocketAddr, tokio::sync::mpsc::Sender<OutboundMsg>>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn get_sender(&self, client_addr: &SocketAddr) -> Option<tokio::sync::mpsc::Sender<OutboundMsg>> {
        let map = self.sessions.lock().await;
        map.get(client_addr).cloned()
    }

    pub async fn register(
        &self,
        client_addr: SocketAddr,
        initial_proto_id: u8,
        listener: Arc<DualStackListener>,
    ) -> tokio::sync::mpsc::Sender<OutboundMsg> {
        let (tx, rx) = tokio::sync::mpsc::channel::<OutboundMsg>(1024);
        {
            let mut map = self.sessions.lock().await;
            map.insert(client_addr, tx.clone());
        }

        let sessions_clone = self.sessions.clone();
        tokio::spawn(async move {
            Self::run_session_worker(client_addr, initial_proto_id, listener, rx).await;
            let mut map = sessions_clone.lock().await;
            map.remove(&client_addr);
        });

        tx
    }

    async fn run_session_worker(
        client_addr: SocketAddr,
        initial_proto_id: u8,
        listener: Arc<DualStackListener>,
        mut rx: tokio::sync::mpsc::Receiver<OutboundMsg>,
    ) {
        // Dual-stack upstream sockets: IPv4 and IPv6
        let upstream_v4 = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[ERROR] Upstream IPv4 bind failed for {}: {}", client_addr, e);
                return;
            }
        };

        let upstream_v6 = match UdpSocket::bind("[::]:0").await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("[WARN] Upstream IPv6 bind failed for {} (IPv4 only upstream): {}", client_addr, e);
                None
            }
        };

        let mut up_v4_rx_buf = [0u8; 65535];
        let mut up_v6_rx_buf = [0u8; 65535];
        let mut resp_buf = [0u8; 65535];
        let mut in_count: u64 = 0;
        let mut active_proto_id = initial_proto_id;

        loop {
            tokio::select! {
                // 1. Packets from client to target
                msg = rx.recv() => {
                    match msg {
                        Some((target, proto_id, data)) => {
                            active_proto_id = proto_id;
                            match target {
                                SocketAddr::V4(_) => {
                                    if let Err(e) = upstream_v4.send_to(&data, target).await {
                                        eprintln!("[WARN] Upstream IPv4 send_to error for {}: {}", client_addr, e);
                                    }
                                }
                                SocketAddr::V6(_) => {
                                    if let Some(ref sock_v6) = upstream_v6 {
                                        if let Err(e) = sock_v6.send_to(&data, target).await {
                                            eprintln!("[WARN] Upstream IPv6 send_to error for {}: {}", client_addr, e);
                                        }
                                    } else {
                                        eprintln!("[ERROR] IPv6 target requested but IPv6 upstream socket unavailable: {}", target);
                                    }
                                }
                            }
                        }
                        None => break, // Channel closed
                    }
                }

                // 2. Inbound packets from IPv4 target to client
                res_v4 = upstream_v4.recv_from(&mut up_v4_rx_buf) => {
                    match res_v4 {
                        Ok((up_len, target_src)) => {
                            if up_len > 0 {
                                in_count += 1;
                                let camo_hdr = build_inbound_camo(active_proto_id, in_count as u32);
                                resp_buf[0..INBOUND_STRIP_LEN].copy_from_slice(&camo_hdr);
                                let total_len = INBOUND_STRIP_LEN + up_len;
                                if total_len <= resp_buf.len() {
                                    resp_buf[INBOUND_STRIP_LEN..total_len].copy_from_slice(&up_v4_rx_buf[..up_len]);
                                    if let Err(e) = listener.send_to(&resp_buf[..total_len], client_addr).await {
                                        eprintln!("[WARN] Listener send_to error for {}: {}", client_addr, e);
                                    }

                                    if in_count <= 5 || in_count % 100 == 0 {
                                        let proto = get_protocol_by_id(active_proto_id);
                                        println!(
                                            "[RELAY INBOUND #{}] IPv4 Target {} -> Return [{}] -> Client {} ({} B orig + 8B Camo = {} B)",
                                            in_count, target_src, proto.key, client_addr, up_len, total_len
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[WARN] Upstream IPv4 recv_from error for {}: {}", client_addr, e);
                        }
                    }
                }

                // 3. Inbound packets from IPv6 target to client
                res_v6 = async {
                    if let Some(ref sock_v6) = upstream_v6 {
                        sock_v6.recv_from(&mut up_v6_rx_buf).await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    match res_v6 {
                        Ok((up_len, target_src)) => {
                            if up_len > 0 {
                                in_count += 1;
                                let camo_hdr = build_inbound_camo(active_proto_id, in_count as u32);
                                resp_buf[0..INBOUND_STRIP_LEN].copy_from_slice(&camo_hdr);
                                let total_len = INBOUND_STRIP_LEN + up_len;
                                if total_len <= resp_buf.len() {
                                    resp_buf[INBOUND_STRIP_LEN..total_len].copy_from_slice(&up_v6_rx_buf[..up_len]);
                                    if let Err(e) = listener.send_to(&resp_buf[..total_len], client_addr).await {
                                        eprintln!("[WARN] Listener send_to error for {}: {}", client_addr, e);
                                    }

                                    if in_count <= 5 || in_count % 100 == 0 {
                                        let proto = get_protocol_by_id(active_proto_id);
                                        println!(
                                            "[RELAY INBOUND #{}] IPv6 Target {} -> Return [{}] -> Client {} ({} B orig + 8B Camo = {} B)",
                                            in_count, target_src, proto.key, client_addr, up_len, total_len
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[WARN] Upstream IPv6 recv_from error for {}: {}", client_addr, e);
                        }
                    }
                }

                // 4. Inactivity timeout (60 seconds)
                _ = tokio::time::sleep(Duration::from_secs(SESSION_TIMEOUT_SECS)) => {
                    println!("[SESSION TIMEOUT] Inactive client {} purged (Closed dual-stack upstream)", client_addr);
                    break;
                }
            }
        }
    }
}
