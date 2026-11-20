use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use masque_common::{get_protocol_by_id, OutboundEnvelope};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::session::SessionManager;

pub struct DualStackListener {
    pub sock_v4: Arc<UdpSocket>,
    pub sock_v6: Option<Arc<UdpSocket>>,
}

impl DualStackListener {
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        match target {
            SocketAddr::V4(_) => self.sock_v4.send_to(buf, target).await,
            SocketAddr::V6(_) => {
                if let Some(ref sock_v6) = self.sock_v6 {
                    sock_v6.send_to(buf, target).await
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "IPv6 listener not available",
                    ))
                }
            }
        }
    }
}

pub struct RelayServer {
    listener: Arc<DualStackListener>,
    sessions: SessionManager,
    port: u16,
}

impl RelayServer {
    pub fn bind(port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let v4_socket = Self::create_v4_socket(port)?;
        println!("  [IPv4] Listening on 0.0.0.0:{}", port);

        let v6_socket = match Self::create_v6_socket(port) {
            Ok(s) => {
                println!("  [IPv6] Listening on [::]:{} (Dual-Stack IPV6_V6ONLY)", port);
                Some(Arc::new(s))
            }
            Err(e) => {
                eprintln!("  [IPv6 WARN] Failed to bind [::]:{}: {} (IPv4 only mode)", port, e);
                None
            }
        };

        let listener = Arc::new(DualStackListener {
            sock_v4: Arc::new(v4_socket),
            sock_v6: v6_socket,
        });

        Ok(Self {
            listener,
            sessions: SessionManager::new(),
            port,
        })
    }

    fn create_v4_socket(port: u16) -> Result<UdpSocket, std::io::Error> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        socket.bind(&addr.into())?;
        let std_sock: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(std_sock)
    }

    fn create_v6_socket(port: u16) -> Result<UdpSocket, std::io::Error> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(true)?;
        socket.set_nonblocking(true)?;
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
        socket.bind(&addr.into())?;
        let std_sock: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(std_sock)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn has_ipv6(&self) -> bool {
        self.listener.sock_v6.is_some()
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut rx_v4_buf = [0u8; 65535];
        let mut rx_v6_buf = [0u8; 65535];
        let mut pkt_count: u64 = 0;

        let sock_v4 = self.listener.sock_v4.clone();
        let sock_v6 = self.listener.sock_v6.clone();

        loop {
            let (len, client_addr) = tokio::select! {
                res_v4 = sock_v4.recv_from(&mut rx_v4_buf) => {
                    match res_v4 {
                        Ok((len, addr)) => (len, addr, false),
                        Err(e) => {
                            eprintln!("[ERROR] IPv4 listener recv_from: {}", e);
                            continue;
                        }
                    }
                }
                res_v6 = async {
                    if let Some(ref s) = sock_v6 {
                        s.recv_from(&mut rx_v6_buf).await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    match res_v6 {
                        Ok((len, addr)) => (len, addr, true),
                        Err(e) => {
                            eprintln!("[ERROR] IPv6 listener recv_from: {}", e);
                            continue;
                        }
                    }
                }
            }.into_tuple();

            let rx_slice = if client_addr.is_ipv6() {
                &rx_v6_buf[..len]
            } else {
                &rx_v4_buf[..len]
            };

            let (env, env_len) = match OutboundEnvelope::decode(rx_slice) {
                Some(res) => res,
                None => continue, // Malformed packet
            };

            if len <= env_len {
                continue;
            }

            let target_addr = env.target;
            // Ignore warm-up lead-in packets with unallocated/zero targets
            if target_addr.ip().is_unspecified() || target_addr.port() == 0 {
                continue;
            }

            let proto_info = get_protocol_by_id(env.proto_id);
            let payload = rx_slice[env_len..len].to_vec();

            pkt_count += 1;
            if pkt_count <= 5 || pkt_count % 100 == 0 {
                println!(
                    "[RELAY OUTBOUND #{}] Client {} -> Proto [{}] -> Target {} ({} B stripped payload, Env: {}B)",
                    pkt_count, client_addr, proto_info.key, target_addr, payload.len(), env_len
                );
            }

            // Route to existing session or register new session
            if let Some(tx) = self.sessions.get_sender(&client_addr).await {
                let _ = tx.send((target_addr, env.proto_id, payload)).await;
            } else {
                let tx = self.sessions.register(client_addr, env.proto_id, self.listener.clone()).await;
                let _ = tx.send((target_addr, env.proto_id, payload)).await;

                println!(
                    "[NEW SESSION] Registered client {} (Initial Proto: {}, Target: {})",
                    client_addr, proto_info.key, target_addr
                );
            }
        }
    }
}

trait TupleHelper {
    fn into_tuple(self) -> (usize, SocketAddr);
}

impl TupleHelper for (usize, SocketAddr, bool) {
    fn into_tuple(self) -> (usize, SocketAddr) {
        (self.0, self.1)
    }
}
