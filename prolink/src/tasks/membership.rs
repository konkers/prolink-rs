use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::anyhow;
use log::info;
use mac_address::mac_address_by_name;
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig, V4IfAddr};
use tokio::{
    net::UdpSocket,
    sync::{broadcast, mpsc, watch},
    time::{self, Instant},
};

use crate::{
    message,
    proto::{self, KeepAlivePacket},
    Config, Message, Peer, PeerEvent, ProlinkError, Result,
};

pub(crate) struct MembershipTask {
    config: Config,
    joined_tx: watch::Sender<bool>,
    peers_tx: broadcast::Sender<PeerEvent>,
    msg_tx: mpsc::Sender<Message>,
    socket: UdpSocket,
    my_addr: SocketAddr,
    broadcast_addr: SocketAddr,
    mac_addr: [u8; 6],
    ip_addr: [u8; 4],
    peers: HashMap<u8, Peer>,
}

fn ipv4_iface(iface: &NetworkInterface) -> Option<(String, V4IfAddr)> {
    if let Some(addr) = iface.addr {
        match addr {
            Addr::V4(a) => Some((iface.name.clone(), a)),
            _ => None,
        }
    } else {
        None
    }
}

impl MembershipTask {
    pub(crate) async fn new(
        config: &Config,
        joined_tx: watch::Sender<bool>,
        peers_tx: broadcast::Sender<PeerEvent>,
        msg_tx: mpsc::Sender<Message>,
    ) -> Result<MembershipTask> {
        let socket = UdpSocket::bind("0.0.0.0:50000").await?;
        socket.set_broadcast(true)?;

        // Interface auto detection alogrithm inspried by:
        //     https://github.com/evanpurkhiser/prolink-connect
        //
        // We start by listening for keep alive packets and noting the address
        // that sent it.
        let mut buf = [0; 256];
        let keep_alive_addr = loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            if let Ok(pkt) = proto::Packet::parse_membership(&buf[0..len]) {
                if let proto::Packet::KeepAlive(_) = pkt {
                    match src {
                        SocketAddr::V4(v4) => break v4.ip().clone(),
                        _ => (),
                    }
                }
            }
        };

        // Next we get all IPv4 interfaces in the system.
        let all_interfaces =
            NetworkInterface::show().map_err(|e| anyhow!("can't get network interfaces: {}", e))?;
        let mut network_interfaces = all_interfaces.iter().filter_map(|iface| ipv4_iface(iface));

        // We then look for an interface who's network keep_alive_addr belongs.
        let keep_alive_addr = u32::from_be_bytes(keep_alive_addr.octets());
        let (name, addr) = network_interfaces
            .find(|(_, addr)| match addr.netmask {
                None => false,
                Some(netmask) => {
                    let netmask = u32::from_be_bytes(netmask.octets());
                    let iface_addr = u32::from_be_bytes(addr.ip.octets());

                    (iface_addr & netmask) == (keep_alive_addr & netmask)
                }
            })
            .ok_or(anyhow!(
                "Can't find interface for \"{}\".",
                &keep_alive_addr
            ))?;

        let mac = mac_address_by_name(&name)
            .map_err(|e| anyhow!("failed to look up mac address: {}", e))?
            .ok_or(anyhow!("failed to look up mac address"))?;

        info!("Listening on {}", name);
        let ip = IpAddr::V4(addr.ip);
        let my_addr = SocketAddr::new(ip, 50000);
        let ip_addr = addr.ip.octets();
        let mac_addr = mac.bytes().clone();

        let broadcast_addr = SocketAddr::new(
            IpAddr::V4(addr.broadcast.ok_or(anyhow!("Can't get broacast addr"))?),
            50000,
        );

        Ok(MembershipTask {
            config: config.clone(),
            joined_tx,
            peers_tx,
            msg_tx,
            socket,
            my_addr,
            broadcast_addr,
            mac_addr,
            ip_addr,
            peers: HashMap::new(),
        })
    }

    async fn process_timeouts(&mut self) -> Result<()> {
        let now = Instant::now();

        // This should use drain_filter once stabilized.
        let timed_out_peers: Vec<u8> = self
            .peers
            .iter()
            .filter(|(_id, peer)| (now - peer.last_seen) > Duration::from_secs(10))
            .map(|(id, _peer)| *id)
            .collect();
        for id in &timed_out_peers {
            if let Some(peer) = self.peers.remove(&id) {
                info!("Peer left {:?}", &peer);
                self.msg_tx
                    .send(Message::PeerLeft(message::Peer {
                        name: peer.name.clone(),
                        device_num: peer.device_num,
                    }))
                    .await?;
                self.peers_tx
                    .send(PeerEvent::Left(peer))
                    .map_err(|e| anyhow!("Failed to send peer left event: {}", e))?;
            }
        }

        Ok(())
    }

    pub(crate) async fn run(&mut self) -> Result<()> {
        if let Err(e) = self.run_impl().await {
            match e {
                ProlinkError::Terminating => return Ok(()),
                _ => return Err(e),
            }
        }
        Ok(())
    }

    async fn run_impl(&mut self) -> Result<()> {
        self.join().await?;
        // Enter KeepAlive phase
        let mut keep_alive = proto::KeepAlivePacket {
            name: self.config.name.clone(),
            proto_ver: 2,
            device_num: self.config.device_num,
            unknown_25: 1,
            mac_addr: self.mac_addr,
            ip_addr: self.ip_addr,
            peers_seen: 1,
            device_type: 2,
            unknown_35: 1,
        };

        let mut keep_alive_data = Vec::new();
        loop {
            self.process_timeouts().await?;
            keep_alive.peers_seen = self.peers.len() as u8 + 1u8;
            keep_alive_data.clear();
            keep_alive.write(&mut keep_alive_data)?;
            self.socket
                .send_to(&keep_alive_data, self.broadcast_addr)
                .await?;
            self.wait(Duration::from_millis(1500)).await?;
        }
    }

    async fn join(&mut self) -> Result<()> {
        // Announce
        let announce = proto::AnnouncePacket {
            name: self.config.name.clone(),
            proto_ver: 2,
            device_type: 1,
        };
        let mut announce_data = Vec::new();
        announce.write(&mut announce_data)?;
        for _ in 0..3 {
            self.socket
                .send_to(&announce_data, self.broadcast_addr)
                .await?;
            self.wait(Duration::from_millis(300)).await?;
        }

        // Claim Phase 1
        let mut claim1 = proto::DeviceNumClaim1Packet {
            name: self.config.name.clone(),
            proto_ver: 2,
            pkt_num: 0,
            device_type: 1,
            mac_addr: self.mac_addr.clone(),
        };

        for i in 1..4 {
            let mut claim1_data = Vec::new();
            claim1.pkt_num = i;
            claim1.write(&mut claim1_data)?;
            self.socket
                .send_to(&claim1_data, self.broadcast_addr)
                .await?;
            self.wait(Duration::from_millis(300)).await?;
        }

        // Claim Phase 2
        let mut claim2 = proto::DeviceNumClaim2Packet {
            name: self.config.name.clone(),
            proto_ver: 2,
            ip_addr: self.ip_addr.clone(),
            mac_addr: self.mac_addr.clone(),
            device_num: self.config.device_num,
            pkt_num: 0,
            device_type: 1,
            auto_assign: false,
        };

        for i in 1..4 {
            let mut claim2_data = Vec::new();
            claim2.pkt_num = i;
            claim2.write(&mut claim2_data)?;
            self.socket
                .send_to(&claim2_data, self.broadcast_addr)
                .await?;
            self.wait(Duration::from_millis(300)).await?;
        }

        // Claim Phase 3
        // In non-auto-assing mode, we only send one.
        let claim3 = proto::DeviceNumClaim3Packet {
            name: self.config.name.clone(),
            proto_ver: 2,
            device_num: self.config.device_num,
            pkt_num: 1,
        };
        let mut claim3_data = Vec::new();
        claim3.write(&mut claim3_data)?;
        self.socket
            .send_to(&claim3_data, self.broadcast_addr)
            .await?;
        self.wait(Duration::from_millis(300)).await?;

        self.joined_tx.send(true)?;

        Ok(())
    }

    async fn wait(&mut self, dur: Duration) -> Result<()> {
        self.wait_until(Instant::now() + dur).await
    }

    async fn wait_until(&mut self, when: Instant) -> Result<()> {
        let timeout = time::sleep_until(when);
        tokio::pin!(timeout);

        let mut buf = [0; 4096];
        loop {
            tokio::select! {
                _ = &mut timeout => {
                    return Ok(())
                }
                _ = self.msg_tx.closed() => {
                    return Err(ProlinkError::Terminating);
                }
                res = self.socket.recv_from(&mut buf) => {
                    if let Ok((len, src)) = res {
                        let pkt_buf = &buf[0..len];
                        if src != self.my_addr {
                            match proto::Packet::parse_membership(pkt_buf) {
                                Ok(pkt) => match pkt {
                                    proto::Packet::KeepAlive(ka) => self.handle_keep_alive(&ka).await?,
                                    _ => (),
                                }
                                #[allow(unused_variables)]
                                Err(e) => {
                                    #[cfg(feature = "log_bad_packets")]
                                    log::warn!("can't parse packet: {}", e);
                                }
                            }
                        }
                    }
                }

            }
        }
    }

    async fn handle_keep_alive(&mut self, ka: &KeepAlivePacket) -> Result<()> {
        let peer = Peer {
            name: ka.name.clone(),
            device_num: ka.device_num,
            mac_addr: ka.mac_addr,
            ip_addr: ka.ip_addr,
            proto_ver: ka.proto_ver,
            last_seen: Instant::now(),
        };
        let mut new = false;

        if let Some(prev) = self.peers.insert(ka.device_num, peer.clone()) {
            if !prev.is_same(&peer) {
                info!("Peer left {:?}", &prev);
                self.msg_tx
                    .send(Message::PeerLeft(message::Peer {
                        name: prev.name.clone(),
                        device_num: prev.device_num,
                    }))
                    .await?;
                self.peers_tx
                    .send(PeerEvent::Left(prev))
                    .map_err(|e| anyhow!("Failed to send peer left event: {}", e))?;
                new = true
            }
        } else {
            new = true;
        }

        if new {
            info!("Peer joined {:?}", &peer);
            self.msg_tx
                .send(Message::PeerJoined(message::Peer {
                    name: peer.name.clone(),
                    device_num: peer.device_num,
                }))
                .await?;
            self.peers_tx
                .send(PeerEvent::Joined(peer))
                .map_err(|e| anyhow!("Failed to send peer joined event: {}", e))?;
        }

        Ok(())
    }
}
