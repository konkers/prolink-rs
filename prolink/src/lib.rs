use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::anyhow;
use log::{debug, error, info, warn};
use mac_address::mac_address_by_name;
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig, V4IfAddr};
use proto::KeepAlivePacket;
use thiserror::Error;
use tokio::{
    net::UdpSocket,
    sync::{broadcast, mpsc, watch},
    task::JoinHandle,
    time::{self, Instant},
};

mod analysis;
mod database;
pub mod message;
mod metadata;
mod proto;

pub use message::Message;

#[derive(Clone, Debug)]
struct Peer {
    name: String,
    device_num: u8,
    mac_addr: [u8; 6],
    ip_addr: [u8; 4],
    proto_ver: u8,
    last_seen: Instant,
}

impl Peer {
    fn is_same(&self, other: &Self) -> bool {
        self.name == other.name
            && self.mac_addr == other.mac_addr
            && self.ip_addr == other.ip_addr
            && self.proto_ver == other.proto_ver
    }
}

#[derive(Debug, Clone)]
enum PeerEvent {
    Joined(Peer),
    Left(Peer),
}

#[derive(Error, Debug)]
pub enum ProlinkError {
    #[error("terminating")]
    Terminating,

    #[error("{error_kind} error at 0x{pos:x} parsing {timestamp}: \n{dump}")]
    ParseError {
        error_kind: String,
        pos: usize,
        timestamp: u128,
        dump: String,
    },

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    SystemTime(#[from] std::time::SystemTimeError),

    #[error(transparent)]
    WatchRecvError(#[from] watch::error::RecvError),
    #[error(transparent)]
    WatchSendError(#[from] watch::error::SendError<bool>),
    #[error(transparent)]
    MessageSendError(#[from] mpsc::error::SendError<Message>),
}

pub type Result<T> = std::result::Result<T, ProlinkError>;

#[derive(Debug, Clone)]
pub struct Config {
    pub name: String,
    pub device_num: u8,
    pub interface_name: Option<String>,
}

pub struct Prolink {
    child_tasks: Vec<JoinHandle<()>>,
    msg_rx: mpsc::Receiver<Message>,
}

impl Prolink {
    pub async fn join(config: Config) -> Result<Prolink> {
        let (msg_tx, msg_rx) = mpsc::channel(256);
        let (joined_tx, mut joined_rx) = watch::channel(false);
        let (peers_tx, peers_rx) = broadcast::channel(64);
        let mut membership =
            Membership::new(&config, joined_tx, peers_tx.clone(), msg_tx.clone()).await?;

        let status = StatusTask::new(&config, peers_rx, msg_tx.clone()).await?;

        let status_handle = tokio::spawn(async move {
            if let Err(e) = status.run().await {
                error!(target: "prolink", "status task error: {}", e);
            }
        });

        // Membership task needs to be run last so that other tasks don't miss
        // membership events.
        let join_handle = tokio::spawn(async move {
            if let Err(e) = membership.run().await {
                error!(target: "prolink", "membership task error: {}", e);
            }
        });

        while *joined_rx.borrow() == false {
            joined_rx.changed().await?;
        }

        Ok(Prolink {
            child_tasks: vec![join_handle, status_handle],
            msg_rx,
        })
    }

    pub async fn next(&mut self) -> Result<Message> {
        self.msg_rx
            .recv()
            .await
            .ok_or(anyhow!("membership task has terminated").into())
    }

    pub async fn terminate(self) {
        // notify children that we are terminating.

        drop(self.msg_rx);
        for t in self.child_tasks {
            let _ = tokio::join!(t);
        }
    }
}

struct Membership {
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

impl Membership {
    async fn new(
        config: &Config,
        joined_tx: watch::Sender<bool>,
        peers_tx: broadcast::Sender<PeerEvent>,
        msg_tx: mpsc::Sender<Message>,
    ) -> Result<Membership> {
        let all_interfaces =
            NetworkInterface::show().map_err(|e| anyhow!("can't get network interfaces: {}", e))?;

        let mut network_interfaces = all_interfaces.iter().filter_map(|iface| ipv4_iface(iface));

        let (name, addr) = if let Some(iface_name) = &config.interface_name {
            network_interfaces
                .find(|(name, _)| name == iface_name)
                .ok_or(anyhow!("Can't find interface \"{}\".", iface_name))?
        } else {
            network_interfaces
                .next()
                .ok_or(anyhow!("Can't find a default interface."))?
        };

        let mac = mac_address_by_name(&name)
            .map_err(|e| anyhow!("failed to look up mac address: {}", e))?
            .ok_or(anyhow!("failed to look up mac address"))?;
        let ip = IpAddr::V4(addr.ip);
        let my_addr = SocketAddr::new(ip, 50000);
        let ip_addr = addr.ip.octets();
        let mac_addr = mac.bytes().clone();

        let broadcast_addr = SocketAddr::new(
            IpAddr::V4(addr.broadcast.ok_or(anyhow!("Can't get broacast addr"))?),
            50000,
        );

        let socket = UdpSocket::bind("0.0.0.0:50000").await?;
        socket.set_broadcast(true)?;

        Ok(Membership {
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
    async fn run(&mut self) -> Result<()> {
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
            device_type: 2,
            mac_addr: self.mac_addr,
            ip_addr: self.ip_addr,
            peers_seen: 1,
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
                            if let Ok(pkt) = proto::Packet::parse(pkt_buf) {
                                match pkt {
                                    proto::Packet::KeepAlive(ka) => self.handle_keep_alive(&ka).await?,
                                    _ => ()
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

struct StatusTask {
    config: Config,
    socket: UdpSocket,
    peers_rx: broadcast::Receiver<PeerEvent>,
    msg_tx: mpsc::Sender<Message>,
    current_tracks: HashMap<u8, message::Track>,

    peers: HashMap<u8, Peer>,
}

impl StatusTask {
    async fn new(
        config: &Config,
        peers_rx: broadcast::Receiver<PeerEvent>,
        msg_tx: mpsc::Sender<Message>,
    ) -> Result<StatusTask> {
        let socket = UdpSocket::bind("0.0.0.0:50002").await?;
        Ok(StatusTask {
            config: config.clone(),
            socket,
            peers_rx,
            msg_tx,
            current_tracks: HashMap::new(),
            peers: HashMap::new(),
        })
    }

    async fn run(mut self) -> Result<()> {
        let mut buf = [0; 4096];
        loop {
            tokio::select! {
                _ = self.msg_tx.closed() => {
                    return Ok(())
                }
                res = self.peers_rx.recv() => {
                    if let Ok(event) = res {
                        info!("peer event {:?}", &event);
                        match event {
                            PeerEvent::Joined(peer) => {self.peers.insert(peer.device_num, peer);}
                            PeerEvent::Left(peer) => {self.peers.remove(&peer.device_num);}
                        }
                    }
                }
                res = self.socket.recv_from(&mut buf) => {
                    if let Ok((len, _src)) = res {
                        let buf = &buf[0..len];
                        match  proto::Packet::parse(buf) {
                            Ok(pkt) => self.handle_packet(&pkt).await?,
                            Err(e) => debug!(target: "prolink", "error parsing packet {:x?}", e),
                        }
                    }
                }
            }
        }
    }

    async fn handle_packet(&mut self, pkt: &proto::Packet) -> Result<()> {
        match &pkt {
            &proto::Packet::PlayerStatus(status) => {
                self.handle_player_status_packet(&status).await?
            }
            _ => (),
        }
        Ok(())
    }

    async fn handle_player_status_packet(&mut self, pkt: &proto::PlayerStatusPacket) -> Result<()> {
        // Ignore packets form unknown peers
        if !self.peers.contains_key(&pkt.device_num) {
            warn!(
                "got player status packet from unknown player {}",
                pkt.device_num
            );
            return Ok(());
        }

        let track = message::Track {
            player_device: pkt.device_num,
            track_device: pkt.track_device,
            track_slot: pkt.track_slot,
            track_type: pkt.track_type,
            rekordbox_id: pkt.rekordbox_id,
            metadata: HashMap::new(),
            artwork: None,
        };

        let new = if let Some(prev) = self.current_tracks.insert(pkt.device_num, track.clone()) {
            prev != track
        } else {
            true
        };

        if new {
            if track.rekordbox_id != 0 {
                let peer = self
                    .peers
                    .get(&track.track_device)
                    .ok_or(anyhow!("unable to look up peer: {}", track.track_device))?
                    .clone();

                let msg_tx = self.msg_tx.clone();
                let dev_num = self.config.device_num;
                tokio::spawn(async move {
                    if let Err(e) = Self::fecth_metadata(dev_num, peer, track, msg_tx).await {
                        println!("metadata fetch failed: {}", e);
                    }
                });
            } else {
                self.msg_tx.send(Message::NewTrack(track)).await?;
            }
        }
        Ok(())
    }

    async fn fecth_metadata(
        our_device_num: u8,
        peer: Peer,
        mut track: message::Track,
        msg_tx: mpsc::Sender<Message>,
    ) -> Result<()> {
        let port = metadata::get_metadata_port(&peer.ip_addr).await?;
        metadata::get_metadata(our_device_num, &mut track, &peer.ip_addr, port).await?;
        msg_tx.send(Message::NewTrack(track)).await?;
        Ok(())
    }
}
