use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::IndexMut,
    time::Duration,
};

use anyhow::{anyhow, Result};
use pnet::{datalink, packet::ip::IpNextHeaderProtocols::Udp};
use proto::KeepAlivePacket;
use tokio::{
    net::UdpSocket,
    sync::watch,
    task::JoinHandle,
    time::{self, Instant},
};

mod proto;

#[derive(Debug, Clone)]
pub struct Config {
    pub name: String,
    pub device_num: u8,
}

pub struct Prolink {
    config: Config,
    joined_rx: watch::Receiver<bool>,
    child_tasks: Vec<JoinHandle<()>>,
}

impl Prolink {
    pub async fn join(config: Config) -> Result<Prolink> {
        let (joined_tx, mut joined_rx) = watch::channel(false);
        let mut membership = Membership::new(&config, joined_tx).await?;

        let join_handle = tokio::spawn(async move {
            if let Err(e) = membership.run().await {
                println!("error joining: {}", e);
            }
        });

        while *joined_rx.borrow() == false {
            joined_rx.changed().await?;
        }
        Ok(Prolink {
            config,
            joined_rx,
            child_tasks: vec![join_handle],
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        let status = StatusTask::new(&self.config.clone()).await?;

        let status_handle = tokio::spawn(async move {
            if let Err(e) = status.run().await {
                println!("error joining: {}", e);
            }
        });

        self.child_tasks.push(status_handle);

        Ok(())
    }

    pub async fn terminate(self) {
        for t in self.child_tasks {
            let _ = tokio::join!(t);
        }
    }
}

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

struct Membership {
    config: Config,
    joined_tx: watch::Sender<bool>,
    socket: UdpSocket,
    my_addr: SocketAddr,
    broadcast_addr: SocketAddr,
    mac_addr: [u8; 6],
    ip_addr: [u8; 4],
    peers: HashMap<u8, Peer>,
}

impl Membership {
    async fn new(config: &Config, joined_tx: watch::Sender<bool>) -> Result<Membership> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .iter()
            .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty() && !e.mac.is_none())
            .ok_or(anyhow!("Can't find default interface"))?;
        let mac_addr = interface.mac.unwrap().octets().clone();
        let iface = interface.ips.iter().find(|e| e.is_ipv4()).unwrap();
        let my_addr = SocketAddr::new(iface.ip(), 50000);
        let ip_addr = match iface.ip() {
            IpAddr::V4(ip) => ip.octets(),
            _ => panic!("is_ipv4() is wrong"),
        };

        let broadcast_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), 50000);

        let socket = UdpSocket::bind("0.0.0.0:50000").await?;
        socket.set_broadcast(true)?;

        Ok(Membership {
            config: config.clone(),
            joined_tx,
            socket,
            my_addr,
            broadcast_addr,
            mac_addr,
            ip_addr,
            peers: HashMap::new(),
        })
    }

    fn process_timeouts(&mut self) {
        let now = Instant::now();

        // This should use drain_filter once stabilized.
        let timed_out_peers: Vec<u8> = self
            .peers
            .iter()
            .filter(|(_id, peer)| (now - peer.last_seen) > Duration::from_secs(10))
            .map(|(id, _peer)| *id)
            .collect();
        for id in timed_out_peers {
            if let Some(peer) = self.peers.remove(&id) {
                println!("Peer {} @ {} left", peer.name, peer.device_num);
            }
        }
    }
    async fn run(&mut self) -> Result<()> {
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
            self.process_timeouts();
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
        for i in 0..3 {
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
                res = self.socket.recv_from(&mut buf) => {
                    if let Ok((len, src)) = res {
                        let pkt_buf = &buf[0..len];
                        if src != self.my_addr {
                            if let Ok(pkt) = proto::Packet::parse(pkt_buf) {
                                println!("{:x?}", &pkt);
                                match pkt {
                                    proto::Packet::KeepAlive(ka) => self.handle_keep_alive(&ka),
                                    _ => ()
                                }
                            }
                        }
                    }
                }

            }
        }
    }

    fn handle_keep_alive(&mut self, ka: &KeepAlivePacket) {
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
                println!("Peer {} @ {} left", prev.name, prev.device_num);
                new = true
            }
        } else {
            new = true;
        }

        if new {
            println!("Peer {} @ {} joined", peer.name, peer.device_num);
        }
    }
}

struct StatusTask {
    config: Config,
    socket: UdpSocket,
}

impl StatusTask {
    async fn new(config: &Config) -> Result<StatusTask> {
        let socket = UdpSocket::bind("0.0.0.0:50002").await?;
        Ok(StatusTask {
            config: config.clone(),
            socket,
        })
    }

    async fn run(self) -> Result<()> {
        let mut buf = [0; 4096];
        loop {
            let (_len, src) = self.socket.recv_from(&mut buf).await?;
            println!("50002 {:?}", &src);
            if let Ok(pkt) = proto::Packet::parse(&buf) {
                println!("{:#?}", &pkt);
            }
        }
    }
}
