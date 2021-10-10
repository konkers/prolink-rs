use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::anyhow;
use mac_address::get_mac_address;
use pnet::datalink::{self, NetworkInterface};
use tokio::{net::UdpSocket, time};

use prolink::{
    AnnouncePacket, BeatPacket, DeviceNumClaim1Packet, DeviceNumClaim2Packet,
    DeviceNumClaim3Packet, KeepAlivePacket, Packet,
};

async fn negotiation() -> std::io::Result<()> {
    let name = "prolink-util".to_string();
    let device_type = 2;
    let device_num = 4;

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty() && !e.mac.is_none())
        .unwrap();
    let mac_addr = interface.mac.unwrap().octets().clone();
    let iface = interface.ips.iter().find(|e| e.is_ipv4()).unwrap();
    let my_addr = SocketAddr::new(iface.ip(), 50000);
    let ip_addr = match iface.ip() {
        IpAddr::V4(ip) => ip.octets(),
        _ => panic!("is_ipv4() is wrong"),
    };

    let socket = UdpSocket::bind("0.0.0.0:50000").await?;
    socket.set_broadcast(true)?;
    let broadcast_addr = "192.168.1.255:50000";
    println!("announce");
    // Announce
    let announce = AnnouncePacket {
        name: name.clone(),
        proto_ver: 2,
    };
    let mut announce_data = Vec::new();
    announce.write(&mut announce_data)?;
    for i in 0..3 {
        socket.send_to(&announce_data, broadcast_addr).await?;
        time::sleep(Duration::from_millis(300)).await;
    }

    println!("claim1");
    // Claim Phase 1
    let mut claim1 = DeviceNumClaim1Packet {
        name: name.clone(),
        proto_ver: 2,
        pkt_num: 0,
        mac_addr: mac_addr.clone(),
    };

    for i in 1..4 {
        let mut claim1_data = Vec::new();
        claim1.pkt_num = i;
        claim1.write(&mut claim1_data)?;
        socket.send_to(&claim1_data, broadcast_addr).await?;
        time::sleep(Duration::from_millis(300)).await;
    }

    println!("claim2");
    // Claim Phase 2
    let mut claim2 = DeviceNumClaim2Packet {
        name: name.clone(),
        proto_ver: 2,
        ip_addr: ip_addr.clone(),
        mac_addr: mac_addr.clone(),
        device_num,
        pkt_num: 0,
        auto_assign: false,
    };

    for i in 1..4 {
        let mut claim2_data = Vec::new();
        claim2.pkt_num = i;
        claim2.write(&mut claim2_data)?;
        socket.send_to(&claim2_data, broadcast_addr).await?;
        time::sleep(Duration::from_millis(300)).await;
    }

    println!("claim3");
    // Claim Phase 3
    // In non-auto-assing mode, we only send one.
    let mut claim3 = DeviceNumClaim3Packet {
        name: name.clone(),
        proto_ver: 2,
        device_num,
        pkt_num: 1,
    };
    let mut claim3_data = Vec::new();
    claim3.write(&mut claim3_data)?;
    socket.send_to(&claim3_data, broadcast_addr).await?;
    time::sleep(Duration::from_millis(300)).await;

    // Enter KeepAlive phase
    let keep_alive = KeepAlivePacket {
        name: name.clone(),
        proto_ver: 2,
        device_num: 4,
        device_type: 2,
        mac_addr,
        ip_addr,
        peers_seen: 1,
        unknown_35: 1,
    };
    let mut keep_alive_data = Vec::new();
    keep_alive.write(&mut keep_alive_data)?;

    let mut interval = time::interval(Duration::from_millis(1500));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    let mut buf = [0; 4096];
    loop {
        tokio::select! {
            _ = interval.tick() => {
              socket.send_to(&keep_alive_data, broadcast_addr).await?;
            }
            res = socket.recv_from(&mut buf) => {
                if let Ok((len, src)) = res {
                    let pkt_buf = &buf[0..len];
                    if src != my_addr {
                        if let Ok(pkt) = Packet::parse(pkt_buf) {
                            println!("{:x?}", &pkt);
                        }
                    }
                }
            }
        }
    }
}
async fn status() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:50002").await?;
    let mut buf = [0; 4096];
    loop {
        let (_len, src) = socket.recv_from(&mut buf).await?;
        if let Ok(pkt) = Packet::parse(&buf) {
            println!("{:#?}", &pkt);
        }
    }
}

async fn beatsync() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:50001").await?;
    let mut buf = [0; 4096];
    loop {
        let (_len, src) = socket.recv_from(&mut buf).await?;
        if let Ok(pkt) = Packet::parse(&buf) {
            println!("{:#?}", &pkt);
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let _ = tokio::join!(negotiation(), beatsync(), status());

    Ok(())
}
