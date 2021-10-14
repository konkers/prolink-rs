use std::{
    net::{IpAddr, SocketAddr},
    os::linux::fs::MetadataExt,
    time::Duration,
};

use anyhow::{anyhow, Result};
use mac_address::get_mac_address;
use pnet::datalink::{self, NetworkInterface};
use tokio::{net::UdpSocket, time};

use prolink::{Config, Prolink};
/*
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
*/

#[tokio::main]
async fn main() -> Result<()> {
    let mut prolink = Prolink::join(Config {
        name: "prolink-util".to_string(),
        device_num: 4,
    })
    .await?;

    println!("connected");

    prolink.run().await?;
    tokio::signal::ctrl_c().await?;
    println!("terminating");
    // prolink.terminate().await;

    Ok(())
}
