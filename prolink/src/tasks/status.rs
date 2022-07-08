use anyhow::anyhow;
use log::{debug, info, warn};
use std::collections::HashMap;
use tokio::{
    net::UdpSocket,
    sync::{broadcast, mpsc},
};

use crate::{message, metadata, proto, Config, Message, Peer, PeerEvent, Result};

pub(crate) struct StatusTask {
    config: Config,
    socket: UdpSocket,
    peers_rx: broadcast::Receiver<PeerEvent>,
    msg_tx: mpsc::Sender<Message>,
    current_tracks: HashMap<u8, message::Track>,

    peers: HashMap<u8, Peer>,
}

impl StatusTask {
    pub(crate) async fn new(
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

    pub(crate) async fn run(mut self) -> Result<()> {
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
