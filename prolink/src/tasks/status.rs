use log::{info, warn};
use std::collections::HashMap;
use tokio::{
    net::UdpSocket,
    sync::{broadcast, mpsc},
};

use crate::{message, proto, tasks::metadata::MetadataClient, Message, Peer, PeerEvent, Result};

pub(crate) struct StatusTask {
    socket: UdpSocket,
    peers_rx: broadcast::Receiver<PeerEvent>,
    msg_tx: mpsc::Sender<Message>,
    metadata: MetadataClient,
    current_tracks: HashMap<u8, message::Track>,

    peers: HashMap<u8, Peer>,
}

impl StatusTask {
    pub(crate) async fn new(
        peers_rx: broadcast::Receiver<PeerEvent>,
        msg_tx: mpsc::Sender<Message>,
        metadata: MetadataClient,
    ) -> Result<StatusTask> {
        let socket = UdpSocket::bind("0.0.0.0:50002").await?;
        Ok(StatusTask {
            socket,
            peers_rx,
            msg_tx,
            metadata,
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
                        self.handle_buf(buf).await?;
                    }
                }
            }
        }
    }

    async fn handle_buf(&mut self, buf: &[u8]) -> Result<()> {
        match proto::Packet::parse_status(buf) {
            Ok(pkt) => match &pkt {
                proto::Packet::PlayerStatus(ref status) => {
                    self.handle_player_status_packet(status).await?
                }
                _ => (),
            },
            #[allow(unused_variables)]
            Err(e) => {
                #[cfg(feature = "log_bad_packets")]
                log::warn!("can't parse packet: {}", e);
            }
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
            metadata: None,
            artwork: None,
        };

        let new_track =
            if let Some(prev) = self.current_tracks.insert(pkt.device_num, track.clone()) {
                prev != track
            } else {
                true
            };

        if new_track {
            if track.rekordbox_id != 0 {
                let msg_tx = self.msg_tx.clone();
                let client = self.metadata.clone();
                tokio::spawn(async move {
                    if let Err(e) = Self::fecth_metadata(client, track, msg_tx).await {
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
        client: MetadataClient,
        mut track: message::Track,
        msg_tx: mpsc::Sender<Message>,
    ) -> Result<()> {
        let info = client
            .lookup(track.track_device, track.track_slot, track.rekordbox_id)
            .await?;
        track.metadata = Some(info.metadata);
        track.artwork = info.artwork;
        msg_tx.send(Message::NewTrack(track)).await?;
        Ok(())
    }
}
