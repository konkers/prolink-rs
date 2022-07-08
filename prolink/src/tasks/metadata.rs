use anyhow::anyhow;
use log::{info, warn};
use prolink_nfs::NfsClient;
use serde::Serialize;
use std::{
    collections::HashMap,
    io::Cursor,
    net::{IpAddr, Ipv4Addr},
};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::{database::Database, Message, PeerEvent, Result};

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TrackMetadata {
    pub sample_rate: u32,
    pub composer: String,
    pub file_size: u32,
    pub key: String,
    pub original_artist: String,
    pub label: String,
    pub remixer: String,
    pub bitrate: u32,
    pub track_number: u32,
    pub tempo: f32,
    pub genre: String,
    pub album_name: String,
    pub album_artist: String,
    pub artist: String,
    pub disc: u16,
    pub play_count: u16,
    pub year: u16,
    pub sample_depth: u16,
    pub duration: u16,
    pub color: String,
    pub rating: u8,
    pub isrc: String,
    pub date_added: String,
    pub release_date: String,
    pub mix_name: String,
    pub comment: String,
    pub title: String,
}

pub struct TrackInfo {
    pub metadata: TrackMetadata,
    pub artwork: Option<Vec<u8>>,
}
struct MetadataRequest {
    device: u8,
    slot: u8,
    rekordbox_id: u32,
    result_tx: oneshot::Sender<Result<TrackInfo>>,
}

pub(crate) struct MetadataTask {
    peers_rx: broadcast::Receiver<PeerEvent>,
    msg_tx: mpsc::Sender<Message>,
    nfs_clients: HashMap<u8, NfsClient>,
    databases: HashMap<u8, HashMap<u8, Database>>,
    request_tx: mpsc::Sender<MetadataRequest>,
    request_rx: mpsc::Receiver<MetadataRequest>,
}

impl MetadataTask {
    pub(crate) fn new(
        peers_rx: broadcast::Receiver<PeerEvent>,
        msg_tx: mpsc::Sender<Message>,
    ) -> MetadataTask {
        let (request_tx, request_rx) = mpsc::channel(16);
        MetadataTask {
            peers_rx,
            msg_tx,
            nfs_clients: HashMap::new(),
            databases: HashMap::new(),
            request_tx,
            request_rx,
        }
    }

    pub(crate) fn client(&self) -> MetadataClient {
        MetadataClient {
            request_tx: self.request_tx.clone(),
        }
    }

    pub(crate) async fn run(mut self) -> Result<()> {
        loop {
            tokio::select! {
                _ = self.msg_tx.closed() => {
                        return Ok(())
                }
                res = self.peers_rx.recv() => {
                    if let Ok(event) = res {
                        self.peer_event(event).await?;
                    }
                }
                res = self.request_rx.recv() => {
                    if let Some(request) = res {
                        self.metadata_request_wrapper(request).await?;
                    }
                }
            }
        }
    }

    async fn peer_event(&mut self, event: PeerEvent) -> Result<()> {
        match event {
            PeerEvent::Joined(peer) => {
                let addr = IpAddr::V4(Ipv4Addr::new(
                    peer.ip_addr[0],
                    peer.ip_addr[1],
                    peer.ip_addr[2],
                    peer.ip_addr[3],
                ));
                self.nfs_clients
                    .insert(peer.device_num, NfsClient::connect(addr).await?);
            }
            PeerEvent::Left(peer) => {
                self.nfs_clients.remove(&peer.device_num);
                self.databases.remove(&peer.device_num);
            }
        }

        Ok(())
    }

    async fn metadata_request_wrapper(&mut self, request: MetadataRequest) -> Result<()> {
        let result = self.metadata_request(&request).await;
        request
            .result_tx
            .send(result)
            .map_err(|_| anyhow!("Error sending response to metadata request").into())
    }

    async fn metadata_request(&mut self, request: &MetadataRequest) -> Result<TrackInfo> {
        let dbs = self
            .databases
            .entry(request.device)
            .or_insert_with(|| HashMap::new());

        let mut client = self.nfs_clients.get_mut(&request.device).unwrap();
        if !dbs.contains_key(&request.slot) {
            dbs.insert(
                request.slot,
                Self::fetch_database(&mut client, request.slot).await?,
            );
        }
        let db = dbs.get(&request.slot).unwrap();

        let track = db
            .tracks
            .get(&request.rekordbox_id)
            .ok_or(anyhow!("Can't find track for id {}", &request.rekordbox_id))?;

        let blank = "".to_string();
        let composer = db.artists.get(&track.composer_id).unwrap_or(&blank);
        let key = db.keys.get(&track.key_id).unwrap_or(&blank);
        let original_artist = db.artists.get(&track.original_artist_id).unwrap_or(&blank);
        let label = db.labels.get(&track.label_id).unwrap_or(&blank);
        let remixer = db.artists.get(&track.remixer_id).unwrap_or(&blank);
        let genere = db.generes.get(&track.genre_id).unwrap_or(&blank);
        let album = db.albums.get(&track.album_id);
        let (album_name, album_artist) = match album {
            Some(album) => (
                &album.name,
                db.artists.get(&album.artist_id).unwrap_or(&blank),
            ),
            None => (&blank, &blank),
        };

        let artist = db.artists.get(&track.artist_id).unwrap_or(&blank);
        let color = db.colors.get(&(track.color_id as u32)).unwrap_or(&blank);

        let tempo = track.tempo as f32 / 100.0;

        let artwork = match db.artwork.get(&track.artwork_id) {
            Some(path) => {
                let path = Self::slot_prefix(request.slot)?.to_owned() + path;
                match client.get_file(&path).await {
                    Ok(data) => Some(data),
                    Err(e) => {
                        warn!("Failed to fetch artwork at {}: {}", path, e);
                        None
                    }
                }
            }
            None => None,
        };

        Ok(TrackInfo {
            metadata: TrackMetadata {
                sample_rate: track.sample_rate,
                composer: composer.clone(),
                file_size: track.file_size,
                key: key.clone(),
                original_artist: original_artist.clone(),
                label: label.clone(),
                remixer: remixer.clone(),
                bitrate: track.bitrate,
                track_number: track.track_number,
                tempo,
                genre: genere.clone(),
                album_name: album_name.clone(),
                album_artist: album_artist.clone(),
                artist: artist.clone(),
                disc: track.disc,
                play_count: track.play_count,
                year: track.year,
                sample_depth: track.sample_depth,
                duration: track.duration,
                color: color.clone(),
                rating: track.rating,
                isrc: track.strings[0].clone(),
                date_added: track.strings[10].clone(),
                release_date: track.strings[11].clone(),
                mix_name: track.strings[12].clone(),
                comment: track.strings[16].clone(),
                title: track.strings[17].clone(),
            },
            artwork,
        })
    }

    async fn fetch_database(client: &mut NfsClient, slot: u8) -> Result<Database> {
        let prefix = Self::slot_prefix(slot)?;
        let db_path = prefix.to_owned() + "/PIONEER/rekordbox/export.pdb";
        let data = client.get_file(&db_path).await?;
        info!("db len {}", data.len());
        let mut c = Cursor::new(data);

        let db = Database::parse(&mut c).await?;
        info!("database loaded");
        Ok(db)
    }

    fn slot_prefix(slot: u8) -> Result<&'static str> {
        match slot {
            2 => Ok(&"/B"),
            3 => Ok(&"/C"),
            _ => Err(anyhow!("metadata request on unsupported slot {}", slot).into()),
        }
    }
}

#[derive(Clone)]
pub(crate) struct MetadataClient {
    request_tx: mpsc::Sender<MetadataRequest>,
}

impl MetadataClient {
    pub(crate) async fn lookup(
        &self,
        device: u8,
        slot: u8,
        rekordbox_id: u32,
    ) -> Result<TrackInfo> {
        let (tx, rx) = oneshot::channel();

        self.request_tx
            .send(MetadataRequest {
                device,
                slot,
                rekordbox_id,
                result_tx: tx,
            })
            .await
            .map_err(|e| anyhow!("error sending metadata request: {}", e))?;

        rx.await
            .map_err(|e| anyhow!("error recieving metadata response: {}", e))?
    }
}
