use anyhow::anyhow;
use log::error;
use thiserror::Error;
use tokio::{
    sync::{broadcast, mpsc, watch},
    task::JoinHandle,
    time::Instant,
};

mod analysis;
mod database;
pub mod message;
//mod metadata;
mod proto;
mod tasks;

use tasks::{
    beat::BeatTask, membership::MembershipTask, metadata::MetadataTask, status::StatusTask,
};

pub use message::Message;
pub use tasks::metadata::TrackMetadata;

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

    #[error("{error_kind} error at 0x{pos:x} parsing @{timestamp}: \n{dump}")]
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
            MembershipTask::new(&config, joined_tx, peers_tx.clone(), msg_tx.clone()).await?;

        let metadata = MetadataTask::new(peers_rx, msg_tx.clone());
        let status =
            StatusTask::new(peers_tx.subscribe(), msg_tx.clone(), metadata.client()).await?;
        let beat = BeatTask::new(msg_tx.clone()).await?;

        let metadata_handle = tokio::spawn(async move {
            if let Err(e) = metadata.run().await {
                error!(target: "prolink", "metadata task error: {}", e);
            }
        });

        let status_handle = tokio::spawn(async move {
            if let Err(e) = status.run().await {
                error!(target: "prolink", "status task error: {}", e);
            }
        });

        let beat_handle = tokio::spawn(async move {
            if let Err(e) = beat.run().await {
                error!(target: "prolink", "beat task error: {}", e);
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
            child_tasks: vec![join_handle, status_handle, metadata_handle, beat_handle],
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
