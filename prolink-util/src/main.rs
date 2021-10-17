use std::hash::Hash;
use std::{borrow::Borrow, collections::HashMap};

use anyhow::Result;

use prolink::{message::Track, Config, Message, Prolink};
use serde::{Deserialize, Serialize};
use tide::{prelude::*, sse, Request};
use tokio::{fs, sync::watch};

#[derive(Clone, Debug, Serialize)]
struct DeckInfo {
    attrs: HashMap<String, String>,
    artwork: Option<String>,
}

#[derive(Clone)]
struct WebState {
    decks: watch::Receiver<HashMap<u8, DeckInfo>>,
}

struct ProlinkTask {
    prolink: Prolink,
    decks_tx: watch::Sender<HashMap<u8, DeckInfo>>,
    decks: HashMap<u8, DeckInfo>,
}

impl ProlinkTask {
    async fn start(decks_tx: watch::Sender<HashMap<u8, DeckInfo>>) -> Result<()> {
        let prolink = Prolink::join(Config {
            name: "prolink-util".to_string(),
            device_num: 4,
        })
        .await?;

        let task = ProlinkTask {
            prolink,
            decks_tx,
            decks: HashMap::new(),
        };
        println!("connected");

        task.run().await?;
        Ok(())
    }

    async fn run(mut self) -> Result<()> {
        self.prolink.run().await?;
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    break;
                }
                res = self.prolink.next() => {
                    match res {
                        Ok(Message::NewTrack(t)) => self.handle_new_track(&t).await?,
                        _ => println!("msg: {:?}", res)
                    }

                }
            }
        }
        println!("terminating");
        self.prolink.terminate().await;

        Ok(())
    }
    async fn handle_new_track(&mut self, t: &Track) -> Result<()> {
        let mut info = DeckInfo {
            attrs: t.metadata.clone(),
            artwork: None,
        };
        if let Some(artwork) = &t.artwork {
            let suffix = if artwork[0..3] == [0xff, 0xd8, 0xff] {
                ".jpg"
            } else if artwork[0..8] == [137, 80, 78, 71, 13, 10, 26, 10] {
                ".png"
            } else {
                ""
            };
            let filename = format!("artwork-{}{}", t.rekordbox_id, suffix);
            let path = format!("./art/{}", filename);
            fs::write(&path, artwork).await?;
            info.artwork = Some(format!("/art/{}", filename));
        }

        self.decks.insert(t.player_device, info);
        self.decks_tx.send(self.decks.clone())?;

        Ok(())
    }
}

async fn web(decks_rx: watch::Receiver<HashMap<u8, DeckInfo>>) -> Result<()> {
    tide::log::start();
    let mut app = tide::with_state(WebState { decks: decks_rx });
    app.at("/decks")
        .get(sse::endpoint(|req: Request<WebState>, sender| async move {
            let mut state = req.state().clone();
            while state.decks.changed().await.is_ok() {
                let decks = {
                    let decks = state.decks.borrow();
                    json!(*decks).to_string()
                };
                sender.send("decks", decks, None).await?;
            }

            Ok(())
        }));
    app.at("/art").serve_dir("./art/")?;
    app.listen("127.0.0.1:8080").await?;
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let (decks_tx, decks_rx) = watch::channel(HashMap::new());

    let _ = tokio::spawn(async move {
        if let Err(e) = web(decks_rx).await {
            println!("web task error: {}", e);
        }
    });
    let _ = tokio::spawn(async move {
        if let Err(e) = ProlinkTask::start(decks_tx).await {
            println!("prolink task error: {}", e);
        }
    });
    tokio::signal::ctrl_c().await?;
    println!("terminating");

    Ok(())
}
