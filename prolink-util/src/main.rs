use anyhow::Result;

use tokio::fs;

use prolink::{message::Track, Config, Message, Prolink};

#[tokio::main]
async fn main() -> Result<()> {
    let mut prolink = Prolink::join(Config {
        name: "prolink-util".to_string(),
        device_num: 4,
    })
    .await?;

    println!("connected");

    prolink.run().await?;
    println!("running");
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            res = prolink.next() => {
                match res {
                    Ok(Message::NewTrack(t)) => handle_new_track(&t).await?,
                    _ => println!("msg: {:?}", res)
                }

            }
        }
    }
    println!("terminating");
    prolink.terminate().await;

    Ok(())
}

async fn handle_new_track(t: &Track) -> Result<()> {
    println!("New Track:");
    for (cat, val) in &t.metadata {
        println!("\t{}: {}", cat, val);
    }
    if let Some(artwork) = &t.artwork {
        let suffix = if artwork[0..3] == [0xff, 0xd8, 0xff] {
            ".jpg"
        } else if artwork[0..8] == [137, 80, 78, 71, 13, 10, 26, 10] {
            ".png"
        } else {
            ""
        };
        let path = format!("artwork-{}{}", t.rekordbox_id, suffix);
        fs::write(&path, artwork).await?;
    }
    Ok(())
}
