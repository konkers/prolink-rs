use anyhow::Result;

use prolink::{Config, Prolink};

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
                println!("msg: {:?}", res);
            }
        }
    }
    println!("terminating");
    prolink.terminate().await;

    Ok(())
}
