use anyhow::{anyhow, Result};
use prolink_nfs::NfsClient;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(about = "prolink nfs utility")]
enum Opt {
    Ls { paths: Vec<String> },
}

fn parse_nfs_path(nfs_path: &str) -> Result<(IpAddr, String)> {
    let (host, path) = nfs_path
        .split_once(":")
        .ok_or(anyhow!("No : in path spec {}", nfs_path))?;

    let mut addrs = (host, 0).to_socket_addrs()?;
    let addr = addrs.next().ok_or(anyhow!("filed to lookup {}", host))?;
    Ok((addr.ip(), path.to_string()))
}
async fn ls(paths: &Vec<String>) -> Result<()> {
    for path in paths {
        let (addr, path) = parse_nfs_path(path)?;

        let mut client = NfsClient::connect(addr).await?;

        let exports = client.exports().await?;

        println!("Exports");
        for export in exports {
            println!("  {}", export);
        }

        let files = client.list_files(&path).await?;
        println!("Files");
        for file in files {
            println!("  {}", file);
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::from_args();

    match opt {
        Opt::Ls { paths } => ls(&paths).await,
    }
}
