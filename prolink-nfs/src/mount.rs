use anyhow::anyhow;
use byteorder::{LittleEndian, WriteBytesExt};
use std::{
    io::Cursor,
    net::{IpAddr, SocketAddr},
};

use super::bind::{self, Bind};
use super::rpc::{NoneParam, Rpc};
use super::FileHandle;
use crate::Result;

#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    unused_assignments,
    deprecated
)]
pub(super) mod xdr {
    use xdr_codec;
    include!(concat!(env!("OUT_DIR"), "/mount_xdr.rs"));
}

pub const MOUNTPROG: u32 = 100005;
pub const MOUNTVER: u32 = 1;

#[repr(u32)]
#[allow(dead_code)]
pub enum MountProc {
    NULL = 0,
    MNT = 1,
    DUMP = 2,
    UMNT = 3,
    UMNTALL = 4,
    EXPORT = 5,
}

pub(super) struct Mount {
    rpc: Rpc,
}

impl Mount {
    pub async fn lookup_port(bind: &mut Bind) -> Result<u16> {
        bind.lookup(MOUNTPROG, MOUNTVER, bind::Protocol::UDP).await
    }

    pub async fn connect(ip: IpAddr, port: u16) -> Result<Mount> {
        let rpc = Rpc::connect(SocketAddr::new(ip, port)).await?;
        Ok(Mount { rpc })
    }

    pub async fn mount(&mut self, path: &str) -> Result<FileHandle> {
        let path_vec: Vec<_> = path.encode_utf16().collect();
        let mut c = Cursor::new(Vec::<u8>::with_capacity(path_vec.len() * 2));
        for point in path_vec {
            c.write_u16::<LittleEndian>(point)?;
        }
        let status: xdr::FHStatus = self
            .rpc
            .call(
                MOUNTPROG,
                MOUNTVER,
                MountProc::MNT as u32,
                &xdr::DirPath(c.into_inner()),
            )
            .await?;

        match status {
            xdr::FHStatus::Const0(handle) => Ok(handle.0),
            _ => Err(anyhow!("mount failed for unkown reason")),
        }
    }

    fn mount_list_to_vec(list: &Option<Box<xdr::ExportList>>, v: &mut Vec<String>) {
        if let Some(ref m) = list {
            let raw_path_u8 = m.fileSystem.0.clone();
            if raw_path_u8.len() % 2 != 0 {
                // XXX: log error
                return;
            }
            let raw_path: Vec<u16> = raw_path_u8
                .chunks(2)
                .map(|b| (b[0] as u16) + ((b[1] as u16) << 8))
                .collect();
            let path = String::from_utf16_lossy(&raw_path);
            v.push(path);
            Self::mount_list_to_vec(&m.next, v);
        }
    }

    pub async fn exports(&mut self) -> Result<Vec<String>> {
        let mounts: xdr::ExportListRes = self
            .rpc
            .call(MOUNTPROG, MOUNTVER, MountProc::EXPORT as u32, &NoneParam {})
            .await?;

        let mut exports = Vec::new();

        Self::mount_list_to_vec(&mounts.next, &mut exports);

        Ok(exports)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::super::bind::{Bind, Protocol};
    use super::*;

    #[tokio::test]
    async fn test_loopkup() {
        if false {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 35));
            let mut bind = Bind::connect(ip).await.unwrap();
            let port = bind
                .lookup(MOUNTPROG, MOUNTVER, Protocol::UDP)
                .await
                .unwrap();
            println!("{:?}", port);
            let mut mount = Mount::connect(ip, port).await.unwrap();
            mount.exports().await.ok();
            mount.mount("/C/").await.unwrap();
        }
    }
}
