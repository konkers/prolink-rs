use std::{
    io::Cursor,
    net::{IpAddr, SocketAddr},
};

use anyhow::anyhow;
use byteorder::{BigEndian, LittleEndian, WriteBytesExt};

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

    pub async fn exports(&mut self) -> Result<Vec<String>> {
        let mounts: xdr::ExportListRes = self
            .rpc
            .call(MOUNTPROG, MOUNTVER, MountProc::EXPORT as u32, &NoneParam {})
            .await?;

        let mut exports = Vec::new();

        let mut mount_list = mounts.next;

        while mount_list.is_some() {
            if let Some(m) = mount_list {
                let raw_path = m.fileSystem.0;

                mount_list = m.next;
            }
        }

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
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 243));
        let mut bind = Bind::connect(ip).await.unwrap();
        let port = bind
            .lookup(MOUNTPROG, MOUNTVER, Protocol::UDP)
            .await
            .unwrap();
        println!("{:?}", port);
        let mut mount = Mount::connect(ip, port).await.unwrap();
        let list = mount.exports().await.ok();
        let list = mount.mount("/C/").await.unwrap();
    }
}
