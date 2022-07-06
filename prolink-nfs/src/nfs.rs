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
    include!(concat!(env!("OUT_DIR"), "/nfs_xdr.rs"));
}

pub const NFSPROG: u32 = 100003;
pub const NFSVER: u32 = 2;

#[repr(u32)]
enum NfsProc {
    NULL = 0,
    GETATTR = 1,
    SETATTR = 2,
    ROOT = 3,
    LOOKUP = 4,
    READLINK = 5,
    READ = 6,
    WRITE_CACHE = 7,
    WRITE = 8,
    CREATE = 9,
    REMOVE = 10,
    RENAME = 11,
    LINK = 12,
    SYMLINK = 13,
    MKDIR = 14,
    RMDIR = 15,
    READDIR = 16,
    STATFS = 17,
}

pub(super) struct Nfs {
    rpc: Rpc,
}

impl Nfs {
    pub async fn lookup_port(bind: &mut Bind) -> Result<u16> {
        bind.lookup(NFSPROG, NFSVER, bind::Protocol::UDP).await
    }

    pub async fn connect(ip: IpAddr, port: u16) -> Result<Nfs> {
        let rpc = Rpc::connect(SocketAddr::new(ip, port)).await?;
        Ok(Nfs { rpc })
    }

    pub async fn lookup(&mut self, mount: &FileHandle, path: &str) -> Result<FileHandle> {
        let path_vec: Vec<_> = path.encode_utf16().collect();
        let mut c = Cursor::new(Vec::<u8>::with_capacity(path_vec.len() * 2));
        for point in path_vec {
            c.write_u16::<LittleEndian>(point)?;
        }

        let status: xdr::DirOpRes = self
            .rpc
            .call(
                NFSPROG,
                NFSVER,
                NfsProc::LOOKUP as u32,
                &xdr::DirOpArgs {
                    dir: xdr::FHandle(*mount),
                    name: xdr::Filename(c.into_inner()),
                },
            )
            .await?;

        match status {
            xdr::DirOpRes::NFS_OK(body) => Ok(body.file.0),
            _ => Err(anyhow!("can't look up dir")),
        }
    }
    fn dir_list_to_vec(list: &Option<Box<xdr::Entry>>, v: &mut Vec<String>) {
        if let Some(ref m) = list {
            let raw_path_u8 = m.name.0.clone();
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
            Self::dir_list_to_vec(&m.next, v);
        }
    }
    pub async fn readdir(&mut self, dir: &FileHandle) -> Result<Vec<String>> {
        let status: xdr::ReadDirRes = self
            .rpc
            .call(
                NFSPROG,
                NFSVER,
                NfsProc::READDIR as u32,
                &xdr::ReadDirArgs {
                    dir: xdr::FHandle(*dir),
                    cookie: xdr::NFSCookie([0u8; xdr::COOKIESIZE as usize]),
                    count: 16552,
                },
            )
            .await?;
        match status {
            xdr::ReadDirRes::NFS_OK(bodies) => {
                let mut files = Vec::new();
                Self::dir_list_to_vec(&bodies.entries, &mut files);
                Ok(files)
            }
            _ => Err(anyhow!("read files in directory")),
        }
    }
}
