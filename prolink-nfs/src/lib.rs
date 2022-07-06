use std::{collections::HashMap, fs::File, net::IpAddr};

use anyhow::anyhow;
use bytes::Bytes;

mod bind;
mod mount;
mod nfs;
mod rpc;

pub use anyhow::Result;
use bind::Bind;
use mount::Mount;
use nfs::Nfs;

type FileHandle = [u8; 32];

pub struct NfsClient {
    mount: Mount,
    nfs: Nfs,
    mounts: HashMap<String, FileHandle>,
}

impl NfsClient {
    pub async fn connect(ip: IpAddr) -> Result<NfsClient> {
        let mut bind = Bind::connect(ip).await?;

        let mount_port = Mount::lookup_port(&mut bind).await?;
        let mount = Mount::connect(ip, mount_port).await?;

        let nfs_port = Nfs::lookup_port(&mut bind).await?;
        let nfs = Nfs::connect(ip, nfs_port).await?;

        Ok(NfsClient {
            mount,
            nfs,
            mounts: HashMap::new(),
        })
    }

    pub async fn exports(&mut self) -> Result<Vec<String>> {
        self.mount.exports().await
    }

    async fn get_mount<'a>(&mut self, path: &'a str) -> Result<(FileHandle, &'a str)> {
        for (mount_path, fh) in &self.mounts {
            if path.starts_with(mount_path) {
                let new_path = path.strip_prefix(mount_path).unwrap();
                return Ok((fh.clone(), new_path));
            }
        }

        let exports = self.mount.exports().await?;
        for export_path in &exports {
            if path.starts_with(export_path) {
                let fh = self.mount.mount(export_path).await?;
                self.mounts.insert(export_path.clone(), fh);
                return Ok((
                    self.mounts
                        .get(export_path)
                        .ok_or(anyhow!("Can't lookup just mounted filesystem"))?
                        .clone(),
                    path.strip_prefix(export_path).unwrap(),
                ));
            }
        }

        Err(anyhow!("Can't find export mount for {}", path))
    }

    pub async fn list_files(&mut self, path: &str) -> Result<Vec<String>> {
        let (mount_handle, path) = self.get_mount(path).await?;
        let dir_handle = self.nfs.lookup(&mount_handle, path).await?;
        self.nfs.readdir(&dir_handle).await
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use xdr_codec;

    #[test]
    fn test_nfs_read() {
        let mut data = Cursor::new(&include_bytes!("test-data/nfs-read.bin")[..]);
        let msg: rpc::xdr::rpc_msg = xdr_codec::unpack(&mut data).unwrap();

        // Assert RPC header is correct.
        assert_eq!(
            msg,
            rpc::xdr::rpc_msg {
                xid: 2864887188,
                body: rpc::xdr::msg_body::CALL(rpc::xdr::call_body {
                    rpcvers: 2,
                    prog: 100003,
                    vers: 2,
                    proc_: 6,
                    cred: rpc::xdr::opaque_auth {
                        flavor: rpc::xdr::auth_flavor::AUTH_SYS,
                        body: Vec::from(&b"\xa5\x9cu\x8d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..]),
                    },
                    verf: rpc::xdr::opaque_auth {
                        flavor: rpc::xdr::auth_flavor::AUTH_NONE,
                        body: Vec::from(&b""[..]),
                    }
                })
            }
        );

        let nfs_msg: nfs::xdr::ReadArgs = xdr_codec::unpack(&mut data).unwrap();
        assert_eq!(
            nfs_msg,
            nfs::xdr::ReadArgs {
                file: nfs::xdr::FHandle(
                    *b"\0\0\0\x05\0\0\0\x04\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                ),
                offset: 0x27c3800,
                count: 0x800,
                totalcount: 0
            }
        );

        assert_eq!(data.position() as usize, data.get_ref().len());
    }
}
