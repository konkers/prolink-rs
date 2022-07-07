use std::{io::Cursor, net::SocketAddr};

use anyhow::anyhow;
use pretty_hex::pretty_hex;
use tokio::net::{lookup_host, ToSocketAddrs, UdpSocket};
use xdr_codec::{Pack, Write};

use crate::Result;

#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    unused_assignments,
    deprecated
)]
pub(super) mod xdr {
    include!(concat!(env!("OUT_DIR"), "/rpc_xdr.rs"));
}

pub(super) struct NoneParam {}
impl<Out: xdr_codec::Write> Pack<Out> for NoneParam {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        Ok(0usize)
    }
}

const RPCVERS: u32 = 2;

pub(super) struct Rpc {
    socket: UdpSocket,
    addr: SocketAddr,
    xid: u32,
}

impl Rpc {
    pub async fn connect<A: ToSocketAddrs + std::fmt::Debug>(addr: A) -> Result<Rpc> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let addrs: Vec<SocketAddr> = lookup_host(&addr).await?.collect();
        if addrs.len() == 0 {
            return Err(anyhow!("can't lookup {:?}", addr).into());
        }

        Ok(Rpc {
            socket,
            addr: addrs[0],
            xid: 0,
        })
    }

    pub async fn call<
        P: xdr_codec::Pack<Cursor<Vec<u8>>>,
        R: xdr_codec::Unpack<Cursor<Vec<u8>>>,
    >(
        &mut self,
        prog: u32,
        vers: u32,
        proc: u32,
        payload: &P,
    ) -> Result<R> {
        let mut c: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let xid = self.encode_rpc(&mut c, prog, vers, proc)?;
        payload
            .pack(&mut c)
            .map_err(|e| anyhow!("error encoding payload: {}", e))?;

        let buf = c.into_inner();
        let size = self.socket.send_to(&buf, &self.addr).await?;
        if size != buf.len() {
            return Err(anyhow!("Incomplete write").into());
        }

        let mut buf = [0u8; 16 * 1024];
        let (len, _src) = self.socket.recv_from(&mut buf).await?;
        let mut c: Cursor<Vec<u8>> = Cursor::new(Vec::from(&buf[0..len]));

        let rpc_response: xdr::rpc_msg = xdr_codec::unpack(&mut c)
            .map_err(|e| anyhow!("error decoding rpc_msg response: {}", e))?;

        let reply = match rpc_response.body {
            xdr::msg_body::REPLY(r) => r,
            _ => {
                return Err(anyhow!("expected reply: {:?}", rpc_response).into());
            }
        };

        let reply = match reply {
            xdr::reply_body::MSG_ACCEPTED(r) => r,
            _ => {
                return Err(anyhow!("non-accepted reply: {:?}", reply).into());
            }
        };

        match reply.data {
            xdr::reply_data::SUCCESS => (),
            _ => {
                return Err(anyhow!("unsucessful call: {:?}", reply).into());
            }
        }

        let ret: R =
            xdr_codec::unpack(&mut c).map_err(|e| anyhow!("error decoding response: {}", e))?;

        Ok(ret)
    }

    fn encode_rpc(
        &mut self,
        c: &mut Cursor<Vec<u8>>,
        prog: u32,
        vers: u32,
        proc: u32,
    ) -> Result<u32> {
        self.xid += 1;
        let msg = xdr::rpc_msg {
            xid: self.xid,
            body: xdr::msg_body::CALL(xdr::call_body {
                rpcvers: RPCVERS,
                prog,
                vers,
                proc_: proc,
                cred: xdr::opaque_auth {
                    flavor: xdr::auth_flavor::AUTH_SYS,
                    //body: Vec::from(&b"\xa5\x9cu\x8d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..]),
                    body: Vec::from(&b"\x95\x7b\x87\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..]),
                },
                verf: xdr::opaque_auth {
                    flavor: xdr::auth_flavor::AUTH_NONE,
                    body: Vec::from(&b""[..]),
                },
            }),
        };

        msg.pack(c)
            .map_err(|e| anyhow!("error encoding rpc: {}", e))?;

        Ok(self.xid)
    }
}
