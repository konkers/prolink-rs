use std::net::{IpAddr, SocketAddr};

use super::rpc::{NoneParam, Rpc};
use crate::Result;

#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    unused_assignments,
    deprecated
)]

pub(super) mod xdr {

    include!(concat!(env!("OUT_DIR"), "/bind_xdr.rs"));
}

const RPCBPROG: u32 = 100000;
const RPCBVERS: u32 = 2;

#[repr(u32)]
enum RpcbProg {
    NULL = 0,
    SET = 1,
    UNSET = 2,
    GETPORT = 3,
    DUMP = 4,
    CALLIT = 5,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub(super) enum Protocol {
    TCP = xdr::IPPROTO_TCP as u32,
    UDP = xdr::IPPROTO_UDP as u32,
}

pub(super) type Mapping = xdr::mapping;

pub(super) struct Bind {
    rpc: Rpc,
}

impl Bind {
    pub async fn connect(ip: IpAddr) -> Result<Bind> {
        let rpc = Rpc::connect(SocketAddr::new(ip, xdr::PMAP_PORT as u16)).await?;
        Ok(Bind { rpc })
    }

    pub async fn lookup(&mut self, prog: u32, vers: u32, prot: Protocol) -> Result<u16> {
        let port: u32 = self
            .rpc
            .call(
                RPCBPROG,
                RPCBVERS,
                RpcbProg::GETPORT as u32,
                &xdr::mapping {
                    prog,
                    vers,
                    prot: prot as u32,
                    port: 0,
                },
            )
            .await?;

        Ok(port as u16)
    }

    pub async fn list(&mut self) -> Result<Vec<Mapping>> {
        let mut entry: xdr::pmaplist_ptr = self
            .rpc
            .call(RPCBPROG, RPCBVERS, RpcbProg::DUMP as u32, &NoneParam {})
            .await?;

        let mut mappings = Vec::new();

        loop {
            match entry {
                Some(m) => {
                    mappings.push(m.map.clone());
                    entry = m.next;
                }
                None => {
                    break;
                }
            }
        }

        Ok(mappings)
    }
}
