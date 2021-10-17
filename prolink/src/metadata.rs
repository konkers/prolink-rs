use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::anyhow;
use bytes::{Buf, BytesMut};
use num_traits::FromPrimitive;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::message::Track;
use crate::Result;

mod encoding;

use encoding::{Field, MenuItemType, Message, Packet};

const METADATA_PORT_LOOKUP_PORT: u16 = 12523;

pub(crate) async fn get_metadata_port(ip: &[u8; 4]) -> Result<u16> {
    let addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
        METADATA_PORT_LOOKUP_PORT,
    );

    let mut stream = TcpStream::connect(addr).await?;

    let msg = b"\x00\x00\x00\x0fRemoteDBServer\x00";

    stream.write_all(msg).await?;
    let port = stream.read_u16().await?;

    Ok(port)
}

pub(crate) async fn get_metadata(
    our_device_num: u8,
    track: &mut Track,
    ip: &[u8; 4],
    port: u16,
) -> Result<()> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), port);

    let mut conn = MetadataConnection::connect(&addr, our_device_num).await?;

    // Metadata Request
    conn.send_message(
        0x2002,
        vec![
            Field::dmst(our_device_num, 0x1, track.track_slot, track.track_type),
            Field::U32(track.rekordbox_id),
        ],
    )
    .await?;

    let response = conn.read_message().await?;
    if response.args.len() != 2 || response.args[0] != Field::U32(0x2002) || response.ty != 0x4000 {
        return Err(anyhow!("can't find metadata for tack").into());
    }
    let num_fields = match response.args[1] {
        Field::U32(n) => n,
        _ => {
            return Err(anyhow!("wrong field type in media request reponse").into());
        }
    };

    // Render Menu Request
    conn.send_message(
        0x3000,
        vec![
            Field::dmst(our_device_num, 0x1, track.track_slot, track.track_type),
            Field::U32(0x0),        // offset
            Field::U32(num_fields), // limit
            Field::U32(0x0),
            Field::U32(num_fields), // total
            Field::U32(0x0),
        ],
    )
    .await?;

    let mut artwork_id = None;
    loop {
        let response = conn.read_message().await?;

        if response.ty == 0x4201 {
            break;
        }

        if response.ty == 0x4101 {
            let item_type_raw = response.arg_u32(6)?;
            let val = response.arg_string(3)?;
            if let Some(item_type) = MenuItemType::from_u32(item_type_raw) {
                track.metadata.insert(format!("{}", item_type), val.clone());
                if item_type == MenuItemType::TrackTitle {
                    let id = response.arg_u32(8)?;
                    if id > 0 {
                        artwork_id = Some(id);
                    }
                }
            }
        }
    }

    if let Some(id) = artwork_id {
        // Track Artwork
        conn.send_message(
            0x2003,
            vec![
                Field::dmst(our_device_num, 0x8, track.track_slot, track.track_type),
                Field::U32(id),
            ],
        )
        .await?;
        let response = conn.read_message().await?;
        if response.ty == 0x4002 && response.args.len() == 4 {
            track.artwork = Some(response.arg_blob(3)?.clone());
        }
    }

    Ok(())
}

struct MetadataConnection {
    stream: TcpStream,
    buf: BytesMut,
    tx_id: u32,
}

impl MetadataConnection {
    async fn connect(addr: &SocketAddr, our_device_num: u8) -> Result<MetadataConnection> {
        let mut stream = TcpStream::connect(addr).await?;

        let msg = Packet::new().with_field(Field::U32(0x1)).to_bytes()?;

        stream.write_all(&msg).await?;
        let mut buf = [0; 4096];
        let len = stream.read(&mut buf).await?;

        if buf[0..len] != msg {
            return Err(anyhow!("did not get connection reply from metadata server").into());
        }

        let mut msg_buf = Vec::new();

        // Initial Handshake
        msg_buf.clear();
        Message::new(0xfffffffe, 0x0, vec![Field::U32(our_device_num as u32)])?
            .encode(&mut msg_buf)?;
        stream.write_all(&msg_buf).await?;

        let mut conn = MetadataConnection {
            stream,
            buf: BytesMut::with_capacity(4096),
            tx_id: 0,
        };

        let response = conn.read_message().await?;
        assert_eq!(response.args[0], Field::U32(0x0));

        Ok(conn)
    }

    async fn send_message(&mut self, ty: u16, args: Vec<Field>) -> Result<()> {
        self.tx_id += 1;
        let mut msg_buf = Vec::new();
        Message::new(self.tx_id, ty, args)?.encode(&mut msg_buf)?;

        self.stream.write_all(&msg_buf).await?;
        Ok(())
    }

    // Using the framing patern from https://tokio.rs/tokio/tutorial/framing
    async fn read_message(&mut self) -> Result<Message> {
        loop {
            // Parse a message that is already in the buffer.
            if let Some(msg) = self.parse_message()? {
                return Ok(msg);
            }

            // Read more data into the buffer if we don't have enough for a
            // message.
            if 0 == self.stream.read_buf(&mut self.buf).await? {
                // The remote closed the connection. For this to be
                // a clean shutdown, there should be no data in the
                // read buffer. If there is, this means that the
                // peer closed the socket while sending a frame.
                return Err(anyhow!("connection reset by peer").into());
            }
        }
    }

    fn parse_message(&mut self) -> Result<Option<Message>> {
        let buf = &self.buf[..];
        let (len, msg) = match Message::parse(buf) {
            Ok((rest, msg)) => (buf.len() - rest.len(), msg),
            Err(nom::Err::Incomplete(_)) => return Ok(None),
            Err(e) => return Err(anyhow!("error parsing message {}", e).into()),
        };
        self.buf.advance(len);
        return Ok(Some(msg));
    }
}
