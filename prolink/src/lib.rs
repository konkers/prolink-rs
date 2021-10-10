use std::{convert::TryInto, io::Write};

use anyhow::{anyhow, Result};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    number::complete::{be_u16, be_u32, be_u8},
    IResult,
};

struct PacketHeader {
    name: String,
    proto_ver: u8,
    len: u16,
}

const HEADER: &'static [u8] = &[0x51, 0x73, 0x70, 0x74, 0x31, 0x57, 0x6d, 0x4a, 0x4f, 0x4c];

fn header(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, _) = tag(HEADER)(i)?;
    Ok((i, ()))
}

fn device_name(i: &[u8]) -> IResult<&[u8], String> {
    let (i, raw_name) = take(20usize)(i)?;
    let name = String::from_utf8_lossy(raw_name);
    let name = name.trim_end_matches('\0');

    Ok((i, name.into()))
}

fn negotiation_header(pkt_type: u8) -> impl Fn(&[u8]) -> IResult<&[u8], PacketHeader> {
    move |i: &[u8]| -> IResult<&[u8], PacketHeader> {
        let (i, _) = header(i)?;
        let (i, _) = tag(&[pkt_type, 0x00])(i)?;
        let (i, name) = device_name(i)?;
        let (i, _) = tag(&[0x01])(i)?;
        let (i, proto_ver) = be_u8(i)?;
        let (i, len) = be_u16(i)?;
        Ok((
            i,
            PacketHeader {
                name,
                proto_ver,
                len,
            },
        ))
    }
}

fn mac_addr(i: &[u8]) -> IResult<&[u8], [u8; 6]> {
    let (i, mac_addr) = take(6usize)(i)?;
    Ok((i, mac_addr.try_into().unwrap()))
}

fn ip_addr(i: &[u8]) -> IResult<&[u8], [u8; 4]> {
    let (i, ip_addr) = take(4usize)(i)?;
    Ok((i, ip_addr.try_into().unwrap()))
}

fn write_device_name(w: &mut dyn Write, name: &String) -> std::io::Result<()> {
    let mut name_buf = [0u8; 20];
    (&mut name_buf as &mut [u8]).write(name.as_bytes())?;
    w.write_all(&name_buf)?;

    Ok(())
}

fn write_header(
    w: &mut dyn Write,
    pkt_type: u8,
    name: &String,
    proto_ver: u8,
    pkt_len: u16,
) -> std::io::Result<()> {
    w.write_all(HEADER)?;
    w.write_u8(pkt_type)?;
    w.write_u8(0x0)?;

    write_device_name(w, name)?;

    w.write_u8(0x01)?;
    w.write_u8(proto_ver)?; // CDJ-3000s have a 3 here.

    // packet length
    w.write_u16::<BigEndian>(pkt_len)?;
    Ok(())
}

#[derive(Debug, PartialEq)]
pub struct AnnouncePacket {
    pub name: String,
    pub proto_ver: u8,
}

impl AnnouncePacket {
    pub fn write(&self, w: &mut dyn Write) -> std::io::Result<()> {
        let len = if self.proto_ver == 3 { 0x26 } else { 0x25 };
        write_header(w, 0xa, &self.name, self.proto_ver, len)?;
        w.write_u8(0x01)?;
        if self.proto_ver == 3 {
            w.write_u8(0x00)?;
        }

        Ok(())
    }
    pub fn parse(i: &[u8]) -> IResult<&[u8], Packet> {
        let (i, hdr) = negotiation_header(0x0a)(i)?;
        let (i, _) = tag(&[0x01])(i)?;
        Ok((
            i,
            Packet::Announce(AnnouncePacket {
                name: hdr.name,
                proto_ver: hdr.proto_ver,
            }),
        ))
    }
}

#[derive(Debug, PartialEq)]
pub struct DeviceNumClaim1Packet {
    pub name: String,
    pub proto_ver: u8,
    pub pkt_num: u8,
    pub mac_addr: [u8; 6],
}

impl DeviceNumClaim1Packet {
    pub fn write(&self, w: &mut dyn Write) -> std::io::Result<()> {
        write_header(w, 0x0, &self.name, self.proto_ver, 0x2c)?;
        w.write_u8(self.pkt_num)?;
        w.write_u8(0x01)?;
        w.write_all(&self.mac_addr)?;
        Ok(())
    }

    pub fn parse(i: &[u8]) -> IResult<&[u8], Packet> {
        let (i, hdr) = negotiation_header(0x00)(i)?;
        let (i, pkt_num) = be_u8(i)?;
        let (i, _) = tag(&[0x01])(i)?;
        let (i, mac_addr) = mac_addr(i)?;

        Ok((
            i,
            Packet::DeviceNumClaim1(DeviceNumClaim1Packet {
                name: hdr.name,
                proto_ver: hdr.proto_ver,
                pkt_num,
                mac_addr,
            }),
        ))
    }
}

#[derive(Debug, PartialEq)]
pub struct DeviceNumClaim2Packet {
    pub name: String,
    pub proto_ver: u8,
    pub ip_addr: [u8; 4],
    pub mac_addr: [u8; 6],
    pub device_num: u8,
    pub pkt_num: u8,
    pub auto_assign: bool,
}

impl DeviceNumClaim2Packet {
    pub fn write(&self, w: &mut dyn Write) -> std::io::Result<()> {
        write_header(w, 0x2, &self.name, self.proto_ver, 0x32)?;

        w.write_all(&self.ip_addr)?;
        w.write_all(&self.mac_addr)?;

        w.write_u8(self.device_num)?;
        w.write_u8(self.pkt_num)?;
        w.write_u8(01)?;
        w.write_u8(if self.auto_assign { 0x01 } else { 0x02 })?;
        Ok(())
    }

    pub fn parse(i: &[u8]) -> IResult<&[u8], Packet> {
        let (i, hdr) = negotiation_header(0x02)(i)?;
        let (i, ip_addr) = ip_addr(i)?;
        let (i, mac_addr) = mac_addr(i)?;
        let (i, device_num) = be_u8(i)?;
        let (i, pkt_num) = be_u8(i)?;
        let (i, _) = tag(&[0x01])(i)?;
        let (i, auto) = be_u8(i)?;

        Ok((
            i,
            Packet::DeviceNumClaim2(DeviceNumClaim2Packet {
                name: hdr.name,
                proto_ver: hdr.proto_ver,
                ip_addr,
                mac_addr,
                device_num,
                pkt_num,
                auto_assign: auto == 0x01,
            }),
        ))
    }
}

#[derive(Debug, PartialEq)]
pub struct DeviceNumClaim3Packet {
    pub name: String,
    pub proto_ver: u8,
    pub device_num: u8,
    pub pkt_num: u8,
}

impl DeviceNumClaim3Packet {
    pub fn write(&self, w: &mut dyn Write) -> std::io::Result<()> {
        write_header(w, 0x4, &self.name, self.proto_ver, 0x26)?;

        w.write_u8(self.device_num)?;
        w.write_u8(self.pkt_num)?;
        Ok(())
    }

    pub fn parse(i: &[u8]) -> IResult<&[u8], Packet> {
        let (i, hdr) = negotiation_header(0x04)(i)?;
        let (i, device_num) = be_u8(i)?;
        let (i, pkt_num) = be_u8(i)?;

        Ok((
            i,
            Packet::DeviceNumClaim3(DeviceNumClaim3Packet {
                name: hdr.name,
                proto_ver: hdr.proto_ver,
                device_num,
                pkt_num,
            }),
        ))
    }
}

#[derive(Debug, PartialEq)]
pub struct KeepAlivePacket {
    pub name: String,
    pub proto_ver: u8,
    pub device_num: u8,
    pub device_type: u8,
    pub mac_addr: [u8; 6],
    pub ip_addr: [u8; 4],
    pub peers_seen: u8,
    pub unknown_35: u8,
}

impl KeepAlivePacket {
    pub fn write(&self, w: &mut dyn Write) -> std::io::Result<()> {
        write_header(w, 0x6, &self.name, self.proto_ver, 0x36)?;

        w.write_u8(self.device_num)?;

        w.write_u8(self.device_type)?;

        w.write_all(&self.mac_addr)?;
        w.write_all(&self.ip_addr)?;

        w.write_all(&[self.peers_seen, 0x00, 0x00, 0x00, 0x01, self.unknown_35])?;

        Ok(())
    }

    pub fn parse(i: &[u8]) -> IResult<&[u8], Packet> {
        let (i, hdr) = negotiation_header(0x06)(i)?;
        let (i, device_num) = be_u8(i)?;
        let (i, device_type) = be_u8(i)?;
        let (i, mac_addr) = mac_addr(i)?;
        let (i, ip_addr) = ip_addr(i)?;
        let (i, peers_seen) = be_u8(i)?;
        let (i, _) = tag(&[0x00, 0x00, 0x00, 0x01])(i)?;
        let (i, unknown_35) = be_u8(i)?;

        Ok((
            i,
            Packet::KeepAlive(KeepAlivePacket {
                name: hdr.name,
                proto_ver: hdr.proto_ver,
                device_num,
                device_type,
                mac_addr,
                ip_addr,
                peers_seen,
                unknown_35,
            }),
        ))
    }
}

#[derive(Debug, PartialEq)]
pub struct BeatPacket {
    pub name: String,
    pub device_num: u8,
    pub next_beat: u32,
    pub second_beat: u32,
    pub next_bar: u32,
    pub fourth_beat: u32,
    pub second_bar: u32,
    pub eighth_beat: u32,
    pub pitch: f32,
    pub bpm: f32,
    pub beat: u8,
}

impl BeatPacket {
    pub fn parse(i: &[u8]) -> IResult<&[u8], Packet> {
        let (i, _) = header(i)?;
        let (i, _) = tag(&[0x28])(i)?; // TODO: make enum
        let (i, name) = device_name(i)?;
        let (i, _) = tag(&[0x01, 0x00])(i)?; // TODO: make enum
        let (i, device_num) = be_u8(i)?;
        let (i, _) = be_u16(i)?; // length should be 0x003c.
        let (i, next_beat) = be_u32(i)?;
        let (i, second_beat) = be_u32(i)?;
        let (i, next_bar) = be_u32(i)?;
        let (i, fourth_beat) = be_u32(i)?;
        let (i, second_bar) = be_u32(i)?;
        let (i, eighth_beat) = be_u32(i)?;
        let (i, _) = take(24usize)(i)?; // padding, should be 0xff.
        let (i, pitch_raw) = be_u32(i)?;
        let pitch = (pitch_raw as f32 - 0x100000 as f32) / 0x100000 as f32 * 100.0;
        let (i, _) = take(2usize)(i)?; // padding, should be 0x00.
        let (i, bpm_raw) = be_u16(i)?;
        let bpm = bpm_raw as f32 / 100.0;
        let (i, beat) = be_u8(i)?;
        let (i, _) = take(2usize)(i)?; // padding, should be 0x00.
        let (i, _) = be_u8(i)?; // repeated device ID.

        Ok((
            i,
            Packet::Beat(BeatPacket {
                name,
                device_num,
                next_beat,
                second_beat,
                next_bar,
                fourth_beat,
                second_bar,
                eighth_beat,
                pitch,
                bpm,
                beat,
            }),
        ))
    }
}

#[derive(Debug, PartialEq)]
pub enum Packet {
    Announce(AnnouncePacket),
    DeviceNumClaim1(DeviceNumClaim1Packet),
    DeviceNumClaim2(DeviceNumClaim2Packet),
    DeviceNumClaim3(DeviceNumClaim3Packet),
    KeepAlive(KeepAlivePacket),
    Beat(BeatPacket),
}

impl Packet {
    pub fn parse(data: &[u8]) -> Result<Packet> {
        let (i, pkt) = alt((
            AnnouncePacket::parse,
            DeviceNumClaim1Packet::parse,
            DeviceNumClaim2Packet::parse,
            DeviceNumClaim3Packet::parse,
            KeepAlivePacket::parse,
            BeatPacket::parse,
        ))(data)
        .map_err(|e| anyhow!("Error parsing packet: {}", e))?;
        if !i.is_empty() {
            return Err(anyhow!("packet has extra data {:x?}", i));
        }

        Ok(pkt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_header() {
        assert!(header(&[0u8]).is_err());
        assert_eq!(
            header(&[0x51, 0x73, 0x70, 0x74, 0x31, 0x57, 0x6d, 0x4a, 0x4f, 0x4c]),
            Ok((&[][..], ()))
        );
    }

    #[test]
    fn test_announce() {
        let test_cases = [
            (
                &[
                    0x51, 0x73, 0x70, 0x74, 0x31, 0x57, /* Qspt1W */
                    0x6d, 0x4a, 0x4f, 0x4c, 0x0a, 0x00, 0x43, 0x44, /* mJOL..CD */
                    0x4a, 0x2d, 0x39, 0x30, 0x30, 0x00, 0x00, 0x00, /* J-900... */
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
                    0x00, 0x00, 0x01, 0x02, 0x00, 0x25, 0x01, /* .....%. */
                ][..],
                AnnouncePacket {
                    name: "CDJ-900".to_string(),
                    proto_ver: 2,
                },
            ),
            (
                &[
                    0x51, 0x73, 0x70, 0x74, 0x31, 0x57, /* Qspt1W */
                    0x6d, 0x4a, 0x4f, 0x4c, 0x0a, 0x00, 0x43, 0x44, /* mJOL..CD */
                    0x4a, 0x2d, 0x33, 0x30, 0x30, 0x30, 0x00, 0x00, /* J-3000.. */
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
                    0x00, 0x00, 0x01, 0x03, 0x00, 0x26, 0x01, 0x00, /* .....&.. */
                ],
                AnnouncePacket {
                    name: "CDJ-3000".to_string(),
                    proto_ver: 3,
                },
            ),
        ];

        for (data, pkt) in test_cases {
            let mut c = std::io::Cursor::new(Vec::new());
            pkt.write(&mut c).unwrap();
            let v = c.into_inner();

            if pkt.proto_ver == 3 {
                assert_eq!(v.len(), 0x26);
            } else {
                assert_eq!(v.len(), 0x25);
            }
            assert_eq!(v.as_slice(), data);

            let (_, parsed) = AnnouncePacket::parse(data).unwrap();
            assert_eq!(parsed, Packet::Announce(pkt));
        }
    }

    #[test]
    fn test_claim1() {
        let test_cases = [
            (
                &[
                    0x51, 0x73, 0x70, 0x74, 0x31, 0x57, /* Qspt1W */
                    0x6d, 0x4a, 0x4f, 0x4c, 0x00, 0x00, 0x43, 0x44, /* mJOL..CD */
                    0x4a, 0x2d, 0x39, 0x30, 0x30, 0x00, 0x00, 0x00, /* J-900... */
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
                    0x00, 0x00, 0x01, 0x02, 0x00, 0x2c, 0x01, 0x01, /* .....,.. */
                    0x00, 0xe0, 0x36, 0xd2, 0x68, 0xf8, /* ..6.h. */
                ],
                DeviceNumClaim1Packet {
                    name: "CDJ-900".to_string(),
                    proto_ver: 2,
                    pkt_num: 1,
                    mac_addr: [0x00, 0xe0, 0x36, 0xd2, 0x68, 0xf8],
                },
            ),
            (
                &[
                    0x51, 0x73, 0x70, 0x74, 0x31, 0x57, /* Qspt1W */
                    0x6d, 0x4a, 0x4f, 0x4c, 0x00, 0x00, 0x43, 0x44, /* mJOL..CD */
                    0x4a, 0x2d, 0x33, 0x30, 0x30, 0x30, 0x00, 0x00, /* J-3000.. */
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
                    0x00, 0x00, 0x01, 0x03, 0x00, 0x2c, 0x03, 0x01, /* .....,.. */
                    0xc8, 0x3d, 0xfc, 0x0b, 0xf5, 0x1f, /* .=.... */
                ],
                DeviceNumClaim1Packet {
                    name: "CDJ-3000".to_string(),
                    proto_ver: 3,
                    pkt_num: 3,
                    mac_addr: [0xc8, 0x3d, 0xfc, 0x0b, 0xf5, 0x1f],
                },
            ),
        ];

        for (data, pkt) in test_cases {
            let mut c = std::io::Cursor::new(Vec::new());
            pkt.write(&mut c).unwrap();
            let v = c.into_inner();

            assert_eq!(v.len(), 0x2c);
            assert_eq!(v.as_slice(), data);

            let (_, parsed) = DeviceNumClaim1Packet::parse(data).unwrap();
            assert_eq!(parsed, Packet::DeviceNumClaim1(pkt));
        }
    }

    #[test]
    fn test_claim2() {
        let test_cases = [
            (
                &[
                    0x51, 0x73, 0x70, 0x74, 0x31, 0x57, /* Qspt1W */
                    0x6d, 0x4a, 0x4f, 0x4c, 0x02, 0x00, 0x43, 0x44, /* mJOL..CD */
                    0x4a, 0x2d, 0x39, 0x30, 0x30, 0x00, 0x00, 0x00, /* J-900... */
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
                    0x00, 0x00, 0x01, 0x02, 0x00, 0x32, 0xc0, 0xa8, /* .....2.. */
                    0x01, 0xf7, 0x00, 0xe0, 0x36, 0xd2, 0x68, 0xf8, /* ....6.h. */
                    0x03, 0x01, 0x01, 0x02, /* .... */
                ],
                DeviceNumClaim2Packet {
                    name: "CDJ-900".to_string(),
                    proto_ver: 2,
                    ip_addr: [192, 168, 1, 247],
                    mac_addr: [0x00, 0xe0, 0x36, 0xd2, 0x68, 0xf8],
                    device_num: 3,
                    pkt_num: 1,
                    auto_assign: false,
                },
            ),
            (
                &[
                    0x51, 0x73, 0x70, 0x74, 0x31, 0x57, /* .{Qspt1W */
                    0x6d, 0x4a, 0x4f, 0x4c, 0x02, 0x00, 0x43, 0x44, /* mJOL..CD */
                    0x4a, 0x2d, 0x33, 0x30, 0x30, 0x30, 0x00, 0x00, /* J-3000.. */
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
                    0x00, 0x00, 0x01, 0x03, 0x00, 0x32, 0xc0, 0xa8, /* .....2.. */
                    0x01, 0xf3, 0xc8, 0x3d, 0xfc, 0x0b, 0xf5, 0x1f, /* ...=.... */
                    0x02, 0x01, 0x01, 0x02, /* .... */
                ],
                DeviceNumClaim2Packet {
                    name: "CDJ-3000".to_string(),
                    proto_ver: 3,
                    ip_addr: [192, 168, 1, 243],
                    mac_addr: [0xc8, 0x3d, 0xfc, 0x0b, 0xf5, 0x1f],
                    device_num: 2,
                    pkt_num: 1,
                    auto_assign: false,
                },
            ),
        ];

        for (data, pkt) in test_cases {
            let mut c = std::io::Cursor::new(Vec::new());
            pkt.write(&mut c).unwrap();
            let v = c.into_inner();

            assert_eq!(v.len(), 0x32);
            assert_eq!(v.as_slice(), data);

            let (_, parsed) = DeviceNumClaim2Packet::parse(data).unwrap();
            assert_eq!(parsed, Packet::DeviceNumClaim2(pkt));
        }
    }

    #[test]
    fn test_claim3() {
        let test_cases = [
            (
                &[
                    0x51, 0x73, 0x70, 0x74, 0x31, 0x57, /* Qspt1W */
                    0x6d, 0x4a, 0x4f, 0x4c, 0x04, 0x00, 0x43, 0x44, /* mJOL..CD */
                    0x4a, 0x2d, 0x39, 0x30, 0x30, 0x00, 0x00, 0x00, /* J-900... */
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
                    0x00, 0x00, 0x01, 0x02, 0x00, 0x26, 0x03, 0x02, /* .....&.. */
                ],
                DeviceNumClaim3Packet {
                    name: "CDJ-900".to_string(),
                    proto_ver: 2,
                    device_num: 3,
                    pkt_num: 2,
                },
            ),
            (
                &[
                    0x51, 0x73, 0x70, 0x74, 0x31, 0x57, /* Qspt1W */
                    0x6d, 0x4a, 0x4f, 0x4c, 0x04, 0x00, 0x43, 0x44, /* mJOL..CD */
                    0x4a, 0x2d, 0x33, 0x30, 0x30, 0x30, 0x00, 0x00, /* J-3000.. */
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
                    0x00, 0x00, 0x01, 0x03, 0x00, 0x26, 0x00, 0x01, /* .....&.. */
                ],
                DeviceNumClaim3Packet {
                    name: "CDJ-3000".to_string(),
                    proto_ver: 3,
                    device_num: 0, // huh?
                    pkt_num: 1,
                },
            ),
        ];
        for (data, pkt) in test_cases {
            let mut c = std::io::Cursor::new(Vec::new());
            pkt.write(&mut c).unwrap();
            let v = c.into_inner();

            assert_eq!(v.len(), 0x26);
            assert_eq!(v.as_slice(), data);

            let (_, parsed) = DeviceNumClaim3Packet::parse(data).unwrap();
            assert_eq!(parsed, Packet::DeviceNumClaim3(pkt));
        }
    }

    #[test]
    fn test_keep_alive() {
        let test_cases = [
            (
                &[
                    0x51, 0x73, 0x70, 0x74, 0x31, 0x57, /* Qspt1W */
                    0x6d, 0x4a, 0x4f, 0x4c, 0x06, 0x00, 0x43, 0x44, /* mJOL..CD */
                    0x4a, 0x2d, 0x33, 0x30, 0x30, 0x30, 0x00, 0x00, /* J-3000.. */
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
                    0x00, 0x00, 0x01, 0x03, 0x00, 0x36, 0x02, 0x01, /* .....6.. */
                    0xc8, 0x3d, 0xfc, 0x0b, 0xf5, 0x1f, 0xc0, 0xa8, /* .=...... */
                    0x01, 0xf3, 0x01, 0x00, 0x00, 0x00, 0x01, 0x24, /* .......$ */
                ],
                KeepAlivePacket {
                    name: "CDJ-3000".to_string(),
                    proto_ver: 3,
                    device_num: 2,
                    device_type: 1,
                    mac_addr: [0xc8, 0x3d, 0xfc, 0x0b, 0xf5, 0x1f],
                    ip_addr: [192, 168, 1, 243],
                    peers_seen: 1,
                    unknown_35: 0x24,
                },
            ),
            (
                &[
                    0x51, 0x73, 0x70, 0x74, 0x31, 0x57, /* Qspt1W */
                    0x6d, 0x4a, 0x4f, 0x4c, 0x06, 0x00, 0x43, 0x44, /* mJOL..CD */
                    0x4a, 0x2d, 0x39, 0x30, 0x30, 0x00, 0x00, 0x00, /* J-900... */
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
                    0x00, 0x00, 0x01, 0x02, 0x00, 0x36, 0x02, 0x02, /* .....6.. */
                    0x00, 0xe0, 0x36, 0xd2, 0x68, 0xf8, 0xc0, 0xa8, /* ..6.h... */
                    0x01, 0xf7, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, /* ........ */
                ],
                KeepAlivePacket {
                    name: "CDJ-900".to_string(),
                    proto_ver: 2,
                    device_num: 2,
                    device_type: 2,
                    mac_addr: [0x00, 0xe0, 0x36, 0xd2, 0x68, 0xf8],
                    ip_addr: [192, 168, 1, 247],
                    peers_seen: 1,
                    unknown_35: 0x00,
                },
            ),
        ];

        for (data, pkt) in test_cases {
            let mut c = std::io::Cursor::new(Vec::new());
            pkt.write(&mut c).unwrap();
            let v = c.into_inner();

            assert_eq!(v.len(), 0x36);
            assert_eq!(v.as_slice(), data);

            let (_, parsed) = KeepAlivePacket::parse(data).unwrap();
            assert_eq!(parsed, Packet::KeepAlive(pkt));
        }
    }
}
