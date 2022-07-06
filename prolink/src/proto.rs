use std::{convert::TryInto, fs, io::Write};

use anyhow::anyhow;
use byteorder::{BigEndian, WriteBytesExt};
use nom::{
    bytes::complete::{tag, take},
    error::context,
    number::complete::{be_u16, be_u24, be_u32, be_u8},
    IResult,
};
use nom_locate::LocatedSpan;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use pretty_hex::pretty_hex;

use crate::{ProlinkError, Result};

type Span<'a> = LocatedSpan<&'a [u8]>;

#[derive(FromPrimitive)]
#[repr(u8)]
enum PacketType {
    DeviceNumClaim1 = 0x00,
    DeviceNumClaim2 = 0x02,
    DeviceNumClaim3 = 0x04,
    KeepAlive = 0x06,
    AnnounceStatus = 0x0a, // Both announce and Status packet have 0xa packet types.
    Beat = 0x28,
}

struct PacketHeader {
    name: String,
    proto_ver: u8,
}

const HEADER: &'static [u8] = &[0x51, 0x73, 0x70, 0x74, 0x31, 0x57, 0x6d, 0x4a, 0x4f, 0x4c];

fn header(i: Span) -> IResult<Span, ()> {
    let (i, _) = tag(HEADER)(i)?;
    Ok((i, ()))
}

fn device_name(i: Span) -> IResult<Span, String> {
    let (i, raw_name) = take(20usize)(i)?;
    let name = String::from_utf8_lossy(&raw_name);
    let name = name.trim_end_matches('\0');

    Ok((i, name.into()))
}

fn negotiation_header(pkt_type: u8) -> impl Fn(Span) -> IResult<Span, PacketHeader> {
    move |i: Span| -> IResult<Span, PacketHeader> {
        let (i, _) = header(i)?;
        let (i, _) = tag(&[pkt_type, 0x00])(i)?;
        let (i, name) = device_name(i)?;
        let (i, _) = tag(&[0x01])(i)?;
        let (i, proto_ver) = be_u8(i)?;
        let (i, _len) = be_u16(i)?;
        Ok((i, PacketHeader { name, proto_ver }))
    }
}

fn mac_addr(i: Span) -> IResult<Span, [u8; 6]> {
    let (i, mac_addr) = take(6usize)(i)?;
    Ok((i, (*mac_addr.fragment()).try_into().unwrap()))
}

fn ip_addr(i: Span) -> IResult<Span, [u8; 4]> {
    let (i, ip_addr) = take(4usize)(i)?;
    Ok((i, (*ip_addr.fragment()).try_into().unwrap()))
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
        write_header(
            w,
            PacketType::AnnounceStatus as u8,
            &self.name,
            self.proto_ver,
            len,
        )?;
        w.write_u8(0x01)?;
        if self.proto_ver == 3 {
            w.write_u8(0x00)?;
        }

        Ok(())
    }
    pub fn parse(i: Span) -> IResult<Span, Packet> {
        let (i, hdr) = negotiation_header(PacketType::AnnounceStatus as u8)(i)?;
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
        write_header(
            w,
            PacketType::DeviceNumClaim1 as u8,
            &self.name,
            self.proto_ver,
            0x2c,
        )?;
        w.write_u8(self.pkt_num)?;
        w.write_u8(0x01)?;
        w.write_all(&self.mac_addr)?;
        Ok(())
    }

    pub fn parse(i: Span) -> IResult<Span, Packet> {
        let (i, hdr) = negotiation_header(PacketType::DeviceNumClaim1 as u8)(i)?;
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
        write_header(
            w,
            PacketType::DeviceNumClaim2 as u8,
            &self.name,
            self.proto_ver,
            0x32,
        )?;

        w.write_all(&self.ip_addr)?;
        w.write_all(&self.mac_addr)?;

        w.write_u8(self.device_num)?;
        w.write_u8(self.pkt_num)?;
        w.write_u8(01)?;
        w.write_u8(if self.auto_assign { 0x01 } else { 0x02 })?;
        Ok(())
    }

    pub fn parse(i: Span) -> IResult<Span, Packet> {
        let (i, hdr) = negotiation_header(PacketType::DeviceNumClaim2 as u8)(i)?;
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
        write_header(
            w,
            PacketType::DeviceNumClaim3 as u8,
            &self.name,
            self.proto_ver,
            0x26,
        )?;

        w.write_u8(self.device_num)?;
        w.write_u8(self.pkt_num)?;
        Ok(())
    }

    pub fn parse(i: Span) -> IResult<Span, Packet> {
        let (i, hdr) = negotiation_header(PacketType::DeviceNumClaim3 as u8)(i)?;
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
        write_header(
            w,
            PacketType::KeepAlive as u8,
            &self.name,
            self.proto_ver,
            0x36,
        )?;

        w.write_u8(self.device_num)?;

        w.write_u8(self.device_type)?;

        w.write_all(&self.mac_addr)?;
        w.write_all(&self.ip_addr)?;

        w.write_all(&[self.peers_seen, 0x00, 0x00, 0x00, 0x01, self.unknown_35])?;

        Ok(())
    }

    pub fn parse(i: Span) -> IResult<Span, Packet> {
        let (i, hdr) = negotiation_header(PacketType::KeepAlive as u8)(i)?;
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
pub struct PlayerStatusExtraData0 {
    pub unknown_d4: [u8; 28],
    pub unknown_f4: [u8; 6],
    pub waveform_color: u8,
    pub unknown_fb: u16,
    pub waveform_pos: u8,
    pub unknown_fe: [u8; 31],
    pub buf_f: u8,
    pub buf_b: u8,
    pub buf_s: u8,
    pub unknown_120: [u8; 0x38],
    pub master_tempo: u8,
    pub unknown_159: [u8; 3],
    pub key: u32, // only 24 bits in packet
    pub unknown_15f: [u8; 5],
    pub key_shift: [u8; 8],
    pub unknown_16c: [u8; 0x288],
}

#[derive(Debug, PartialEq)]
pub struct PlayerStatusPacket {
    pub name: String,
    pub unknown_10: u8,
    pub device_num: u8,
    pub unknown_16: u8,
    pub active: u8,
    pub track_device: u8,
    pub track_slot: u8,
    pub track_type: u8,
    pub rekordbox_id: u32,
    pub track_num: u16,
    pub d_l: u8,
    pub unknown_38: [u8; 14],
    pub d_n: u16,
    pub unknown_48: [u8; 32],
    pub usb_activity: u8,
    pub sd_activity: u8,
    pub u_l: u8,
    pub s_l: u8,
    pub link_available: u8,
    pub unknown_78: u8,
    pub play_mode: u8,
    pub firmware_ver: String,
    pub sync_n: u32,
    pub flags: u8,
    pub unknown_8b: u8,
    pub play_state: u8,
    pub pitch_1: u32,
    pub m_v: u16,
    pub bpm: u16,
    pub unknown_94: u32,
    pub pitch_2: u32,
    pub p_3: u8,
    pub m_m: u8,
    pub m_h: u8,
    pub beat: u32,
    pub cue: u16,
    pub bar_beat: u8,
    pub media_presence: u8,
    pub u_e: u8,
    pub s_e: u8,
    pub emergency_loop_active: u8,
    pub pitch_3: u32,
    pub pitch_4: u32,
    pub seq_num: u32,
    pub player_type: u8,
    pub unknown_cd: [u8; 3],
    pub extra0: Option<PlayerStatusExtraData0>,
}

impl PlayerStatusPacket {
    pub fn parse(i: Span) -> IResult<Span, Packet> {
        let (i, _) = header(i)?;
        let (i, _) = context("packet type", tag(&[PacketType::AnnounceStatus as u8]))(i)?; // TODO: make enum
        let (i, name) = device_name(i)?;
        let (i, _) = tag(&[0x01])(i)?;
        let (i, unknown_10) = be_u8(i)?;
        let (i, device_num) = be_u8(i)?;
        let (i, _pkt_len) = be_u16(i)?; // len
        let (i, _device_num2) = be_u8(i)?;
        let (i, _) = context("tag1", tag(&[0x00]))(i)?;
        let (i, unknown_16) = be_u8(i)?;

        let (i, active) = be_u8(i)?;
        let (i, track_device) = be_u8(i)?;
        let (i, track_slot) = be_u8(i)?;
        let (i, track_type) = be_u8(i)?;

        // 0x30
        let (i, _) = context("tag2", tag(&[0x00]))(i)?;
        let (i, rekordbox_id) = be_u32(i)?;
        let (i, _) = context("tag3", tag(&[0x00, 0x00]))(i)?;
        let (i, track_num) = be_u16(i)?;
        let (i, _) = context("tag4", tag(&[0x00, 0x00, 0x00]))(i)?;
        let (i, d_l) = be_u8(i)?;

        // 0x38
        let (i, unknown_38) = take(14usize)(i)?;

        // 0x46
        let (i, d_n) = be_u16(i)?;
        let (i, unknown_48) = take(32usize)(i)?;
        let (i, _) = context("tag6", tag(&[0x01, 0x00]))(i)?;

        // 0x6a
        let (i, usb_activity) = be_u8(i)?;
        let (i, sd_activity) = be_u8(i)?;
        let (i, _) = context("tag7", tag(&[0x00; 3]))(i)?;
        let (i, u_l) = be_u8(i)?;

        // 0x70
        let (i, _) = tag(&[0x00; 3])(i)?;
        let (i, s_l) = be_u8(i)?;
        let (i, _) = tag(&[0x00])(i)?;
        let (i, link_available) = be_u8(i)?;

        // 0x76
        let (i, _) = tag(&[0x00; 2])(i)?;
        let (i, unknown_78) = be_u8(i)?;
        let (i, _) = tag(&[0x00; 2])(i)?;
        let (i, play_mode) = be_u8(i)?;
        let (i, firmware_ver_raw) = take(4usize)(i)?;
        let firmware_ver = String::from_utf8_lossy(*firmware_ver_raw.fragment());
        let firmware_ver = firmware_ver.trim_end_matches('\0').to_string();

        // 0x80
        let (i, _) = tag(&[0x00; 4])(i)?;
        let (i, sync_n) = be_u32(i)?;
        let (i, _) = tag(&[0x00])(i)?;
        let (i, flags) = be_u8(i)?;
        let (i, unknown_8b) = be_u8(i)?;
        let (i, play_state) = be_u8(i)?;
        let (i, pitch_1) = be_u32(i)?;

        // 0x90
        let (i, m_v) = be_u16(i)?;
        let (i, bpm) = be_u16(i)?;
        let (i, unknown_94) = be_u32(i)?;
        let (i, pitch_2) = be_u32(i)?;
        let (i, _) = tag(&[0x00])(i)?;
        let (i, p_3) = be_u8(i)?;
        let (i, m_m) = be_u8(i)?;
        let (i, m_h) = be_u8(i)?;

        // 0xa0
        let (i, beat) = be_u32(i)?;
        let (i, cue) = be_u16(i)?;
        let (i, bar_beat) = be_u8(i)?;
        let (i, _) = tag(&[0x00; 9])(i)?;

        // 0xb0
        let (i, _) = tag(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])(i)?;
        let (i, media_presence) = be_u8(i)?;
        let (i, u_e) = be_u8(i)?;
        let (i, s_e) = be_u8(i)?;
        let (i, emergency_loop_active) = be_u8(i)?;
        let (i, _) = tag(&[0x00; 5])(i)?;

        // 0xc0
        let (i, pitch_3) = be_u32(i)?;
        let (i, pitch_4) = be_u32(i)?;
        let (i, seq_num) = be_u32(i)?;
        let (i, player_type) = be_u8(i)?;
        let (i, unknown_cd) = take(3usize)(i)?;

        let (i, extra0) = if player_type == 0x05 {
            (i, None)
        } else if player_type == 0x1f {
            // 0xd0
            let (i, _) = tag(&[0x12, 0x34, 0x56, 0x78])(i)?;
            let (i, unknown_d4) = take(28usize)(i)?;

            // 0xf0
            let (i, _) = tag(&[0x12, 0x34, 0x56, 0x78])(i)?;
            let (i, unknown_f4) = take(6usize)(i)?;
            let (i, waveform_color) = be_u8(i)?;
            let (i, unknown_fb) = be_u16(i)?;
            let (i, waveform_pos) = be_u8(i)?;
            let (i, unknown_fe) = take(31usize)(i)?;
            let (i, buf_f) = be_u8(i)?;
            let (i, buf_b) = be_u8(i)?;
            let (i, buf_s) = be_u8(i)?;

            // 0x120
            let (i, unknown_120) = take(0x38usize)(i)?;

            // 0x158
            let (i, master_tempo) = be_u8(i)?;
            let (i, unknown_159) = take(3usize)(i)?;
            let (i, key) = be_u24(i)?;

            // 0x160
            let (i, unknown_15f) = take(5usize)(i)?;
            let (i, key_shift) = take(8usize)(i)?;

            // 0x16c
            let (i, unknown_16c) = take(0x288usize)(i)?;
            (
                i,
                Some(PlayerStatusExtraData0 {
                    unknown_d4: (*unknown_d4.fragment()).try_into().unwrap(),
                    unknown_f4: (*unknown_f4.fragment()).try_into().unwrap(),
                    waveform_color,
                    unknown_fb,
                    waveform_pos,
                    unknown_fe: (*unknown_fe.fragment()).try_into().unwrap(),
                    buf_f,
                    buf_b,
                    buf_s,
                    unknown_120: (*unknown_120.fragment()).try_into().unwrap(),
                    master_tempo,
                    unknown_159: (*unknown_159.fragment()).try_into().unwrap(),
                    key,
                    unknown_15f: (*unknown_15f.fragment()).try_into().unwrap(),
                    key_shift: (*key_shift.fragment()).try_into().unwrap(),
                    unknown_16c: (*unknown_16c.fragment()).try_into().unwrap(),
                }),
            )
        } else {
            (i, None) // TODO: 2000nx2?
        };

        Ok((
            i,
            Packet::PlayerStatus(PlayerStatusPacket {
                name: name.to_string(),
                unknown_10,
                device_num,
                unknown_16,
                active,
                track_device,
                track_slot,
                track_type,
                rekordbox_id,
                track_num,
                d_l,
                unknown_38: (*unknown_38.fragment()).try_into().unwrap(),
                d_n,
                unknown_48: (*unknown_48.fragment()).try_into().unwrap(),
                usb_activity,
                sd_activity,
                u_l,
                s_l,
                link_available,
                unknown_78,
                play_mode,
                firmware_ver,
                sync_n,
                flags,
                unknown_8b,
                play_state,
                pitch_1,
                m_v,
                bpm,
                unknown_94,
                pitch_2,
                p_3,
                m_m,
                m_h,
                beat,
                cue,
                bar_beat,
                media_presence,
                u_e,
                s_e,
                emergency_loop_active,
                pitch_3,
                pitch_4,
                seq_num,
                player_type,
                unknown_cd: (*unknown_cd.fragment()).try_into().unwrap(),
                extra0,
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
    pub fn parse(i: Span) -> IResult<Span, Packet> {
        let (i, _) = header(i)?;
        let (i, _) = tag(&[PacketType::Beat as u8])(i)?; // TODO: make enum
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
    PlayerStatus(PlayerStatusPacket),
    Beat(BeatPacket),
}

impl Packet {
    pub fn parse_impl(data: Span) -> IResult<Span, Packet> {
        let (i, _) = header(data)?;
        let (i, packet_type) = be_u8(i)?;

        match FromPrimitive::from_u8(packet_type) {
            Some(PacketType::DeviceNumClaim1) => DeviceNumClaim1Packet::parse(data),
            Some(PacketType::DeviceNumClaim2) => DeviceNumClaim2Packet::parse(data),
            Some(PacketType::DeviceNumClaim3) => DeviceNumClaim3Packet::parse(data),
            Some(PacketType::KeepAlive) => KeepAlivePacket::parse(data),
            Some(PacketType::AnnounceStatus) => {
                // Announce and status packets share the same packet type.
                // Announce Packets like all port 5000 packets, have a 0x00
                // following the packet_type field.
                if data[0xb] == 0x0 {
                    AnnouncePacket::parse(data)
                } else {
                    PlayerStatusPacket::parse(data)
                }
            }
            Some(PacketType::Beat) => BeatPacket::parse(data),
            _ => Err(nom::Err::Error(nom::error::Error::new(
                i,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
    pub fn parse(data: &[u8]) -> Result<Packet> {
        let (i, pkt) = match Self::parse_impl(Span::new(data)) {
            Ok((i, pkt)) => (i, pkt),
            Err(e) => {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_millis();
                let path = format!("./bad-packets/bad-packet-{}.bin", timestamp);
                fs::write(&path, data)?;
                match e {
                    nom::Err::Error(e) | nom::Err::Failure(e) => {
                        return Err(ProlinkError::ParseError {
                            error_kind: format!("{:?}", e.code),
                            pos: e.input.location_offset(),
                            timestamp,
                            dump: pretty_hex(&data),
                        })
                    }
                    _ => return Err(anyhow!("Error parsing packet: {}", e).into()),
                };
            }
        };
        if !i.is_empty() {
            return Err(anyhow!("packet has extra data {} {:x?}", i.len(), i).into());
        }

        Ok(pkt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

            let (_, parsed) = AnnouncePacket::parse(Span::new(data)).unwrap();
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

            let (_, parsed) = DeviceNumClaim1Packet::parse(Span::new(data)).unwrap();
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

            let (_, parsed) = DeviceNumClaim2Packet::parse(Span::new(data)).unwrap();
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

            let (_, parsed) = DeviceNumClaim3Packet::parse(Span::new(data)).unwrap();
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

            let (_, parsed) = KeepAlivePacket::parse(Span::new(data)).unwrap();
            assert_eq!(parsed, Packet::KeepAlive(pkt));
        }
    }

    #[test]
    fn test_player_status() {
        let test_cases = [
            (
                &include_bytes!("test-data/status-3000.bin")[..],
                PlayerStatusPacket {
                    name: "CDJ-3000".to_string(),
                    unknown_10: 0x6,
                    device_num: 0x2,
                    unknown_16: 0x0,
                    active: 0x0,
                    track_device: 0x2,
                    track_slot: 0x3,
                    track_type: 0x1,
                    rekordbox_id: 0x73,
                    track_num: 0x1,
                    d_l: 0x2,
                    unknown_38: [
                        0x0, 0x0, 0x0, 0x33, 0x0, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    ],
                    d_n: 0x2,
                    usb_activity: 0x4,
                    unknown_48: [0; 32],
                    sd_activity: 0x4,
                    u_l: 0x0,
                    s_l: 0x4,
                    link_available: 0x0,
                    unknown_78: 0x0,
                    play_mode: 0x5,
                    firmware_ver: "1.20".to_string(),
                    sync_n: 0x1,
                    flags: 0xa4,
                    unknown_8b: 0xff,
                    play_state: 0xfe,
                    pitch_1: 0x1026e9,
                    m_v: 0x8000,
                    bpm: 0x3070,
                    unknown_94: 0x80003070,
                    pitch_2: 0x0,
                    p_3: 0x1,
                    m_m: 0x1,
                    m_h: 0xff,
                    beat: 0x3f,
                    cue: 0x3,
                    bar_beat: 0x3,
                    media_presence: 0x0,
                    u_e: 0x0,
                    s_e: 0x0,
                    emergency_loop_active: 0x0,
                    pitch_3: 0x1026e9,
                    pitch_4: 0x0,
                    seq_num: 0x0,
                    player_type: 0x1f,
                    unknown_cd: [0xf3, 0x0, 0x0],
                    extra0: Some(PlayerStatusExtraData0 {
                        unknown_d4: [
                            0x0, 0x0, 0x0, 0x1, 0x1, 0x1, 0x4, 0x1, 0x2, 0x1, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        ],
                        unknown_f4: [0x0, 0x0, 0x0, 0x1, 0x1, 0x1],
                        waveform_color: 0x1,
                        unknown_fb: 0x1,
                        waveform_pos: 0x1,
                        unknown_fe: [
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x7, 0x7d, 0x0, 0x0,
                            0x4, 0x1d, 0xb,
                        ],
                        buf_f: 0x80,
                        buf_b: 0x1e,
                        buf_s: 0x0,
                        unknown_120: [
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x3, 0xb8, 0xa8, 0x30, 0x70, 0x0, 0x0, 0x3, 0x0, 0x0,
                            0x1,
                        ],
                        master_tempo: 0x1,
                        unknown_159: [0x0, 0x0, 0x0],
                        key: 0x30000,
                        unknown_15f: [0x1, 0x0, 0x0, 0x0, 0x0],
                        key_shift: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                        unknown_16c: [
                            0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1a, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x7, 0x62, 0xa0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0,
                            0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x2, 0x1, 0x2, 0x0, 0x1, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x73, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x33, 0x0, 0x0,
                            0x0, 0x38, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2,
                            0x1, 0x1a, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0xdf, 0xeb, 0x60, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0,
                            0x1, 0x1, 0x2, 0x1, 0x2, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x73, 0x0,
                            0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x33, 0x0, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x1, 0x1a, 0xff, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x3, 0xb8, 0x70, 0x38, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x2, 0x1, 0x2,
                            0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x73, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0,
                            0x0, 0x33, 0x0, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
                            0x0, 0x0, 0x0, 0x2, 0x1, 0x1a, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4,
                            0xa4, 0xb4, 0x98, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0,
                            0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x2, 0x1, 0x2, 0x0, 0x1, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x73, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x33, 0x0, 0x0,
                            0x0, 0x38, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2,
                            0x1, 0x1a, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0xf3, 0x5f, 0x88, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0,
                            0x1, 0x1, 0x2, 0x1, 0x2, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x73, 0x0,
                            0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x33, 0x0, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x1, 0x1a, 0xff, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x7, 0xdf, 0xa3, 0xe7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x2, 0x1, 0x2,
                            0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x73, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0,
                            0x0, 0x33, 0x0, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
                            0x0, 0x0, 0x0, 0x2, 0x1, 0x1a, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9,
                            0xb8, 0x2c, 0xa8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0,
                            0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x2, 0x1, 0x2, 0x0, 0x1, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x73, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x33, 0x0, 0x0,
                            0x0, 0x38, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2,
                            0x1, 0x1a, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x7c, 0xf5, 0xe0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0,
                            0x1, 0x1, 0x2, 0x1, 0x2, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x73, 0x0,
                            0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x33, 0x0, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0,
                        ],
                    }),
                },
            ),
            (
                &include_bytes!("test-data/status-900.bin")[..],
                PlayerStatusPacket {
                    name: "CDJ-900".to_string(),
                    unknown_10: 0x3,
                    device_num: 0x3,
                    unknown_16: 0x0,
                    active: 0x0,
                    track_device: 0x2,
                    track_slot: 0x3,
                    track_type: 0x1,
                    rekordbox_id: 0x73,
                    track_num: 0x1,
                    d_l: 0x2,
                    unknown_38: [
                        0x0, 0x0, 0x0, 0x33, 0x0, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    ],
                    d_n: 0x2,
                    unknown_48: [0; 32],
                    usb_activity: 0x4,
                    sd_activity: 0x4,
                    u_l: 0x4,
                    s_l: 0x4,
                    link_available: 0x1,
                    unknown_78: 0x0,
                    play_mode: 0x5,
                    firmware_ver: "4.32".to_string(),
                    sync_n: 0x0,
                    flags: 0x0,
                    unknown_8b: 0x0,
                    play_state: 0x6e,
                    pitch_1: 0x100000,
                    m_v: 0x8000,
                    bpm: 0x3070,
                    unknown_94: 0x7fffffff,
                    pitch_2: 0x0,
                    p_3: 0x1,
                    m_m: 0x0,
                    m_h: 0x0,
                    beat: 0xffffffff,
                    cue: 0x1ff,
                    bar_beat: 0x0,
                    media_presence: 0x0,
                    u_e: 0x0,
                    s_e: 0x0,
                    emergency_loop_active: 0x0,
                    pitch_3: 0x100000,
                    pitch_4: 0x100000,
                    seq_num: 0x5ea,
                    player_type: 0x5,
                    unknown_cd: [0x0, 0x0, 0x0],
                    extra0: None,
                },
            ),
        ];
        for (data, pkt) in test_cases {
            let (_, parsed) = PlayerStatusPacket::parse(Span::new(data)).unwrap();
            assert_eq!(parsed, Packet::PlayerStatus(pkt));
        }
    }

    #[test]
    fn test_parse_packets() {
        let test_cases = [
            // Unhandled type 05  &include_bytes!("test-data/bad-packet-1634334264964.bin")[..],
            &include_bytes!("test-data/bad-packet-1634334280362.bin")[..],
            &include_bytes!("test-data/bad-packet-1634334280427.bin")[..],
            &include_bytes!("test-data/bad-packet-1634334280747.bin")[..],
        ];
        for (i, data) in test_cases.iter().enumerate() {
            if let Err(e) = Packet::parse(data) {
                panic!("Test {} failed: {}", i, e);
            }
        }
    }
}
