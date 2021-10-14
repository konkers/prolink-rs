use std::{convert::TryInto, io::Write};

use anyhow::{anyhow, Result};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    error::{convert_error, dbg_dmp, ContextError, ParseError, VerboseError},
    number::complete::{be_i32, be_u16, be_u24, be_u32, be_u8},
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

fn header2<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
    i: &'a [u8],
) -> IResult<&'a [u8], (), E> {
    let (i, _) = tag(HEADER)(i)?;
    Ok((i, ()))
}

fn device_name2<'a, E: ParseError<&'a [u8]> + ContextError<&'a [u8]>>(
    i: &'a [u8],
) -> IResult<&'a [u8], String, E> {
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
pub struct PlayerStatusExtraData0 {
    unknown_d4: [u8; 28],
    unknown_f4: [u8; 6],
    waveform_color: u8,
    unknown_fb: u16,
    waveform_pos: u8,
    unknown_fe: [u8; 31],
    buf_f: u8,
    buf_b: u8,
    buf_s: u8,
    unknown_120: [u8; 0x38],
    master_tempo: u8,
    unknown_159: [u8; 3],
    key: u32, // only 24 bits in packet
    unknown_160: [u8; 4],
    key_shift: [u8; 8],
    unknown_16c: [u8; 0x288],
}

#[derive(Debug, PartialEq)]
pub struct PlayerStatusPacket {
    name: String,
    unknown_10: u8,
    device_num: u8,
    unknown_16: u8,
    active: u8,
    track_device: u8,
    track_slot: u8,
    track_type: u8,
    rekordbox_id: u32,
    track_num: u16,
    d_l: u8,
    unknown_38: [u8; 14],
    d_n: u16,
    usb_activity: u8,
    sd_activity: u8,
    u_l: u8,
    s_l: u8,
    link_available: u8,
    unknown_78: u8,
    play_mode: u8,
    firmware_ver: String,
    sync_n: u32,
    flags: u8,
    unknown_8b: u8,
    play_state: u8,
    pitch_1: u32,
    m_v: u16,
    bpm: u16,
    unknown_94: u32,
    pitch_2: u32,
    p_3: u8,
    m_m: u8,
    m_h: u8,
    beat: u32,
    cue: u16,
    bar_beat: u8,
    media_presence: u8,
    u_e: u8,
    s_e: u8,
    emergency_loop_active: u8,
    pitch_3: u32,
    pitch_4: u32,
    seq_num: u32,
    player_type: u8,
    unknown_cd: [u8; 3],
    extra0: Option<PlayerStatusExtraData0>,
}

impl PlayerStatusPacket {
    pub fn parse<'a, E>(i: &'a [u8]) -> IResult<&'a [u8], Packet, E>
    where
        E: ParseError<&'a [u8]> + ContextError<&'a [u8]> + std::fmt::Debug,
    {
        let (i, _) = header2(i)?;
        let (i, _) = tag(&[0x0a])(i)?; // TODO: make enum
        let (i, name) = device_name2(i)?;
        let (i, _) = tag(&[0x01])(i)?;
        let (i, unknown_10) = be_u8(i)?;
        let (i, device_num) = be_u8(i)?;
        let (i, pkt_len) = be_u16(i)?; // len
        let (i, _device_num2) = be_u8(i)?;
        let (i, _) = tag(&[0x00])(i)?;
        let (i, unknown_16) = be_u8(i)?;

        let (i, active) = be_u8(i)?;
        let (i, track_device) = be_u8(i)?;
        let (i, track_slot) = be_u8(i)?;
        let (i, track_type) = be_u8(i)?;

        // 0x30
        let (i, _) = tag(&[0x00])(i)?;
        let (i, rekordbox_id) = be_u32(i)?;
        let (i, _) = tag(&[0x00, 0x00])(i)?;
        let (i, track_num) = be_u16(i)?;
        let (i, _) = tag(&[0x00, 0x00, 0x00])(i)?;
        let (i, d_l) = be_u8(i)?;

        // 0x38
        let (i, unknown_38) = take(14usize)(i)?;

        // 0x46
        let (i, d_n) = be_u16(i)?;
        let (i, _) = tag(&[0x00; 32])(i)?;
        let (i, _) = tag(&[0x01, 0x00])(i)?;

        // 0x6a
        let (i, usb_activity) = be_u8(i)?;
        let (i, sd_activity) = be_u8(i)?;
        let (i, _) = tag(&[0x00; 3])(i)?;
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
        let firmware_ver = String::from_utf8_lossy(firmware_ver_raw);
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

        let extra0 = if player_type == 0x05 {
            None
        } else if player_type == 0x1f {
            // 0xd0
            let (i, _) = dbg_dmp(tag(&[0x12, 0x34, 0x56, 0x78]), "magic0")(i)?;
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
            let (i, _) = tag(&[0x01])(i)?;

            // 0x160
            let (i, unknown_160) = take(4usize)(i)?;
            let (i, key_shift) = take(8usize)(i)?;

            // 0x16c
            let (i, unknown_16c) = take(0x288usize)(i)?;
            Some(PlayerStatusExtraData0 {
                unknown_d4: unknown_d4.try_into().unwrap(),
                unknown_f4: unknown_f4.try_into().unwrap(),
                waveform_color,
                unknown_fb,
                waveform_pos,
                unknown_fe: unknown_fe.try_into().unwrap(),
                buf_f,
                buf_b,
                buf_s,
                unknown_120: unknown_120.try_into().unwrap(),
                master_tempo,
                unknown_159: unknown_159.try_into().unwrap(),
                key,
                unknown_160: unknown_160.try_into().unwrap(),
                key_shift: key_shift.try_into().unwrap(),
                unknown_16c: unknown_16c.try_into().unwrap(),
            })
        } else {
            None // TODO: 2000nx2?
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
                unknown_38: unknown_38.try_into().unwrap(),
                d_n,
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
                unknown_cd: unknown_cd.try_into().unwrap(),
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
    PlayerStatus(PlayerStatusPacket),
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
    use nom::error::{dbg_dmp, Error};

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

    #[test]
    fn test() {
        let data = include_bytes!("test-data/status-3000.bin");
        let expected = PlayerStatusPacket {
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
                    0x0, 0x0, 0x0, 0x1, 0x1, 0x1, 0x4, 0x1, 0x2, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                ],
                unknown_f4: [0x0, 0x0, 0x0, 0x1, 0x1, 0x1],
                waveform_color: 0x1,
                unknown_fb: 0x1,
                waveform_pos: 0x1,
                unknown_fe: [
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x7, 0x7d, 0x0, 0x0, 0x4, 0x1d, 0xb,
                ],
                buf_f: 0x80,
                buf_b: 0x1e,
                buf_s: 0x0,
                unknown_120: [
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0xb8,
                    0xa8, 0x30, 0x70, 0x0, 0x0, 0x3, 0x0, 0x0, 0x1,
                ],
                master_tempo: 0x1,
                unknown_159: [0x0, 0x0, 0x0],
                key: 0x30000,
                unknown_160: [0x0, 0x0, 0x0, 0x0],
                key_shift: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                unknown_16c: [
                    0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x1, 0x1a, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7, 0x62,
                    0xa0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0,
                    0x0, 0x1, 0x1, 0x2, 0x1, 0x2, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x73, 0x0,
                    0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x33, 0x0, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x1, 0x1a, 0xff, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x1, 0xdf, 0xeb, 0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0,
                    0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x2, 0x1, 0x2, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x73, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x33, 0x0, 0x0, 0x0, 0x38, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x1, 0x1a, 0xff, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x3, 0xb8, 0x70, 0x38, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x2, 0x1, 0x2, 0x0, 0x1, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x73, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x33, 0x0, 0x0,
                    0x0, 0x38, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x1,
                    0x1a, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0xa4, 0xb4, 0x98, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x2, 0x1, 0x2,
                    0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x73, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0,
                    0x33, 0x0, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0,
                    0x0, 0x2, 0x1, 0x1a, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0xf3, 0x5f, 0x88, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1,
                    0x2, 0x1, 0x2, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x73, 0x0, 0x0, 0x0, 0x2,
                    0x0, 0x0, 0x0, 0x33, 0x0, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x1, 0x0, 0x0, 0x0, 0x2, 0x1, 0x1a, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7, 0xdf,
                    0xa3, 0xe7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0,
                    0x0, 0x0, 0x1, 0x1, 0x2, 0x1, 0x2, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x73,
                    0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x33, 0x0, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x1, 0x1a, 0xff, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x9, 0xb8, 0x2c, 0xa8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
                    0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x2, 0x1, 0x2, 0x0, 0x1, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x73, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x33, 0x0, 0x0, 0x0, 0x38,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x1, 0x1a, 0xff,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x7c, 0xf5, 0xe0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x2, 0x1, 0x2, 0x0, 0x1,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x73, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x33, 0x0,
                    0x0, 0x0, 0x38, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2,
                    0x0, 0x0, 0x0, 0x0,
                ],
            }),
        };
        let data = include_bytes!("test-data/status-900.bin");
        let expected = PlayerStatusPacket {
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
        };
        let pkt = PlayerStatusPacket::parse::<Error<&[u8]>>(data);
        println!("{:#x?}", pkt.unwrap().1);
    }
}
