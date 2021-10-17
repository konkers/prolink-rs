use std::{convert::TryInto, io::Write};

use anyhow::anyhow;
use byteorder::{BigEndian, WriteBytesExt};
use nom::{
    branch::alt,
    bytes::streaming::{tag, take},
    number::streaming::{be_u16, be_u32, be_u8},
    IResult,
};
use num_derive::FromPrimitive;
use strum::Display;

use crate::Result;

#[derive(Debug)]
#[repr(u8)]
enum FieldType {
    U8 = 0x0f,
    U16 = 0x10,
    U32 = 0x11,
    Blob = 0x14,
    String = 0x26,
}

#[derive(Debug, PartialEq)]
pub(super) enum Field {
    U8(u8),
    U16(u16),
    U32(u32),
    Blob(Vec<u8>),
    String(String),
}

impl Field {
    pub fn encode(&self, mut w: impl Write) -> Result<()> {
        match self {
            Self::U8(val) => {
                w.write_u8(FieldType::U8 as u8)?;
                w.write_u8(*val)?;
            }
            Self::U16(val) => {
                w.write_u8(FieldType::U16 as u8)?;
                w.write_u16::<BigEndian>(*val)?;
            }
            Self::U32(val) => {
                w.write_u8(FieldType::U32 as u8)?;
                w.write_u32::<BigEndian>(*val)?;
            }
            Self::Blob(val) => {
                w.write_u8(FieldType::Blob as u8)?;
                w.write_u32::<BigEndian>(val.len() as u32)?;
                w.write_all(val)?;
            }
            Self::String(val) => {
                let utf: Vec<u16> = val.encode_utf16().collect();
                w.write_u8(FieldType::String as u8)?;
                w.write_u32::<BigEndian>(utf.len() as u32)?;
                for point in utf {
                    w.write_u16::<BigEndian>(point)?;
                }
            }
        }
        Ok(())
    }

    pub fn dmst(d: u8, m: u8, s: u8, t: u8) -> Field {
        Field::U32(((d as u32) << 24) | ((m as u32) << 16) | ((s as u32) << 8) | (t as u32))
    }

    pub fn parse(i: &[u8]) -> IResult<&[u8], Field> {
        alt((
            Self::parse_u8,
            Self::parse_u16,
            Self::parse_u32,
            Self::parse_blob,
            Self::parse_string,
        ))(i)
    }

    fn parse_u8(i: &[u8]) -> IResult<&[u8], Field> {
        let (i, val) = Self::parse_u8_val(i)?;
        Ok((i, Field::U8(val)))
    }

    fn parse_u8_val(i: &[u8]) -> IResult<&[u8], u8> {
        let (i, _) = tag(&[FieldType::U8 as u8])(i)?;
        let (i, val) = be_u8(i)?;
        Ok((i, val))
    }

    fn parse_u16(i: &[u8]) -> IResult<&[u8], Field> {
        let (i, val) = Self::parse_u16_val(i)?;
        Ok((i, Field::U16(val)))
    }

    fn parse_u16_val(i: &[u8]) -> IResult<&[u8], u16> {
        let (i, _) = tag(&[FieldType::U16 as u8])(i)?;
        let (i, val) = be_u16(i)?;
        Ok((i, val))
    }

    fn parse_u32(i: &[u8]) -> IResult<&[u8], Field> {
        let (i, val) = Self::parse_u32_val(i)?;
        Ok((i, Field::U32(val)))
    }

    fn parse_u32_val(i: &[u8]) -> IResult<&[u8], u32> {
        let (i, _) = tag(&[FieldType::U32 as u8])(i)?;
        let (i, val) = be_u32(i)?;
        Ok((i, val))
    }

    fn parse_blob(i: &[u8]) -> IResult<&[u8], Field> {
        let (i, val) = Self::parse_blob_val(i)?;
        Ok((i, Field::Blob(val)))
    }

    fn parse_blob_val(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
        let (i, _) = tag(&[FieldType::Blob as u8])(i)?;
        let (i, len) = be_u32(i)?;
        let (i, data) = take(len as usize)(i)?;
        Ok((i, data.to_vec()))
    }

    fn parse_string(i: &[u8]) -> IResult<&[u8], Field> {
        let (i, val) = Self::parse_string_val(i)?;
        Ok((i, Field::String(val)))
    }

    fn parse_string_val(i: &[u8]) -> IResult<&[u8], String> {
        let (i, _) = tag(&[FieldType::String as u8])(i)?;
        let (i, num_points) = be_u32(i)?;
        let mut data = Vec::with_capacity(num_points as usize);
        let data_i = i;
        let mut i = i;
        for _ in 0..num_points {
            let (i1, val) = be_u16(i)?;
            data.push(val);
            i = i1;
        }

        match String::from_utf16(&data) {
            Ok(s) => Ok((i, s.trim_end_matches('\0').into())),
            Err(_) => Err(nom::Err::Error(nom::error::Error::new(
                data_i,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }

    fn tag_u32(tag_val: u32) -> impl Fn(&[u8]) -> IResult<&[u8], ()> {
        move |i: &[u8]| -> IResult<&[u8], ()> {
            let (i, _) = tag(&[
                FieldType::U32 as u8,
                ((tag_val >> 24) & 0xff) as u8,
                ((tag_val >> 16) & 0xff) as u8,
                ((tag_val >> 8) & 0xff) as u8,
                ((tag_val >> 0) & 0xff) as u8,
            ])(i)?;
            Ok((i, ()))
        }
    }
}

#[derive(Debug)]
pub(super) struct Packet {
    fields: Vec<Field>,
}

impl Packet {
    pub fn new() -> Packet {
        Packet { fields: Vec::new() }
    }

    pub fn add_field(&mut self, field: Field) {
        self.fields.push(field);
    }

    pub fn with_field(mut self, field: Field) -> Packet {
        self.add_field(field);
        self
    }

    pub fn to_bytes(self) -> Result<Vec<u8>> {
        let mut data = Vec::new();

        for field in self.fields {
            field.encode(&mut data)?
        }

        Ok(data)
    }
}

const MESSAGE_MAGIC: u32 = 0x872349ae;

#[derive(Debug)]
pub(super) struct Message {
    pub tx_id: u32,
    pub ty: u16,
    pub num_args: u8,
    pub arg_tags: Vec<u8>,
    pub args: Vec<Field>,
}

impl Message {
    pub fn new(tx_id: u32, ty: u16, args: Vec<Field>) -> Result<Message> {
        if args.len() > 12 {
            return Err(anyhow!("too many args").into());
        }

        let mut arg_tags = Vec::new();
        for arg in &args {
            let tag = match arg {
                Field::U32(_) => 0x06,
                Field::Blob(_) => 0x03,
                Field::String(_) => 0x02,
                _ => return Err(anyhow!("no known tag for field {:?}", arg).into()),
            };

            arg_tags.push(tag);
        }

        Ok(Message {
            tx_id,
            ty,
            num_args: args.len() as u8,
            arg_tags,
            args,
        })
    }

    pub fn arg_u32(&self, idx: usize) -> Result<u32> {
        if idx >= self.args.len() {
            return Err(anyhow!("index out of range").into());
        }

        match self.args[idx] {
            Field::U32(val) => Ok(val),
            _ => Err(anyhow!("wrong arg type").into()),
        }
    }

    pub fn arg_string<'a>(&'a self, idx: usize) -> Result<&'a String> {
        if idx >= self.args.len() {
            return Err(anyhow!("index out of range").into());
        }

        match &self.args[idx] {
            Field::String(val) => Ok(val),
            _ => Err(anyhow!("wrong arg type").into()),
        }
    }

    pub fn arg_blob<'a>(&'a self, idx: usize) -> Result<&'a Vec<u8>> {
        if idx >= self.args.len() {
            return Err(anyhow!("index out of range").into());
        }

        match &self.args[idx] {
            Field::Blob(val) => Ok(val),
            _ => Err(anyhow!("wrong arg type").into()),
        }
    }

    pub fn encode(&self, mut w: impl Write) -> Result<()> {
        Field::U32(MESSAGE_MAGIC).encode(&mut w)?;
        Field::U32(self.tx_id).encode(&mut w)?;
        Field::U16(self.ty).encode(&mut w)?;
        Field::U8(self.num_args).encode(&mut w)?;
        Field::Blob(self.arg_tags.clone()).encode(&mut w)?;

        for arg in &self.args {
            arg.encode(&mut w)?;
        }

        Ok(())
    }

    pub fn parse(i: &[u8]) -> IResult<&[u8], Message> {
        let (i, _) = Field::tag_u32(MESSAGE_MAGIC)(i)?;
        let (i, tx_id) = Field::parse_u32_val(i)?;
        let (i, ty) = Field::parse_u16_val(i)?;
        let (i, num_args) = Field::parse_u8_val(i)?;
        let (i, tags) = Field::parse_blob_val(i)?;

        let mut args = Vec::new();
        let mut i = i;
        for _ in 0..num_args {
            let (i1, field) = Field::parse(i)?;
            args.push(field);
            i = i1;
        }

        Ok((
            i,
            Message {
                tx_id,
                ty,
                num_args,
                arg_tags: tags.try_into().unwrap(), // TODO: need a check for tags size.
                args,
            },
        ))
    }
}

#[derive(Debug, Display, FromPrimitive, PartialEq)]
#[repr(u32)]
pub(super) enum MenuItemType {
    Folder = 0x0001,
    AlbumTitle = 0x0002,
    Disc = 0x0003,
    TrackTitle = 0x0004,
    Genre = 0x0006,
    Artist = 0x0007,
    Playlist = 0x0008,
    Rating = 0x000a,
    Duration = 0x000b,
    Tempo = 0x000d,
    Label = 0x000e,
    Key = 0x000f,
    BitRate = 0x0010,
    Year = 0x0011,
    ColorNone = 0x0013,
    ColorPink = 0x0014,
    ColorRed = 0x0015,
    ColorOrange = 0x0016,
    ColorYellow = 0x0017,
    ColorGreen = 0x0018,
    ColorAqua = 0x0019,
    ColorBlue = 0x001a,
    ColorPurple = 0x001b,
    Comment = 0x023,
    HistoryPlaylist = 0x24,
    OriginalArtist = 0x28,
    Remixer = 0x29,
    DateAdded = 0x2e,
    GenreMenu = 0x80,
    ArtistMenu = 0x81,
    AlbumMenu = 0x82,
    TrackMenu = 0x83,
    PlaylistMenu = 0x84,
    BpmMenu = 0x85,
    RatingMenu = 0x86,
    YearMenu = 0x87,
    RemixerMenu = 0x88,
    LabelMenu = 0x89,
    OriginalArtistMenu = 0x8a,
    KeyMenu = 0x8b,
    ColorMenu = 0x8e,
    FolderMenu = 0x90,
    SearchMenu = 0x91,
    TimeMenu = 0x92,
    BitRateMenu = 0x93,
    FilenameMenu = 0x94,
    HistoryMenu = 0x95,
    All = 0xa0,
}
