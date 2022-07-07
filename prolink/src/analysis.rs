use std::{convert::TryInto, io::SeekFrom, num::Wrapping};

use anyhow::anyhow;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};

use crate::Result;

#[derive(Debug)]
pub enum PhraseType {
    Intro,
    Up,
    Down,
    Chorus,
    Outro,
    Verse,
    Bridge,
}

#[derive(Debug, FromPrimitive)]
pub enum Mood {
    High = 1,
    Mid = 2,
    Low = 3,
}

#[derive(Debug)]
pub struct PhraseId {
    pub ty: PhraseType,
    pub index: u8,
}

#[derive(Debug)]
pub struct Phrase {
    pub index: u16,
    pub beats: Vec<u16>,
    pub phrase_id: PhraseId,
    pub fill_beats: u16,
}

#[derive(Debug)]
pub struct SongStructure {
    pub mood: Mood,
    pub end_beat: u16,
    pub bank: u8,
    pub phrases: Vec<Phrase>,
}

#[derive(Debug)]
pub struct Analysis {
    pub structure: Option<SongStructure>,
}

impl Analysis {
    #[allow(dead_code)]
    pub fn new() -> Analysis {
        Analysis { structure: None }
    }

    #[allow(dead_code)]
    pub async fn parse<R: AsyncRead + AsyncSeek + Unpin>(&mut self, r: &mut R) -> Result<()> {
        r.seek(SeekFrom::Start(0)).await?;
        let _four_cc = r.read_u32().await?;
        let header_len = r.read_u32().await? as u64;
        let file_len = r.read_u32().await? as u64;

        let mut section_offset = header_len;
        while section_offset < file_len {
            r.seek(SeekFrom::Start(section_offset)).await?;
            let section_four_cc = r.read_u32().await?;
            r.seek(SeekFrom::Current(4)).await?;
            let section_len = r.read_u32().await? as u64;

            let mut data = vec![0; section_len as usize];
            r.seek(SeekFrom::Start(section_offset)).await?;
            r.read_exact(&mut data).await?;

            if section_four_cc == u32::from_be_bytes(*b"PSSI") {
                self.parse_song_structure(&data)?;
            }

            section_offset += section_len;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn parse_song_structure(&mut self, data: &[u8]) -> Result<()> {
        let mask = [
            0xCBu8, 0xE1, 0xEE, 0xFA, 0xE5, 0xEE, 0xAD, 0xEE, 0xE9, 0xD2, 0xE9, 0xEB, 0xE1, 0xE9,
            0xF3, 0xE8, 0xE9, 0xF4, 0xE1,
        ];
        let entry_size = be_u32(data, 0xc)? as usize;
        let num_entries = be_u16(data, 0x10)? as usize;
        let decoded_data: Vec<_> = data
            .iter()
            .enumerate()
            .map(|(i, &x)| {
                let mask_index = i + mask.len() - 0x12;
                let mask_byte =
                    Wrapping(mask[mask_index % mask.len()]) + Wrapping(num_entries as u8);
                x ^ mask_byte.0
            })
            .collect();

        let raw_mood = be_u16(&decoded_data, 0x12)?;
        let mood: Mood =
            FromPrimitive::from_u16(raw_mood).ok_or(anyhow!("unsupported mood {}", raw_mood))?;
        let end_beat = be_u16(&decoded_data, 0x1a)?;
        let bank = decoded_data[0x1a];

        let mut phrases = Vec::new();

        for i in 0..num_entries {
            let entry_data = &decoded_data[0x20 + i * entry_size..];
            let index = be_u16(entry_data, 0x0)?;
            let mut beats = vec![be_u16(entry_data, 0x2)?];
            let kind = be_u16(entry_data, 0x4)?;
            let k1 = entry_data[0x7];
            let k2 = entry_data[0x9];
            let flags = entry_data[0x9];
            beats.push(be_u16(entry_data, 0xc)?);
            if flags == 0x01 {
                beats.push(be_u16(entry_data, 0xe)?);
                beats.push(be_u16(entry_data, 0x10)?);
            }
            let k3 = entry_data[0x13];
            let fill = entry_data[0x15];
            let fill_beats = if fill != 0 {
                be_u16(entry_data, 0x16)?
            } else {
                0
            };

            let phrase_id = Self::get_phrase_id(&mood, kind, k1, k2, k3)?;
            phrases.push(Phrase {
                index,
                beats,
                phrase_id,
                fill_beats,
            });
        }

        self.structure = Some(SongStructure {
            mood,
            end_beat,
            bank,
            phrases,
        });

        Ok(())
    }

    fn get_phrase_id(mood: &Mood, kind: u16, k1: u8, k2: u8, k3: u8) -> Result<PhraseId> {
        match mood {
            Mood::High => Self::get_high_phrase_id(kind, k1, k2, k3),
            Mood::Mid => Self::get_mid_phrase_id(kind),
            Mood::Low => Self::get_low_phrase_id(kind),
        }
    }

    fn get_high_phrase_id(kind: u16, k1: u8, k2: u8, k3: u8) -> Result<PhraseId> {
        match (kind, k1, k2, k3) {
            (1, 1, _, _) => Ok(PhraseId {
                ty: PhraseType::Intro,
                index: 1,
            }),
            (1, 0, _, _) => Ok(PhraseId {
                ty: PhraseType::Intro,
                index: 2,
            }),
            (2, _, 0, 0) => Ok(PhraseId {
                ty: PhraseType::Up,
                index: 1,
            }),
            (2, _, 0, 1) => Ok(PhraseId {
                ty: PhraseType::Up,
                index: 2,
            }),
            (2, _, 1, 0) => Ok(PhraseId {
                ty: PhraseType::Up,
                index: 3,
            }),
            (3, _, _, _) => Ok(PhraseId {
                ty: PhraseType::Down,
                index: 0,
            }),
            (5, 1, _, _) => Ok(PhraseId {
                ty: PhraseType::Chorus,
                index: 1,
            }),
            (5, 0, _, _) => Ok(PhraseId {
                ty: PhraseType::Chorus,
                index: 2,
            }),
            (6, 1, _, _) => Ok(PhraseId {
                ty: PhraseType::Outro,
                index: 1,
            }),
            (6, 0, _, _) => Ok(PhraseId {
                ty: PhraseType::Outro,
                index: 2,
            }),

            _ => Err(anyhow!(
                "Unknown high phrase type ({}, {}, {}, {})",
                kind,
                k1,
                k2,
                k3
            )
            .into()),
        }
    }

    fn get_mid_phrase_id(kind: u16) -> Result<PhraseId> {
        match kind {
            1 => Ok(PhraseId {
                ty: PhraseType::Intro,
                index: 0,
            }),
            2..=7 => Ok(PhraseId {
                ty: PhraseType::Verse,
                index: kind as u8 - 1,
            }),
            8 => Ok(PhraseId {
                ty: PhraseType::Bridge,
                index: 0,
            }),
            9 => Ok(PhraseId {
                ty: PhraseType::Chorus,
                index: 0,
            }),
            10 => Ok(PhraseId {
                ty: PhraseType::Outro,
                index: 0,
            }),
            _ => Err(anyhow!("Unknown mid phrase type {}", kind).into()),
        }
    }

    fn get_low_phrase_id(kind: u16) -> Result<PhraseId> {
        match kind {
            1 => Ok(PhraseId {
                ty: PhraseType::Intro,
                index: 0,
            }),
            2 | 3 | 4 => Ok(PhraseId {
                ty: PhraseType::Verse,
                index: 1,
            }),
            5 | 6 | 7 => Ok(PhraseId {
                ty: PhraseType::Verse,
                index: 2,
            }),
            8 => Ok(PhraseId {
                ty: PhraseType::Bridge,
                index: 0,
            }),
            9 => Ok(PhraseId {
                ty: PhraseType::Chorus,
                index: 0,
            }),
            10 => Ok(PhraseId {
                ty: PhraseType::Outro,
                index: 0,
            }),
            _ => Err(anyhow!("Unknown low phrase type {}", kind).into()),
        }
    }
}

fn be_u16(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(
        data[offset..(offset + 2)]
            .try_into()
            .map_err(|e| anyhow!("conversion to u16 failed: {}", e))?,
    ))
}

fn be_u32(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        data[offset..(offset + 4)]
            .try_into()
            .map_err(|e| anyhow!("conversion to u32 failed: {}", e))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ext_load() {
        let mut analysis = Analysis::new();
        let reader = tokio::fs::File::open("src/test-data/ANLZ0000.EXT")
            .await
            .unwrap();
        let mut reader = tokio::io::BufReader::new(reader);
        analysis.parse(&mut reader).await.unwrap();
        println!("{:#?}", analysis);
    }
}
