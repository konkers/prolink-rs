use anyhow::anyhow;
use log::{info, trace};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use pretty_hex::PrettyHex;
use std::{collections::HashMap, convert::TryInto, io::SeekFrom};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};

use crate::Result;

#[derive(Debug, Eq, FromPrimitive, Hash, PartialEq)]
#[repr(u32)]
pub enum TableType {
    Tracks = 0x00,
    Generes = 0x01,
    Artists = 0x02,
    Albums = 0x03,
    Labels = 0x04,
    Keys = 0x05,
    Colors = 0x06,
    PlaylistTree = 0x07,
    PlaylistEntries = 0x08,
    Artwork = 0x0d,
    Columns = 0x10,
    HistoryPlaylists = 0x11,
    HistoryEntires = 0x12,
    History = 0x13,
}

#[derive(Debug)]
pub struct TablePointer {
    first_page: u32,
    last_page: u32,
}

#[derive(Debug)]
pub struct RawAlbum {
    pub artist_id: u32,
    pub id: u32,
    pub name: String,
}

#[derive(Debug)]
pub struct RawTrack {
    pub sample_rate: u32,
    pub composer_id: u32,
    pub file_size: u32,
    pub artwork_id: u32,
    pub key_id: u32,
    pub original_artist_id: u32,
    pub label_id: u32,
    pub remixer_id: u32,
    pub bitrate: u32,
    pub track_number: u32,
    pub tempo: u32,
    pub genre_id: u32,
    pub album_id: u32,
    pub artist_id: u32,
    pub id: u32,
    pub disc: u16,
    pub play_count: u16,
    pub year: u16,
    pub sample_depth: u16,
    pub duration: u16,
    pub color_id: u8,
    pub rating: u8,
    pub strings: Vec<String>,
}

#[derive(Debug)]
pub struct Database {
    page_size: usize,

    pub albums: HashMap<u32, RawAlbum>,
    pub artists: HashMap<u32, String>,
    pub artwork: HashMap<u32, String>,
    pub colors: HashMap<u32, String>,
    pub generes: HashMap<u32, String>,
    pub keys: HashMap<u32, String>,
    pub labels: HashMap<u32, String>,
    pub tracks: HashMap<u32, RawTrack>,
}

impl Database {
    #[allow(dead_code)]
    pub async fn parse<R: AsyncRead + AsyncSeek + Unpin>(r: &mut R) -> Result<Database> {
        r.seek(SeekFrom::Start(4)).await?;
        let page_size = r.read_u32_le().await? as usize;
        let num_tables = r.read_u32_le().await?;
        r.seek(SeekFrom::Current(8)).await?;
        let _sequence = r.read_u32_le().await?;
        r.seek(SeekFrom::Current(4)).await?;

        let mut table_pointers = HashMap::new();

        for _ in 0..num_tables {
            let raw_table_type = r.read_u32_le().await?;
            let table_type: Option<TableType> = FromPrimitive::from_u32(raw_table_type);
            r.seek(SeekFrom::Current(4)).await?;
            let first_page = r.read_u32_le().await?;
            let last_page = r.read_u32_le().await?;

            if let Some(t) = table_type {
                table_pointers.insert(
                    t,
                    TablePointer {
                        first_page,
                        last_page,
                    },
                );
            } else {
                info!(target: "database", "unknown table type: {}", raw_table_type);
            }
        }

        let mut db = Database {
            page_size,
            albums: HashMap::new(),
            artists: HashMap::new(),
            artwork: HashMap::new(),
            colors: HashMap::new(),
            generes: HashMap::new(),
            keys: HashMap::new(),
            labels: HashMap::new(),
            tracks: HashMap::new(),
        };

        for (table_type, table_ptr) in &table_pointers {
            db.read_table(r, table_type, table_ptr).await?;
        }
        Ok(db)
    }

    async fn read_table<R: AsyncRead + AsyncSeek + Unpin>(
        &mut self,
        r: &mut R,
        table_type: &TableType,
        table_ptr: &TablePointer,
    ) -> Result<()> {
        let mut cur_page = table_ptr.first_page;
        let mut page_data = vec![0; self.page_size];

        loop {
            r.seek(SeekFrom::Start(cur_page as u64 * self.page_size as u64))
                .await?;
            r.read_exact(&mut page_data).await?;

            let next_page = self.parse_page(table_type, &page_data)?;

            if cur_page == table_ptr.last_page {
                break;
            }

            cur_page = next_page;
        }
        Ok(())
    }

    fn parse_page(&mut self, table_type: &TableType, page_data: &Vec<u8>) -> Result<u32> {
        trace!("{:?}", page_data.hex_dump());
        let next_page = le_u32(page_data, 0xc)?;

        let page_flags = page_data[0x1b];
        if (page_flags & 0x40) != 0 {
            trace!("strange page");
            return Ok(next_page);
        }

        let num_rows_small = page_data[0x18];
        let num_rows_large = le_u16(page_data, 0x22)?;
        let num_rows = if num_rows_large == 0x1fff {
            num_rows_small as usize
        } else {
            std::cmp::max(num_rows_large as usize, num_rows_small as usize)
        };

        trace!("rows {}", num_rows);
        for i in 0..num_rows {
            let group = i / 16;
            let sub_index = i % 16;
            let group_offset = page_data.len() - group * 18 * 2;
            let valid_mask = le_u16(page_data, group_offset - 4)?;
            trace!(
                "parsing row {} {} {} {} {:x}",
                i,
                group,
                sub_index,
                group_offset,
                valid_mask
            );

            // Skip this row if it's not valid.
            if (valid_mask & (1 << sub_index)) == 0 {
                trace!("invalid_row");
                continue;
            }

            let row_offset = 0x28 + le_u16(page_data, group_offset - 6 - 2 * sub_index)? as usize;
            trace!("row_offset {}", row_offset);

            self.parse_row(table_type, &page_data[row_offset..])?;
        }

        Ok(next_page)
    }

    fn parse_row(&mut self, table_type: &TableType, row_data: &[u8]) -> Result<()> {
        trace!("parse row");
        match table_type {
            TableType::Albums => self.parse_album_row(row_data),
            TableType::Artists => self.parse_artist_row(row_data),
            TableType::Artwork => self.parse_artwork_row(row_data),
            TableType::Colors => self.parse_color_row(row_data),
            TableType::Generes => self.parse_genere_row(row_data),
            TableType::Keys => self.parse_key_row(row_data),
            TableType::Labels => self.parse_label_row(row_data),
            TableType::Tracks => self.parse_track_row(row_data),
            _ => Ok(()), // Silently ignore unsupported rows types.
        }
    }

    fn parse_album_row(&mut self, row_data: &[u8]) -> Result<()> {
        trace!("parse album row");
        let artist_id = le_u32(row_data, 0x8)?;
        let id = le_u32(row_data, 0xc)?;
        let offset = row_data[0x15] as usize;
        let name = Self::parse_string(&row_data[offset..])?;

        self.albums.insert(
            id,
            RawAlbum {
                artist_id,
                id,
                name,
            },
        );

        Ok(())
    }

    fn parse_artist_row(&mut self, row_data: &[u8]) -> Result<()> {
        trace!("parse artist row");
        let sub_type = row_data[0];
        let id = le_u32(row_data, 4)?;
        let offset = match sub_type {
            0x60 => row_data[0x9] as usize,
            0x64 => le_u32(row_data, 0xa)? as usize,
            _ => return Err(anyhow!("Unknown artist record subtype {:x}", sub_type).into()),
        };

        let name = Self::parse_string(&row_data[offset..])?;

        self.artists.insert(id, name);

        Ok(())
    }

    fn parse_artwork_row(&mut self, row_data: &[u8]) -> Result<()> {
        trace!("parse artwork row");
        let id = le_u32(row_data, 0x0)?;
        let string = Self::parse_string(&row_data[4..])?;
        self.artwork.insert(id, string);

        Ok(())
    }

    fn parse_color_row(&mut self, row_data: &[u8]) -> Result<()> {
        trace!("parse color row");
        let id = le_u16(row_data, 0x5)? as u32;
        let string = Self::parse_string(&row_data[8..])?;
        self.colors.insert(id, string);

        Ok(())
    }

    fn parse_genere_row(&mut self, row_data: &[u8]) -> Result<()> {
        trace!("parse genere row");
        let id = le_u32(row_data, 0x0)? as u32;
        let string = Self::parse_string(&row_data[4..])?;
        self.generes.insert(id, string);

        Ok(())
    }

    fn parse_key_row(&mut self, row_data: &[u8]) -> Result<()> {
        trace!("parse key row");
        let id = le_u32(row_data, 0x0)? as u32;
        let string = Self::parse_string(&row_data[8..])?;
        self.keys.insert(id, string);

        Ok(())
    }

    fn parse_label_row(&mut self, row_data: &[u8]) -> Result<()> {
        trace!("parse lable row");
        let id = le_u32(row_data, 0x0)? as u32;
        let string = Self::parse_string(&row_data[4..])?;
        self.labels.insert(id, string);

        Ok(())
    }

    fn parse_track_row(&mut self, row_data: &[u8]) -> Result<()> {
        trace!("parse track row");
        let sample_rate = le_u32(row_data, 0x08)?;
        let composer_id = le_u32(row_data, 0x0c)?;
        let file_size = le_u32(row_data, 0x10)?;
        let artwork_id = le_u32(row_data, 0x1c)?;
        let key_id = le_u32(row_data, 0x20)?;
        let original_artist_id = le_u32(row_data, 0x24)?;
        let label_id = le_u32(row_data, 0x28)?;
        let remixer_id = le_u32(row_data, 0x2c)?;
        let bitrate = le_u32(row_data, 0x30)?;
        let track_number = le_u32(row_data, 0x34)?;
        let tempo = le_u32(row_data, 0x38)?;
        let genre_id = le_u32(row_data, 0x3c)?;
        let album_id = le_u32(row_data, 0x40)?;
        let artist_id = le_u32(row_data, 0x44)?;
        let id = le_u32(row_data, 0x48)?;
        let disc = le_u16(row_data, 0x4c)?;
        let play_count = le_u16(row_data, 0x4c)?;
        let year = le_u16(row_data, 0x50)?;
        let sample_depth = le_u16(row_data, 0x52)?;
        let duration = le_u16(row_data, 0x54)?;
        let color_id = row_data[0x58];
        let rating = row_data[0x59];

        let mut strings = Vec::new();
        for i in 0..20 {
            let offset = le_u16(row_data, 0x5e + 2 * i)? as usize;
            let string = Self::parse_string(&row_data[offset..])?;
            strings.push(string);
        }

        self.tracks.insert(
            id,
            RawTrack {
                sample_rate,
                composer_id,
                file_size,
                artwork_id,
                key_id,
                original_artist_id,
                label_id,
                remixer_id,
                bitrate,
                track_number,
                tempo,
                genre_id,
                album_id,
                artist_id,
                id,
                disc,
                play_count,
                year,
                sample_depth,
                duration,
                color_id,
                rating,
                strings,
            },
        );

        Ok(())
    }

    fn parse_string(data: &[u8]) -> Result<String> {
        let flags = data[0];

        if flags == 0x90 && data.len() > 4 && data[4] == 0x3 {
            // ISRC string
            let len = le_u16(data, 1)? as usize;
            if len < 6 {
                return Ok("".to_string());
            }
            let str_data = &data[5..(len - 1)];
            trace!("ISRC parsing utf8 {:x?}", str_data);
            Ok(String::from_utf8(str_data.into())
                .map_err(|e| anyhow!("Error converting ASCII string: {}", e))?)
        } else if (flags & 0x1) == 0 {
            let len = le_u16(data, 1)? as usize;

            if len < 5 {
                return Ok("".to_string());
            }

            if len % 2 != 0 {
                return Err(anyhow!("utf16 string not a mulitple of 2 ({})", len).into());
            }
            let string: Vec<u16> = data[4..len]
                .chunks(2)
                .map(|b| (b[0] as u16) + ((b[1] as u16) << 8))
                .collect();
            Ok(String::from_utf16(&string)
                .map_err(|e| anyhow!("Error converting UTF16 string: {}", e))?)
        } else {
            let len = (flags >> 1) as usize;
            if len < 2 {
                return Ok("".to_string());
            }
            let str_data = &data[1..len];
            trace!("parsing utf8 {:x?}", str_data);
            Ok(String::from_utf8(str_data.into())
                .map_err(|e| anyhow!("Error converting ASCII string: {}", e))?)
        }
    }
}

fn le_u16(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        data[offset..(offset + 2)]
            .try_into()
            .map_err(|e| anyhow!("conversion to u16 failed: {}", e))?,
    ))
}

fn le_u32(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        data[offset..(offset + 4)]
            .try_into()
            .map_err(|e| anyhow!("conversion to u32 failed: {}", e))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_database_load() {
        let _ = env_logger::builder().is_test(true).try_init();
        let reader = tokio::fs::File::open("src/test-data/export.pdb")
            .await
            .unwrap();
        let mut reader = tokio::io::BufReader::new(reader);
        let db = Database::parse(&mut reader).await.unwrap();
        println!("{:#?}", db);
    }
}
