use anyhow::anyhow;
use byteorder::{LittleEndian, ReadBytesExt};
use nom::character::complete::tab;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use pretty_hex::*;
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
    artist_id: u32,
    id: u32,
    name: String,
}

#[derive(Debug)]
pub struct RawTrack {
    sample_rate: u32,
    composer_id: u32,
    file_size: u32,
    artwork_id: u32,
    key_id: u32,
    org_artist_id: u32,
    label_id: u32,
    remixer_id: u32,
    bitrate: u32,
    track_number: u32,
    tempo: u32,
    genre_id: u32,
    album_id: u32,
    artist_id: u32,
    id: u32,
    disc: u16,
    play_count: u16,
    year: u16,
    sample_depth: u16,
    duration: u16,
    color_id: u8,
    rating: u8,
    strings: Vec<String>,
}

#[derive(Debug)]
pub struct Database {
    page_size: usize,
    num_tables: u32,
    sequence: u32,

    albums: HashMap<u32, RawAlbum>,
    artists: HashMap<u32, String>,
    artwork: HashMap<u32, String>,
    colors: HashMap<u32, String>,
    generes: HashMap<u32, String>,
    keys: HashMap<u32, String>,
    labels: HashMap<u32, String>,
    tracks: HashMap<u32, RawTrack>,
}

impl Database {
    pub async fn parse<R: AsyncRead + AsyncSeek + Unpin>(r: &mut R) -> Result<Database> {
        r.seek(SeekFrom::Start(4)).await?;
        let page_size = r.read_u32_le().await? as usize;
        let num_tables = r.read_u32_le().await?;
        r.seek(SeekFrom::Current(8)).await?;
        let sequence = r.read_u32_le().await?;
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
                println!("unknown table type: {}", raw_table_type);
            }
        }

        let mut db = Database {
            page_size,
            num_tables,
            sequence,
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
        let next_page = le_u32(page_data, 0xc)?;

        let page_flags = page_data[0x1b];
        if (page_flags & 0x40) != 0 {
            return Ok(next_page);
        }

        let num_rows_small = page_data[0x18];
        let num_rows_large = le_u16(page_data, 0x22)?;
        let num_rows = if num_rows_large == 0x1fff {
            num_rows_small as usize
        } else {
            std::cmp::max(num_rows_large as usize, num_rows_small as usize)
        };

        for i in 0..num_rows {
            let group = i / 16;
            let sub_index = i % 16;
            let group_offset = page_data.len() - group * 18;
            let valid_mask = le_u16(page_data, group_offset - 4)?;

            // Skip this row if it's not valid.
            if (valid_mask & (1 << sub_index)) == 0 {
                continue;
            }

            let row_offset = 0x28 + le_u16(page_data, group_offset - 6 - 2 * sub_index)? as usize;

            self.parse_row(table_type, &page_data[row_offset..])?;
        }

        Ok(next_page)
    }

    fn parse_row(&mut self, table_type: &TableType, row_data: &[u8]) -> Result<()> {
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
        let id = le_u32(row_data, 0x0)?;
        let string = Self::parse_string(&row_data[4..])?;
        self.artwork.insert(id, string);

        Ok(())
    }

    fn parse_color_row(&mut self, row_data: &[u8]) -> Result<()> {
        let id = le_u16(row_data, 0x5)? as u32;
        let string = Self::parse_string(&row_data[8..])?;
        self.colors.insert(id, string);

        Ok(())
    }

    fn parse_genere_row(&mut self, row_data: &[u8]) -> Result<()> {
        let id = le_u32(row_data, 0x0)? as u32;
        let string = Self::parse_string(&row_data[4..])?;
        self.generes.insert(id, string);

        Ok(())
    }

    fn parse_key_row(&mut self, row_data: &[u8]) -> Result<()> {
        let id = le_u32(row_data, 0x0)? as u32;
        let string = Self::parse_string(&row_data[8..])?;
        self.keys.insert(id, string);

        Ok(())
    }

    fn parse_label_row(&mut self, row_data: &[u8]) -> Result<()> {
        let id = le_u32(row_data, 0x0)? as u32;
        let string = Self::parse_string(&row_data[4..])?;
        self.labels.insert(id, string);

        Ok(())
    }

    fn parse_track_row(&mut self, row_data: &[u8]) -> Result<()> {
        let sample_rate = le_u32(row_data, 0x08)?;
        let composer_id = le_u32(row_data, 0x0c)?;
        let file_size = le_u32(row_data, 0x10)?;
        let artwork_id = le_u32(row_data, 0x1c)?;
        let key_id = le_u32(row_data, 0x20)?;
        let org_artist_id = le_u32(row_data, 0x24)?;
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
                org_artist_id,
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

        if flags == 0x90 {
            // ISRC string
            let len = le_u16(data, 1)? as usize;
            if len < 6 {
                return Ok("".to_string());
            }
            Ok(String::from_utf8(data[5..(len - 1)].into())
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
            Ok(String::from_utf8(data[1..len].into())
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
        let reader = tokio::fs::File::open("src/test-data/export.pdb")
            .await
            .unwrap();
        let mut reader = tokio::io::BufReader::new(reader);
        let db = Database::parse(&mut reader).await.unwrap();
        println!("{:#?}", db);
    }
}
