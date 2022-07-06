use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::{collections::HashMap, io::SeekFrom};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};

use crate::Result;

#[derive(Debug, Eq, FromPrimitive, Hash, PartialEq)]
#[repr(u32)]
pub enum TableType {
    Tracks = 0x00,
    Geners = 0x01,
    Artists = 0x02,
    Albums = 0x03,
    Lables = 0x04,
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
pub struct Database {
    page_size: u32,
    num_tables: u32,
    sequence: u32,

    table_pointers: HashMap<TableType, TablePointer>,
}

impl Database {
    pub async fn parse<R: AsyncRead + AsyncSeek + Unpin>(r: &mut R) -> Result<Database> {
        r.seek(SeekFrom::Start(4)).await?;
        let page_size = r.read_u32_le().await?;
        let num_tables = r.read_u32_le().await?;
        r.seek(SeekFrom::Current(8)).await?;
        let sequence = r.read_u32_le().await?;
        r.seek(SeekFrom::Current(4)).await?;

        let mut table_pointers = HashMap::new();

        for _ in 0..num_tables {
            let table_type: Option<TableType> = FromPrimitive::from_u32(r.read_u32_le().await?);
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
            }
        }

        Ok(Database {
            page_size,
            num_tables,
            sequence,
            table_pointers,
        })
    }
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
        println!("{:?}", db);
    }
}
