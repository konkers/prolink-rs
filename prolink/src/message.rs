pub use crate::tasks::metadata::TrackMetadata;
#[derive(Clone, Debug, PartialEq)]
pub struct Peer {
    pub name: String,
    pub device_num: u8,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Track {
    pub player_device: u8,
    pub track_device: u8,
    pub track_slot: u8,
    pub track_type: u8,
    pub rekordbox_id: u32,
    pub metadata: Option<TrackMetadata>,
    pub artwork: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Beat {
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

#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    PeerJoined(Peer),
    PeerLeft(Peer),
    NewTrack(Track),
    Beat(Beat),
}
