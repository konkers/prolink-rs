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
}

#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    PeerJoined(Peer),
    PeerLeft(Peer),
    NewTrack(Track),
}
