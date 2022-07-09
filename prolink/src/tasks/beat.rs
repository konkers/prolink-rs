use log::debug;
use tokio::{net::UdpSocket, sync::mpsc};

use crate::{
    message,
    proto::{self, BeatPacket},
    Message, Result,
};

pub(crate) struct BeatTask {
    socket: UdpSocket,
    msg_tx: mpsc::Sender<Message>,
}

impl BeatTask {
    pub(crate) async fn new(msg_tx: mpsc::Sender<Message>) -> Result<BeatTask> {
        let socket = UdpSocket::bind("0.0.0.0:50001").await?;
        Ok(BeatTask { socket, msg_tx })
    }
    pub(crate) async fn run(mut self) -> Result<()> {
        let mut buf = [0; 4096];
        loop {
            tokio::select! {
                _ = self.msg_tx.closed() => {
                    return Ok(())
                }
                res = self.socket.recv_from(&mut buf) => {
                    if let Ok((len, _src)) = res {
                        let buf = &buf[0..len];
                        match  proto::Packet::parse(buf) {
                            Ok(pkt) => self.handle_packet(&pkt).await?,
                            Err(e) => debug!(target: "prolink", "error parsing packet {:x?}", e),
                        }
                    }
                }
            }
        }
    }

    async fn handle_packet(&mut self, pkt: &proto::Packet) -> Result<()> {
        match &pkt {
            &proto::Packet::Beat(beat) => self.handle_beat_packet(&beat).await?,
            _ => (),
        }
        Ok(())
    }

    async fn handle_beat_packet(&mut self, beat: &BeatPacket) -> Result<()> {
        self.msg_tx
            .send(Message::Beat(message::Beat {
                device_num: beat.device_num,
                next_beat: beat.next_beat,
                second_beat: beat.second_beat,
                next_bar: beat.next_bar,
                fourth_beat: beat.fourth_beat,
                second_bar: beat.second_bar,
                eighth_beat: beat.eighth_beat,
                pitch: beat.pitch,
                bpm: beat.bpm,
                beat: beat.beat,
            }))
            .await?;

        Ok(())
    }
}
