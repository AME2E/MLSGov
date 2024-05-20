use std::net::TcpStream;

use log::*;
use tungstenite::{
    connect,
    protocol::{frame::coding::CloseCode, CloseFrame},
    stream::MaybeTlsStream,
    WebSocket,
};
use url::Url;

pub(crate) fn get_websocket(url: Url) -> WebSocket<MaybeTlsStream<TcpStream>> {
    let (websocket, initial_response) = connect(url).expect("Can't connect");
    for (ref header, _value) in initial_response.headers() {
        trace!("Websocket Header: * {}", header);
    }
    websocket
}

pub(crate) fn finish_websocket(websocket: &mut WebSocket<MaybeTlsStream<TcpStream>>) {
    websocket
        .close(Some(CloseFrame {
            code: CloseCode::Normal,
            reason: std::borrow::Cow::Borrowed("Client finishes"),
        }))
        .unwrap();
}
