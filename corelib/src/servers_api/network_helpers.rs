use std::time::SystemTime;

use axum::extract::ws::{Message, WebSocket};
use futures::lock::Mutex;
use futures::sink::SinkExt;
use futures::stream::SplitSink;
use log::*;
use versions::Versioning;

use crate::messages::{OnWireMessage, OnWireMessageWithMetaData};

pub async fn send_enum_app_message(
    app_msg: &OnWireMessage,
    sender: &mut Mutex<SplitSink<WebSocket, Message>>,
) {
    let server_reply_msg = OnWireMessageWithMetaData {
        onwire_msg: app_msg.to_owned(),
        sender_timestamp: SystemTime::now(),
        version: Versioning::new("0.3.0").unwrap().to_string(),
    };
    let encoded_reply_msg = serde_json::to_vec(&server_reply_msg).unwrap();
    let _ = sender
        .get_mut()
        .send(Message::Binary(encoded_reply_msg))
        .await;
}

pub async fn parse_wrapped_ws_msg(
    wrapped_ws_msg: Result<Message, axum::Error>,
) -> Option<OnWireMessageWithMetaData> {
    match wrapped_ws_msg {
        Ok(ws_msg) => {
            trace!("Received: {:?}", ws_msg);

            // Try to retrieve binary from the websocket package
            match ws_msg {
                Message::Binary(ws_binary) => {
                    let parsed_app_msg_w_meta: OnWireMessageWithMetaData =
                        serde_json::from_slice(&ws_binary)
                            .expect("Cannot deserialize received binary");
                    Some(parsed_app_msg_w_meta)
                }
                Message::Close(_) => None,
                _ => {
                    error!("Unsupported WS message type {:?}", ws_msg);
                    None
                }
            }
        }
        Err(e) => {
            error!("in receiving message: {:?}", e);
            None
        }
    }
}
