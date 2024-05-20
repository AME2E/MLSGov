use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::{extract::Extension, response::IntoResponse, routing::get, Router};
use axum_macros::debug_handler;
use clap::Parser;
use futures::lock::Mutex;
use futures::stream::SplitSink;
use futures::stream::StreamExt;
use log::*;

use config::AuthServiceConfig;
use corelib::messages::OnWireMessage;
use corelib::servers_api::network_helpers::{parse_wrapped_ws_msg, send_enum_app_message};
use corelib::servers_api::{as_struct::*, handle_onwire_msg_as_local};

use crate::cli_struct::CliAS;

mod cli_struct;
mod config;

#[tokio::main]
async fn main() {
    let local_cli_param: CliAS = CliAS::try_parse().expect("Input error");

    let as_param = AuthServiceParam {
        verbose: 0,
        persistent_state: !local_cli_param.non_persistent,
    };

    let as_config: AuthServiceConfig =
        confy::load_path("./AuthServiceConfig.yaml").expect("Could not parse AS config.");

    let ip_addr: Ipv4Addr = as_config
        .ip_address
        .parse()
        .expect("Could not parse IP address.");
    let port: u16 = as_config.port;

    let sock_addr = SocketAddr::from((IpAddr::V4(ip_addr), port));

    let mut logger = env_logger::Builder::new();
    match local_cli_param.verbose {
        0 => logger.filter_level(LevelFilter::Info),
        1 => logger.filter_level(LevelFilter::Debug),
        _ => logger.filter_level(LevelFilter::Trace),
    };
    logger.init();

    let server_state: Arc<SharedAuthServiceState> = match &local_cli_param.fresh_start {
        false => Arc::new({
            if let Ok(state) = confy::load_path(&as_config.data_path) {
                state
            } else {
                warn!("Starting fresh (cannot find or restore states)");
                store_state(AuthServiceState::new(), &as_config).await;
                AuthServiceState::new()
            }
        }),

        true => {
            info!("Starting fresh as requested");
            // Remove cached result
            store_state(AuthServiceState::new(), &as_config).await;
            // Return a fresh result
            Arc::new(AuthServiceState::new())
        }
    };

    let app: Router = Router::new()
        .route("/", get(websocket_handler))
        .layer(Extension((server_state, as_config, as_param)));

    tracing::debug!("listening on {}", sock_addr);
    axum::Server::bind(&sock_addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[debug_handler]
async fn websocket_handler(
    ws: WebSocketUpgrade,
    Extension((state, as_config, as_param)): Extension<(
        Arc<SharedAuthServiceState>,
        AuthServiceConfig,
        AuthServiceParam,
    )>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| websocket(socket, state, as_config, as_param))
}

async fn websocket(
    stream: WebSocket,
    state: Arc<SharedAuthServiceState>,
    as_config: AuthServiceConfig,
    as_param: AuthServiceParam,
) {
    // By splitting we can send and receive at the same time.
    let (sender, mut receiver) = stream.split();
    let mut shared_sender = Mutex::new(sender);

    // Loop until a text message is found.
    while let Some(received_message) = receiver.next().await {
        match parse_wrapped_ws_msg(received_message).await {
            None => {}
            Some(app_msg_w_meta) => {
                respond_onwire_msg(app_msg_w_meta.onwire_msg, &mut shared_sender, &state).await;
            }
        }
    }
    if as_param.persistent_state {
        // Save all data of the server
        store_state(Arc::clone(&state).deref().clone(), &as_config).await;
        let _ = state; // Prolong lifetime of state
    }
}

async fn store_state(state: AuthServiceState, as_config: &AuthServiceConfig) {
    match confy::store_path(&as_config.data_path, state) {
        Ok(_) => {
            info!("Server state save successfully\n");
        }
        Err(e) => {
            error!("in Server state saving: {:?}", e);
        }
    }
}

async fn respond_onwire_msg(
    onwire_msg: OnWireMessage,
    sender: &mut Mutex<SplitSink<WebSocket, Message>>,
    shared_state: &Arc<SharedAuthServiceState>,
) {
    debug!("Decoded: {:?}", onwire_msg);

    let reply_msg_queue = handle_onwire_msg_as_local(onwire_msg, shared_state).await;
    for reply_msg in reply_msg_queue {
        send_enum_app_message(&reply_msg, sender).await;
    }
}
