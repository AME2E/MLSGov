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

use config::DeliveryServiceConfig;
use corelib::messages::OnWireMessage;
use corelib::servers_api::ds_structs::{
    DeliveryServiceParam, DeliveryServiceState, SharedDeliverServiceState,
};
use corelib::servers_api::handle_onwire_msg_ds_local;
use corelib::servers_api::network_helpers::{parse_wrapped_ws_msg, send_enum_app_message};

use crate::cli_struct::CliDS;

mod cli_struct;
mod config;

#[tokio::main]
async fn main() {
    let local_cli_param: CliDS = CliDS::try_parse().expect("Input error");

    let ds_param = DeliveryServiceParam {
        verbose: local_cli_param.verbose,
        persistent_state: !local_cli_param.non_persistent,
    };

    let ds_config: DeliveryServiceConfig =
        confy::load_path("./DeliveryServiceConfig.yaml").expect("Could not parse DS config.");

    let ip_addr: Ipv4Addr = ds_config
        .ip_address
        .parse()
        .expect("Could not parse IP address.");
    let port: u16 = ds_config.port;

    let sock_addr = SocketAddr::from((IpAddr::V4(ip_addr), port));

    let mut logger = env_logger::Builder::new();
    match local_cli_param.verbose {
        0 => logger.filter_level(LevelFilter::Info),
        1 => logger.filter_level(LevelFilter::Debug),
        _ => logger.filter_level(LevelFilter::Trace),
    };
    logger.init();

    let server_state: Arc<SharedDeliverServiceState> =
        recover_state(&local_cli_param, &ds_config).await;

    let app: Router = Router::new()
        .route("/", get(websocket_handler))
        .layer(Extension((server_state, ds_config, ds_param)));

    tracing::debug!("listening on {}", sock_addr);
    axum::Server::bind(&sock_addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[debug_handler]
async fn websocket_handler(
    ws: WebSocketUpgrade,
    Extension((state, config, param)): Extension<(
        Arc<SharedDeliverServiceState>,
        DeliveryServiceConfig,
        DeliveryServiceParam,
    )>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| websocket(socket, state, config, param))
}

async fn websocket(
    stream: WebSocket,
    state: Arc<SharedDeliverServiceState>,
    config: DeliveryServiceConfig,
    param: DeliveryServiceParam,
) {
    // By splitting we can send and receive at the same time.
    let (sender, mut receiver) = stream.split();
    let mut shared_sender = Mutex::new(sender);

    // Loop until a text message is found.
    while let Some(received_message) = receiver.next().await {
        match parse_wrapped_ws_msg(received_message).await {
            None => (),
            Some(onwire_msg_w_data) => {
                respond_onwire_msg(onwire_msg_w_data.onwire_msg, &mut shared_sender, &state).await;
            }
        }
    }
    if param.persistent_state {
        // Save all data of the delivery_service
        store_state(Arc::clone(&state).deref().clone(), &config).await;
        let _ = state; // Prolong lifetime of state
    }
}

async fn store_state(state: DeliveryServiceState, config: &DeliveryServiceConfig) {
    match confy::store_path(&config.data_path, state) {
        Ok(_) => {
            info!("Server state save successfully\n");
        }
        Err(e) => {
            error!("in Server state saving: {:?}", e);
        }
    }
}

async fn recover_state(
    local_cli_param: &CliDS,
    config: &DeliveryServiceConfig,
) -> Arc<SharedDeliverServiceState> {
    Arc::new(match &local_cli_param.fresh_start {
        false => match confy::load_path(&config.data_path) {
            Ok(state) => {
                debug!("Restore states successfully");
                state
            }
            Err(_) => {
                warn!("Starting fresh (no local record found or was incompatible)");
                DeliveryServiceState::new()
            }
        },

        true => {
            println!("Starting fresh as requested");
            // Remove cached result
            store_state(DeliveryServiceState::new(), config).await;
            // Return a fresh result
            DeliveryServiceState::new()
        }
    })
}

async fn respond_onwire_msg(
    onwire_msg: OnWireMessage,
    sender: &mut Mutex<SplitSink<WebSocket, Message>>,
    shared_state: &Arc<SharedDeliverServiceState>,
) {
    trace!("Decoded: {:?}", onwire_msg);

    let reply_msg_queue = handle_onwire_msg_ds_local(onwire_msg, shared_state).await;
    for reply_msg in reply_msg_queue {
        send_enum_app_message(&reply_msg, sender).await;
    }
}
