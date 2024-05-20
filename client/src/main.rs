extern crate chrono;
extern crate core;
extern crate ed25519_dalek;

use core::panic;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::TcpStream;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::str::from_utf8;
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use std::vec;

use corelib::client_api::client_struct_impl::*;

use chrono::offset::Local;
use chrono::DateTime;
use clap::Parser;
use colored::Colorize;
use ed25519_dalek::Keypair;
use log::*;
use openmls::prelude::{Credential, KeyPackage};
use rand::Rng;
use rand_07::rngs::OsRng;
use tungstenite::{stream::MaybeTlsStream, WebSocket};
use url::Url;
use versions::Versioning;

use config::ClientConfig;
use corelib::client_api::client_crypto_impl::{CryptoBackend, KeyStoreType};
use corelib::client_api::client_struct::{ClientDataProvider, ClientParsedMsg};
use corelib::client_api::{self, create_group_msg, show_group_state};
use corelib::client_api::{register_msg_as, register_msg_ds, sync_msg};
use corelib::messages::{OnWireMessage, OnWireMessageWithMetaData, UnorderedMsgContent};
use corelib::policyengine::policies::VoteOnNameChangePolicy;
use corelib::MsgSizeType::{IncomingMsg, OutgoingMsg};
use corelib::TimerType::*;
use corelib::{identity_to_str, CommGroupId, SingleMsgSizeMeasurement, SingleTimeMeasurement};
use local_struct::{ClientInput, ClientInputCommand, ReadOption};
use networking::finish_websocket;
use networking::get_websocket;
use process::group_onwire_msgs_for_ds;

mod config;
mod local_struct;
mod networking;
mod process;

const INVITE_COLOR: &str = "blue";
const SUCCESS_COLOR: &str = "green";
const FAILED_COLOR: &str = "red";

fn main() {
    // Client input parsing and validation
    let cli = ClientInput::parse();

    let cli_config: ClientConfig =
        confy::load_path("./CliClientConfig.yaml").expect("Could not parse client config.");

    let ds_url = Url::parse(&cli_config.ds_url_str).unwrap();
    let as_url = Url::parse(&cli_config.as_url_str).unwrap();

    let mut backend = CryptoBackend::default();
    let (client_data_opt, key_storage_opt) = read_local_saved_states(&cli_config);

    // Ensure initialized logger and valid command combination, and return initialized config
    let mut client_data = Box::new(validated_config(
        &cli,
        client_data_opt,
        key_storage_opt,
        &mut backend,
    )) as Box<dyn ClientDataProvider>;

    // Now that the client finished cold-starting, we start our process timer
    let client_begin_timestamp = Instant::now();

    // Ready the websockets
    let mut ws_ds = get_websocket(ds_url);
    let mut ws_as = get_websocket(as_url);

    SingleTimeMeasurement::new(EstablishWebsockets, client_begin_timestamp.elapsed());

    let mut can_retry = false;
    let mut n_trial = 0;
    let mut rng = rand::thread_rng();

    while (n_trial == 0) || (cli.auto_retry && can_retry) {
        if n_trial > 0 {
            let range = 0..(2_u32.pow(n_trial));
            let rand_slot = if !range.is_empty() {
                rng.gen_range(range)
            } else {
                0
            };
            let mut delay_sec: f32 = cli.window_size * (rand_slot as f32);
            delay_sec = delay_sec.min(cli.max_delay);
            let delay_dur = Duration::from_millis((delay_sec * 1000f32) as u64);
            SingleTimeMeasurement::new(InterRetryDelay, delay_dur);
            thread::sleep(delay_dur);
        }
        // Perform default pre-command sync
        let presync_begin_timestamp = Instant::now();
        if (!cli.no_sync) && cli.command.needs_pre_sync() {
            handle_sync_ds(client_data.deref(), &mut backend, &mut ws_ds, &cli_config);
            let msgs = read_ws_messages(&mut ws_ds);

            let parse_begin_timestamp = Instant::now();
            let local_plain_msgs =
                client_api::parse_incoming_onwire_msgs(msgs, &mut client_data, &mut backend);
            SingleTimeMeasurement::new(ParseIncomingMsgsPreSync, parse_begin_timestamp.elapsed());

            handle_sync_as(client_data.deref_mut(), &mut ws_as).unwrap();
            // Avoid printing non-json things when JSON output is expected
            if !cli.json {
                print_out_parsed_msgs(&local_plain_msgs);
            }
        }
        SingleTimeMeasurement::new(PreSyncTurnaround, presync_begin_timestamp.elapsed());

        // Perform default pre-group-operation Key package fetch
        let key_package_begin_timestamp = Instant::now();
        let external_key_packages_opt = match &cli.command {
            ClientInputCommand::Invite { invitee_names, .. } => {
                send_onwire_msg(
                    OnWireMessage::UserCredentialLookup {
                        user_name: client_data.get_user_id(),
                        queried_users: invitee_names.to_owned(),
                    },
                    &mut ws_as,
                );
                send_onwire_msg(
                    OnWireMessage::UserKeyPackageLookup {
                        user_name: client_data.get_user_id(),
                        queried_users: invitee_names.to_owned(),
                    },
                    &mut ws_ds,
                );
                let as_msgs = read_ws_messages(&mut ws_as);
                let ds_msgs = read_ws_messages(&mut ws_ds);

                let parse_kp_begin_timestamp = Instant::now();

                let (credentials, key_packages) = (
                    credentials_or_panic(as_msgs),
                    key_packages_or_panic(ds_msgs),
                );

                let credential_map: HashMap<String, Credential> = credentials
                    .iter()
                    .map(|credential| {
                        (
                            identity_to_str(credential.identity())
                                .expect("Cannot convert identity to string"),
                            credential.clone(),
                        )
                    })
                    .collect();

                for key_package in key_packages.iter() {
                    let key_package_identity = identity_to_str(key_package.credential().identity())
                        .expect("Cannot convert key package identity to string");

                    let credential = credential_map.get(&key_package_identity).expect("Assertion failed: No matching credential found for identity: {key_package_identity}");

                    assert_eq!(
                        credential,
                        key_package.credential(),
                        "Assertion failed for identity: {}",
                        key_package_identity
                    );

                    key_package.verify(&backend).expect(
                        "Cannot continue: Cannot verify signature for {key_package_identity}",
                    );
                }

                SingleTimeMeasurement::new(
                    ParseIncomingMsgsKeyPackage,
                    parse_kp_begin_timestamp.elapsed(),
                );

                Some(key_packages)
            }
            _ => None,
        };
        SingleTimeMeasurement::new(
            KeyPackageRequestTurnaround,
            key_package_begin_timestamp.elapsed(),
        );

        // handle command
        let handle_non_sync_command_start = Instant::now();
        match &cli.command {
            ClientInputCommand::Sync => (), //Because already Synced (unless `sync --no-sync`, which is undefined)
            ClientInputCommand::Register { ref name } => {
                assert_eq!(name.to_string(), client_data.get_user_id());
                assert_eq!(
                    name.to_string(),
                    from_utf8(client_data.get_credential().identity())
                        .unwrap()
                        .to_string()
                );
                handle_register(
                    &mut backend,
                    &mut ws_as,
                    &mut ws_ds,
                    client_data.deref(),
                    &cli_config,
                );
            }
            ClientInputCommand::Read {
                community_id,
                group_id,
                option,
            } => handle_read(
                client_data
                    .as_any_mut()
                    .downcast_mut::<ClientData>()
                    .unwrap(),
                community_id,
                group_id,
                option,
                cli.json,
            ),
            ClientInputCommand::ShowGroupState {
                community_id,
                group_id,
            } => show_group_state(
                &CommGroupId::new(community_id, group_id),
                client_data.deref_mut(),
            ),
            ClientInputCommand::Create {
                group_id,
                community_id,
            } => {
                create_group_msg(
                    &client_data.deref_mut().get_user_id(),
                    &CommGroupId::new(community_id, group_id),
                    &mut backend,
                    client_data.deref_mut(),
                );
            }
            _ => {
                // group-related command case
                let create_msg_begin_timestamp = Instant::now();
                let onwire_msgs = group_onwire_msgs_for_ds(
                    &cli.command,
                    &mut backend,
                    &mut client_data,
                    external_key_packages_opt,
                );
                SingleTimeMeasurement::new(
                    MlsGovNonSyncKpFetchRequestGeneration,
                    create_msg_begin_timestamp.elapsed(),
                );

                if !onwire_msgs.is_empty() {
                    send_onwire_msgs(onwire_msgs, &mut ws_ds);
                }

                let parsed_msgs = client_api::parse_incoming_onwire_msgs(
                    read_ws_messages(&mut ws_ds),
                    &mut client_data,
                    &mut backend,
                );

                print_out_parsed_msgs(&parsed_msgs);
                debug!("parsed_msgs: {:?}", parsed_msgs);
                can_retry = determine_if_retry(&parsed_msgs);
            }
        }
        SingleTimeMeasurement::new(
            NonSyncKPFetchRequestTurnaround,
            handle_non_sync_command_start.elapsed(),
        );
        n_trial += 1;
    }

    // Close WSs
    let close_timestamp = Instant::now();
    finish_websocket(&mut ws_ds);
    finish_websocket(&mut ws_as);

    SingleTimeMeasurement::new(CloseWebsockets, close_timestamp.elapsed());

    //Before storing data, print out the timestamp
    SingleTimeMeasurement::new(TotalEndToEnd, client_begin_timestamp.elapsed());

    // store states before exit
    if !cli.skip_store {
        store_states(&client_data, &backend, &cli_config);
    } else {
        warn!("Skipping storing local states. Dev only. If MLS group state updated, this will cause branch group states");
    }
}

pub(crate) fn read_local_saved_states(
    client_config: &ClientConfig,
) -> (Option<ClientData>, Option<KeyStoreType>) {
    let mut client_config_opt: Option<ClientData> = None;
    let client_str: String = confy::load_path(&client_config.data_path).expect("could not decode");
    if Path::new(&client_config.data_path).exists() {
        client_config_opt = match serde_json::from_str(&client_str) {
            Ok(config) => Some(config),
            Err(e) => {
                error!("Cannot load ClientData using confy:{:?}", e);
                None
            }
        };
    } else {
        info!("Starting Client Data fresh as no local saved states found");
    }

    let key_storage_opt: Option<KeyStoreType> = match confy::load_path(&client_config.keystore_path)
    {
        Ok(keystore) => Some(keystore),
        Err(e) => {
            error!("Cannot decode keystore: {:?}", e);
            None
        }
    };
    (client_config_opt, key_storage_opt)
}

fn store_states(
    client_data: &Box<dyn ClientDataProvider>,
    backend: &CryptoBackend,
    client_config: &ClientConfig,
) {
    let client_ref: &ClientData = client_data
        .as_any()
        .downcast_ref::<ClientData>()
        .expect("could not properly convert client box");
    confy::store_path(&client_config.data_path, client_ref.to_string())
        .expect("Client data saving failed.");
    confy::store_path(
        &client_config.keystore_path,
        backend.key_store.get_key_store_copy(),
    )
    .expect("Client KeyStore saving failed.");
}

pub(crate) fn validated_config(
    cli: &ClientInput,
    mut client_config_opt: Option<ClientData>,
    mut key_storage_opt: Option<KeyStoreType>,
    backend: &mut CryptoBackend,
) -> ClientData {
    if cli.fresh_start {
        client_config_opt = None;
        key_storage_opt = None;
    }

    let mut logger = env_logger::Builder::new();
    match cli.verbose {
        0 => logger.filter_level(LevelFilter::Info),
        1 => logger
            .filter_level(LevelFilter::Debug)
            .filter_module("openmls", LevelFilter::Error),
        _ => logger
            .filter_module("client", LevelFilter::Trace)
            .filter_level(LevelFilter::Info),
    };

    logger.init();

    if cli.no_sync && cli.command == ClientInputCommand::Sync {
        panic!("Cannot sync with no sync");
    }

    // Must register first for all non-register commands
    match &cli.command {
        ClientInputCommand::Register { name } => {
            let credential_bundle =
                backend.generate_credential_bundle(name.to_owned().into_bytes(), None, None);
            backend.store_credential_bundle(&credential_bundle);
            let mut csprng = OsRng {};
            let mut client_data = ClientData::new(
                name.to_owned(),
                credential_bundle.credential().to_owned(),
                Keypair::generate(&mut csprng),
            );
            client_data.set_client_policies(vec![Box::new(VoteOnNameChangePolicy::new())]);
            client_config_opt = Some(client_data);
        }
        _ => match client_config_opt {
            Some(ref config) => {
                match key_storage_opt {
                    None => {
                        error!("Cannot find corresponding UserKeyStore. Local key database reset.")
                    }
                    Some(key_storage) => backend.key_store.replace_from(key_storage),
                }
                info!("Welcome back, {}", config.user_name)
            }
            None => panic!("Please register first."),
        },
    }

    debug!("Input commands: {:?}", &cli);
    if let Some(mut client_config) = client_config_opt {
        client_config.skip_updating_msg_history = cli.skip_history_msg_update;
        return client_config;
    }
    client_config_opt.unwrap()
}

/// Send a sync message to the DS
fn handle_sync_ds(
    client_data: &(impl ClientDataProvider + ?Sized),
    backend: &mut CryptoBackend,
    websocket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    client_config: &ClientConfig,
) {
    let mut new_key_packages = vec![];
    for _ in 0..client_config.new_key_packages_per_sync {
        new_key_packages.push(
            backend.generate_default_key_package_and_store_bundle(&client_data.get_credential()),
        )
    }
    send_onwire_msg(sync_msg(client_data, new_key_packages), websocket);
}

/// Send a sync message to the AS, which responds with a list of every
/// CredentialEntry it currently stores. This function returns that list
/// as as a Vec.
fn handle_sync_as(
    config: &mut (impl ClientDataProvider + ?Sized),
    ws_as: &mut WebSocket<MaybeTlsStream<TcpStream>>,
) -> Result<(), ()> {
    let sync_credentials_msg = OnWireMessage::UserSyncCredentials;
    send_onwire_msg(sync_credentials_msg, ws_as);
    let mut resp = read_ws_messages(ws_as);
    if let OnWireMessage::ASCredentialSyncResponse { credentials } = &mut resp[0] {
        config.set_credential_entries(std::mem::take(credentials));
        Ok(())
    } else {
        Err(())
    }
}

fn handle_register(
    backend: &mut CryptoBackend,
    ws_as: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    ws_ds: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    client_data: &(impl ClientDataProvider + ?Sized),
    client_config: &ClientConfig,
) {
    let credential_bundle = backend.read_credential_bundle(&client_data.get_credential());

    //AS Registration
    send_onwire_msgs(
        register_msg_as(
            credential_bundle.credential().to_owned(),
            client_data.get_keypair().public_key(),
        ),
        ws_as,
    );
    oks_or_panic(read_ws_messages(ws_as));

    //DS Registration
    let mut new_key_packages = vec![];
    for _ in 0..client_config.new_key_packages_per_sync {
        new_key_packages.push(
            backend.generate_default_key_package_and_store_bundle(credential_bundle.credential()),
        )
    }
    send_onwire_msgs(register_msg_ds(new_key_packages), ws_ds);
    oks_or_panic(read_ws_messages(ws_ds));
}

fn handle_read(
    client_config: &mut ClientData,
    community_id: &String,
    group_id: &String,
    read_option_input: &Option<ReadOption>,
    print_json: bool,
) {
    let read_option = read_option_input.clone().unwrap_or_default();

    let user_id = client_config.get_user_id();
    let group = client_config.get_mut_group_state(&CommGroupId::new(community_id, group_id));
    let mut messages = vec![];
    match read_option {
        ReadOption::Unread => {
            let mut remaining_other_msg_count = group.unread_msgs_count;
            for history_msg in &group.history {
                messages.push(history_msg);
                if history_msg.sender != user_id {
                    remaining_other_msg_count -= 1;
                }
                if remaining_other_msg_count == 0 {
                    break;
                }
            }
            group.unread_msgs_count = 0;
        }
        ReadOption::Last { n_message } => {
            let mut remaining_msg_count = n_message;
            for history_msg in &group.history {
                if remaining_msg_count == 0 {
                    break;
                }
                messages.push(history_msg);
                if (history_msg).sender != user_id {
                    remaining_msg_count -= 1;
                }
            }
            group.unread_msgs_count = 0;
        }
        ReadOption::All => {
            for history_msg in &group.history {
                messages.push(history_msg);
            }
        }
    };
    // Message are from new to old. reverse and print
    messages.reverse();
    if print_json {
        print_out_local_history_msg_json(messages);
        warn!("`nano_since_epoch` is incorrect in the JSON output. Use `sec_since_epoch` instead");
    } else {
        print_out_local_history_msg_plaintext(messages, community_id, group_id);
    }
}

fn send_onwire_msgs(
    on_wire_msgs: Vec<OnWireMessage>,
    websocket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
) {
    for on_wire_msg in on_wire_msgs {
        send_onwire_msg(on_wire_msg, websocket);
        debug!("A message was sent to DS")
    }
}

fn send_onwire_msg(
    onwire_msg: OnWireMessage,
    websocket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
) {
    let onwire_msg_w_meta = OnWireMessageWithMetaData {
        onwire_msg: onwire_msg.to_owned(),
        sender_timestamp: SystemTime::now(),
        version: Versioning::new("0.3.0").unwrap().to_string(),
    };
    let encoded = serde_json::to_vec(&onwire_msg_w_meta).expect("Cannot encode app msg");

    let encoded_size = encoded.len();

    let pre_send_timestamp = Instant::now();

    match websocket.write_message(tungstenite::Message::Binary(encoded)) {
        Ok(_) => {
            trace!("Sent message via websocket: [{:?}]", onwire_msg);
            let duration = pre_send_timestamp.elapsed();
            SingleTimeMeasurement::new(SingleSendMessageDelay, duration);
            SingleMsgSizeMeasurement::new(OutgoingMsg, encoded_size);
            return;
        }
        Err(e) => error!(
            "Unable to send message via websocket:  {:?} [{:?}]",
            e, &onwire_msg
        ),
    }
    websocket.write_pending().unwrap();
}

fn read_ws_messages(websocket: &mut WebSocket<MaybeTlsStream<TcpStream>>) -> Vec<OnWireMessage> {
    let pre_read_timestamp = Instant::now();
    let mut onwire_msgs = vec![];
    'ws_reading: while let Ok(msg) = websocket.read_message() {
        match msg {
            tungstenite::Message::Binary(encoded) => {
                SingleMsgSizeMeasurement::new(IncomingMsg, encoded.len());
                let decode_result: serde_json::Result<OnWireMessageWithMetaData> =
                    serde_json::from_slice(&encoded);
                if let Ok(decoded) = decode_result {
                    onwire_msgs.push(decoded.onwire_msg.to_owned());
                    match &decoded.onwire_msg {
                        OnWireMessage::DSResult { .. } | OnWireMessage::ASResult { .. } => {
                            break 'ws_reading;
                        }
                        _ => {
                            if decoded.onwire_msg.is_user_msg() {
                                panic!(
                                    "Received client message type from server. {:?}",
                                    &decoded.onwire_msg
                                )
                            }
                        }
                    };
                }
            }

            _ => panic!("Error: Unsupported WS Message type: {}", msg),
        }
    }

    SingleTimeMeasurement::new(ReadWebSocketMsgsDelay, pre_read_timestamp.elapsed());

    onwire_msgs
}

fn determine_if_retry(msgs: &Vec<ClientParsedMsg>) -> bool {
    let mut result = false;
    for msg in msgs {
        match msg {
            ClientParsedMsg::Invalid {
                external_error,
                retry_possible,
                description,
            } => {
                if !*external_error {
                    error!("{}", description);
                } else {
                    warn!("{}", description);
                }
                if *retry_possible {
                    info!("Please retry, or would be auto retried.");
                    result = true;
                }
            }
            ClientParsedMsg::NewInvite { .. }
            | ClientParsedMsg::NewMsg { .. }
            | ClientParsedMsg::NewOrdMsg { .. }
            | ClientParsedMsg::ASFeedback { .. }
            | ClientParsedMsg::DSFeedback { .. } => {}
        }
    }
    result
}

fn print_out_parsed_msgs(msgs: &Vec<ClientParsedMsg>) {
    let mut message_group_to_count: HashMap<(String, String), u64> = HashMap::new();
    for msg in msgs {
        match msg {
            ClientParsedMsg::NewMsg {
                private_msg: _,
                comm_grp,
            } => match message_group_to_count.entry((comm_grp.community_id(), comm_grp.group_id()))
            {
                Entry::Occupied(mut e) => {
                    *e.get_mut() += 1;
                }
                Entry::Vacant(e) => {
                    e.insert(1);
                }
            },
            ClientParsedMsg::NewOrdMsg { .. } => {
                // TODO(78): Figure out if we need to modify print_out_parsed_msgs for ord app msg
            }
            ClientParsedMsg::NewInvite { inviter, comm_grp } => {
                info!(
                    "{} User [{inviter}] invited you to join {:?}. Respond with Accept or Decline",
                    "Invite:".color(INVITE_COLOR),
                    comm_grp
                )
            }
            ClientParsedMsg::ASFeedback {
                request_valid,
                explanation,
                process_time,
            } => {
                print_out_feedback(request_valid, explanation);
                SingleTimeMeasurement::new(SingleUserRequestASProcessTime, *process_time);
                // Same as in ok_or_panic()
            }
            ClientParsedMsg::DSFeedback {
                request_valid,
                explanation,
                process_time,
            } => {
                print_out_feedback(request_valid, explanation);
                SingleTimeMeasurement::new(SingleUserRequestDSProcessTime, *process_time);
                // Same as in ok_or_panic()
            }
            ClientParsedMsg::Invalid {
                external_error,
                retry_possible,
                description,
            } => {
                if !external_error {
                    error!("{}", description);
                    if *retry_possible {
                        info!("Please retry, or would be auto retried.");
                    }
                } else {
                    warn!("External message errorL {}", description);
                }
            }
        }
    }
    let empty = message_group_to_count.is_empty();
    for ((community_id, group_id), count) in message_group_to_count {
        println!("You have {count} messages from community[{community_id}] group[{group_id}]");
    }
    if !empty {
        info!("Use `Read` command to read above messages");
    }
}

fn print_out_feedback(request_valid: &bool, explanation: &Option<String>) {
    let result = match request_valid {
        true => "Success: ",
        false => "Failed: ",
    };
    if !request_valid {
        error!(
            "{}{}",
            result.color(FAILED_COLOR),
            explanation.clone().unwrap_or_default()
        );
    } else {
        info!(
            "{}{}",
            result.color(SUCCESS_COLOR),
            explanation.clone().unwrap_or_default()
        );
    }
}

fn print_out_local_history_msg_plaintext(
    messages: Vec<&LocalHistoryMessage>,
    community_id: &String,
    group_id: &String,
) {
    println!("Messages from community [{community_id}] group [{group_id}]");
    for msg in messages {
        let datetime: DateTime<Local> = msg.received_timestamp.into();
        match &msg.message.content {
            UnorderedMsgContent::Text { text_content } => println!(
                "[Msg {}] [{}]: {}",
                datetime.format("%d/%m/%Y %T"),
                msg.sender,
                text_content,
            ),
            _ => println!("Content: {:?}", msg.message.content),
        }
    }
}

fn print_out_local_history_msg_json(messages: Vec<&LocalHistoryMessage>) {
    for msg in messages {
        println!("{}", serde_json::to_string_pretty(msg).unwrap());
    }
}

fn oks_or_panic(msgs: Vec<OnWireMessage>) {
    for msg in msgs {
        if msg.is_user_msg() {
            panic!("Received user message from servers");
        }
        match msg {
            OnWireMessage::ASResult {
                request_valid,
                explanation,
                process_time_used,
            } => {
                if !request_valid {
                    panic!(
                        "Failed operation. Explanation: {:?}",
                        explanation.unwrap_or_default()
                    )
                } else {
                    info!("Operation success {:?}", explanation.unwrap_or_default())
                };

                SingleTimeMeasurement::new(SingleUserRequestASProcessTime, process_time_used);
            }
            OnWireMessage::DSResult {
                request_valid,
                explanation,
                process_time_used,
                ..
            } => {
                if !request_valid {
                    panic!(
                        "Failed operation. Explanation: {:?}",
                        explanation.unwrap_or_default()
                    );
                } else {
                    info!("Operation success {:?}", explanation.unwrap_or_default());
                }
                SingleTimeMeasurement::new(SingleUserRequestDSProcessTime, process_time_used);
                // Same as used in print_out_parsed_msgs
            }
            _ => {}
        }
    }
}

fn credentials_or_panic(msgs: Vec<OnWireMessage>) -> Vec<Credential> {
    for msg in msgs {
        if msg.is_user_msg() {
            panic!("Received user message from servers");
        }
        match msg {
            OnWireMessage::ASResult {
                request_valid,
                explanation,
                ..
            }
            | OnWireMessage::DSResult {
                request_valid,
                explanation,
                ..
            } => {
                if !request_valid {
                    panic!("Failed operation. Explanation: {:?}", explanation);
                } else {
                    info!("Operation success {:?}", explanation);
                }
            }
            OnWireMessage::ASCredentialResponse {
                queried_user_credentials,
            } => {
                return queried_user_credentials;
            }
            unk => {
                debug!("Unexpected app msg: {:?}", unk);
            }
        }
    }
    panic!("No credential response from AS");
}

fn key_packages_or_panic(msgs: Vec<OnWireMessage>) -> Vec<KeyPackage> {
    for msg in msgs {
        if msg.is_user_msg() {
            panic!("Received user message from servers");
        }
        match msg {
            OnWireMessage::ASResult {
                request_valid,
                explanation,
                ..
            }
            | OnWireMessage::DSResult {
                request_valid,
                explanation,
                ..
            } => {
                if !request_valid {
                    panic!("Failed operation. Explanation: {:?}", explanation);
                } else {
                    info!("Operation success {:?}", explanation);
                }
            }
            OnWireMessage::DSKeyPackageResponse {
                queried_user_key_packages,
            } => {
                return queried_user_key_packages;
            }
            unk => {
                debug!("Unexpected app msg: {:?}", unk);
            }
        }
    }
    panic!("No credential response from AS");
}

#[cfg(test)]
mod client_tests {
    use ed25519_dalek::Keypair;
    use rand::{
        distributions::{Alphanumeric, DistString},
        Rng,
    };
    use rand_07::rngs::OsRng;

    use crate::client_api::client_struct_impl::ClientData;
    use corelib::client_api::client_crypto_impl::CryptoBackend;

    use crate::{validated_config, ClientInput};

    fn get_test_config(user_name: &String, backend: &mut CryptoBackend) -> Option<ClientData> {
        let mut csprng = OsRng {};
        Some(ClientData::new(
            user_name.to_owned(),
            backend
                .generate_credential_bundle((&user_name).to_string().into_bytes(), None, None)
                .credential()
                .to_owned(),
            Keypair::generate(&mut csprng),
        ))
    }

    #[test]
    #[should_panic]
    fn did_not_register_panic1() {
        // Fresh start flag on but not register, should panic.
        let mut rng = rand::thread_rng();
        let mut backend = CryptoBackend::default();
        let random_id = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
        let input = ClientInput {
            command: crate::ClientInputCommand::Sync,
            verbose: rng.gen::<u8>(),
            json: rng.gen::<bool>(),
            no_sync: false,
            skip_store: false,
            skip_history_msg_update: false,
            fresh_start: true,
            auto_retry: false,
            max_delay: 0.0,
            window_size: 0.0,
        };

        let _ = validated_config(
            &input,
            get_test_config(&random_id, &mut backend),
            None,
            &mut backend,
        );
    }

    #[test]
    #[should_panic]
    fn did_not_register_panic2() {
        // Simply never registered but ask for sync; should panic.
        let mut rng = rand::thread_rng();
        let mut backend = CryptoBackend::default();
        let input = ClientInput {
            command: crate::ClientInputCommand::Sync,
            verbose: rng.gen::<u8>(),
            json: rng.gen::<bool>(),
            no_sync: false,
            skip_store: false,
            skip_history_msg_update: false,
            fresh_start: false,
            auto_retry: false,
            max_delay: 0.0,
            window_size: 0.0,
        };
        let _ = validated_config(&input, None, None, &mut backend);
    }
}
