//! A un-networked module to handle incoming user commands:
//!  produce side effects on local server states;
//!  does not handle network, but all `user_*` functions return
//!  a list of OnWireMessage to be sent to the client

use std::sync::Arc;
use std::time::{Instant, SystemTime};
use std::vec;

use dashmap::mapref::entry::Entry::*;
use log::*;
use openmls::messages::Welcome;
use openmls::prelude::KeyPackage;

use ds_structs::local_message_struct::{Invite, ProtectedMessageWithMetaData};
use ds_structs::SharedDeliverServiceState;

use crate::identity_to_str;
use crate::messages::GroupMessage;
use crate::messages::UserRequestErrors::*;
use crate::messages::{OnWireMessage, UserRequestErrors};
use crate::CommGroupId;

use self::as_struct::CredentialEntry;
use self::as_struct::SharedAuthServiceState;

pub mod as_struct;
pub mod ds_structs;
pub mod mls_helpers;
pub mod network_helpers;

const MAX_KEY_PACKAGES_PER_USER: usize = 20;

pub async fn handle_onwire_msg_ds_local(
    onwire_msg: OnWireMessage,
    shared_state: &Arc<SharedDeliverServiceState>,
) -> Vec<OnWireMessage> {
    let begin_timestamp = Instant::now();
    // Pre-process
    if let Some(msgs) = pre_process_onwire_msgs_ds(&onwire_msg, shared_state, begin_timestamp).await
    {
        return msgs;
    };
    // Execute commands
    match onwire_msg {
        OnWireMessage::UserKeyPackagesForDS { key_packages } => {
            user_reg_key_packages(key_packages, shared_state, begin_timestamp).await
        }
        OnWireMessage::UserSync {
            user_name,
            new_key_packages,
        } => user_sync(&user_name, shared_state, new_key_packages, begin_timestamp).await,
        OnWireMessage::UserInvite {
            user_name,
            invitee_names,
            comm_grp,
            welcome,
        } => {
            user_invite(
                &user_name,
                &comm_grp,
                invitee_names,
                shared_state,
                welcome,
                begin_timestamp,
            )
            .await
        }
        OnWireMessage::UserStandardSend {
            identifier,
            user_msg,
            recipients,
        } => {
            user_send_standard(
                recipients,
                &user_msg,
                shared_state,
                identifier,
                begin_timestamp,
            )
            .await
        }

        OnWireMessage::UserReliableSend {
            user_name,
            recipients,
            user_msg,
        } => {
            user_reliable_send(
                user_name,
                recipients,
                &user_msg,
                shared_state,
                begin_timestamp,
            )
            .await
        }

        OnWireMessage::UserKeyPackageLookup {
            user_name,
            queried_users,
        } => {
            user_request_key_package(
                user_name.as_str(),
                queried_users,
                shared_state,
                begin_timestamp,
            )
            .await
        }

        OnWireMessage::UserRegisterForAS { .. }
        | OnWireMessage::UserCredentialLookup { .. }
        | OnWireMessage::UserSyncCredentials { .. } => {
            error!("Received requests intended for AS rather than for DS");
            vec![]
        }
        OnWireMessage::DSResult { .. }
        | OnWireMessage::DSRelayedUserMsg { .. }
        | OnWireMessage::DSRelayedUserWelcome { .. }
        | OnWireMessage::ASResult { .. }
        | OnWireMessage::ASCredentialResponse { .. }
        | OnWireMessage::ASCredentialSyncResponse { .. }
        | OnWireMessage::DSKeyPackageResponse { .. } => {
            error!("Received requests intended for clients rather than for DS");
            vec![]
        }
    }
}

pub async fn handle_onwire_msg_as_local(
    onwire_msg: OnWireMessage,
    shared_state: &Arc<SharedAuthServiceState>,
) -> Vec<OnWireMessage> {
    let begin_timestamp = Instant::now();
    match onwire_msg {
        OnWireMessage::UserRegisterForAS {
            credential,
            verification_key,
        } => {
            let state = shared_state;
            match identity_to_str(credential.identity()) {
                None => feedback_as_msg(CannotDecodeIdentity.to_string(), false, begin_timestamp)
                    .to_vec(),
                Some(name) => match state.credential_entries.entry(name) {
                    Vacant(e) => {
                        e.insert(CredentialEntry {
                            credential,
                            verification_key,
                        });
                        feedback_as_msg("New Identity OK".to_string(), true, begin_timestamp)
                            .to_vec()
                    }
                    Occupied(_) => {
                        feedback_as_msg(IdentityAlreadyExist.to_string(), false, begin_timestamp)
                            .to_vec()
                    }
                },
            }
        }
        OnWireMessage::UserCredentialLookup {
            user_name: _user_name,
            queried_users,
        } => {
            let state = shared_state;
            let mut found_credentials = Vec::new();
            for queried_user in queried_users {
                if let Some(queried_user_credential) = state.get_credential_copy(queried_user) {
                    found_credentials.push(queried_user_credential);
                } else {
                    return feedback_as_msg(NoSuchQueriedUser.to_string(), false, begin_timestamp)
                        .to_vec();
                }
            }
            vec![
                OnWireMessage::ASCredentialResponse {
                    queried_user_credentials: found_credentials,
                },
                feedback_as_msg("Credential found".to_string(), true, begin_timestamp),
            ]
        }
        OnWireMessage::UserSyncCredentials => {
            let state = shared_state;
            vec![
                OnWireMessage::ASCredentialSyncResponse {
                    credentials: state.get_all_credentials_copy(),
                },
                feedback_as_msg("Credentials retrieved".to_string(), true, begin_timestamp),
            ]
        }
        _ => {
            error!(
                "Unacceptable OnWireMessage for AS received: {:?}",
                onwire_msg
            );
            feedback_as_msg("Unknown command for AS".to_string(), false, begin_timestamp).to_vec()
        }
    }
}

/// Preprocess app message. Currently, only checks if the user is registered.
/// If preprocessing succeeds, then it returns `None`, else returns `Some(Vec<OnWireMessage>)`.
async fn pre_process_onwire_msgs_ds(
    onwire_msg: &OnWireMessage,
    shared_state: &Arc<SharedDeliverServiceState>,
    timestamp: Instant,
) -> Option<Vec<OnWireMessage>> {
    // Check whether non-registration requests are initialized by  known users
    match onwire_msg {
        OnWireMessage::UserKeyPackagesForDS { .. }
        | OnWireMessage::UserRegisterForAS { .. }
        | OnWireMessage::UserStandardSend { .. }
        | OnWireMessage::UserReliableSend { .. } => None,
        OnWireMessage::UserCredentialLookup { user_name, .. }
        | OnWireMessage::UserKeyPackageLookup { user_name, .. }
        // | OnWireMessage::UserCreate { user_name, .. }
        | OnWireMessage::UserSync { user_name, .. }
        | OnWireMessage::UserInvite { user_name, .. } => {
            if shared_state.user_key_packages.contains_key(user_name) {
                None
            } else {
                Some(feedback_ds_msg("Unknown user. Did you register (with DS via KeyPackage)?", false, timestamp).to_vec())
            }
        }
        OnWireMessage::DSResult { .. }
        | OnWireMessage::DSRelayedUserMsg { .. }
        | OnWireMessage::DSRelayedUserWelcome { .. }
        | OnWireMessage::ASResult { .. }
        | OnWireMessage::UserSyncCredentials { .. }
        | OnWireMessage::ASCredentialSyncResponse { .. }
        | OnWireMessage::ASCredentialResponse { .. }
        | OnWireMessage::DSKeyPackageResponse { .. } => {
            panic!("Unacceptable message types received by DS")
        }
    }
}

async fn user_sync(
    user_name: &String,
    shared_state: &Arc<SharedDeliverServiceState>,
    new_key_packages: Vec<KeyPackage>,
    begin_timestamp: Instant,
) -> Vec<OnWireMessage> {
    let state = shared_state;
    let mut return_onwire_msg_list = vec![];

    let n_key_packages = new_key_packages.len();
    let _ = state.add_key_packages(new_key_packages, MAX_KEY_PACKAGES_PER_USER);

    let invite_queue = state
        .invite_indvl_queues
        .remove(user_name)
        .unwrap_or_default()
        .1;

    // Return invites first, as invites should be processed first in clients
    // to avoid client drops messages because no associated invite was ever received
    for invite in invite_queue {
        return_onwire_msg_list.push(OnWireMessage::DSRelayedUserWelcome {
            comm_grp: invite.comm_grp.to_owned(),
            sender: invite.inviter.to_owned(),
            welcome: invite.welcome_obj.to_owned(),
        });
    }

    // Find unordered message, if any
    let unordered_message_queue = state
        .unordered_message_indvl_queues
        .remove(user_name)
        .unwrap_or_default()
        .1;
    let mut unread_messages: Vec<ProtectedMessageWithMetaData> = unordered_message_queue
        .iter()
        .map(|message_id| {
            state
                .pop_message_by_id(&message_id.to_owned(), user_name)
                .expect("Cannot find corresponding message id")
        })
        .collect();

    // Find ordered message, if any
    let comm_group_ids = if let Some((_, group_ids)) = state.indvl_groups.remove(user_name) {
        group_ids
    } else {
        vec![]
    };
    let ordered_messages: Vec<ProtectedMessageWithMetaData> = comm_group_ids
        .iter()
        .flat_map(|comm_group_id| {
            state
                .pop_all_ordered_msg_w_meta(user_name, comm_group_id)
                .into_iter()
        })
        .collect();
    unread_messages.extend(ordered_messages);
    unread_messages.sort_by(|msg1, msg2| msg1.server_timestamp.cmp(&msg2.server_timestamp));
    let unread_count = unread_messages.len();

    for protected_msg_w_meta in unread_messages {
        return_onwire_msg_list.push(OnWireMessage::DSRelayedUserMsg {
            user_msg: protected_msg_w_meta.protected_msg,
            server_timestamp: protected_msg_w_meta.server_timestamp.to_owned(),
        });
    }

    let explanation = format!(
        "User [{}] synced {} messages and submitted {} key packages",
        user_name, unread_count, n_key_packages,
    );

    return_onwire_msg_list.push(feedback_ds_msg(&explanation, true, begin_timestamp));
    return_onwire_msg_list
}

/// The `user_invite` function accepts a request to invite a new user to
/// an existing group. The server places the welcome object from the invite
/// in the invitee's incoming message queue and the group update object in
/// the incoming message queues of the other existing group members. Finally,
/// the function produces a response to the sender of the invite.
async fn user_invite(
    user_name: &String,
    comm_grp: &CommGroupId,
    invitee_names: Vec<String>,
    shared_state: &Arc<SharedDeliverServiceState>,
    welcome_obj: Welcome,
    begin_timestamp: Instant,
) -> Vec<OnWireMessage> {
    let state = shared_state;
    let comm_group_id = comm_grp;

    // if !state.invite_indvl_queues.contains_key(invitee_name) {
    //     state
    //         .invite_indvl_queues
    //         .insert(invitee_name.to_string(), Vec::new());
    // }
    // place welcome message in invitee queue
    for invitee_name in invitee_names {
        state
            .invite_indvl_queues
            .entry(invitee_name.to_string())
            .or_default()
            .push(Invite {
                welcome_obj: welcome_obj.clone(),
                invitee: invitee_name,
                inviter: user_name.to_string(),
                comm_grp: comm_grp.to_owned(),
            });
    }

    feedback_ds_msg_w_identifier(
        "Invite has been sent".to_string(),
        true,
        Some(comm_group_id.get_string()),
        //state.pop_all_ordered_msg(user_name),
        vec![],
        begin_timestamp,
    )
    .to_vec()
}

async fn user_reliable_send(
    user_name: String,
    recipients: Vec<String>,
    protected_message: &GroupMessage,
    shared_state: &Arc<SharedDeliverServiceState>,
    begin_timestamp: Instant,
) -> Vec<OnWireMessage> {
    let state = shared_state;
    let msg_w_meta =
        ProtectedMessageWithMetaData::new(protected_message.to_owned(), true, SystemTime::now());
    state.delivery_to_recipients(&recipients, msg_w_meta);
    let explanation = "A user sent an ordered message.".to_string();

    let comm_group_id = match &protected_message {
        GroupMessage::AppMlsMessage {
            comm_grp,
            mls_msg: _,
            sender: _,
        } => comm_grp,
    };

    feedback_ds_msg_w_identifier(
        explanation,
        true,
        Some(comm_group_id.get_string()),
        state.pop_all_ordered_msg(&user_name, &protected_message.get_group_id()),
        begin_timestamp,
    )
    .to_vec()
}

async fn user_send_standard(
    recipients: Vec<String>,
    protected_message: &GroupMessage,
    shared_state: &Arc<SharedDeliverServiceState>,
    identifier: Option<String>,
    begin_timestamp: Instant,
) -> Vec<OnWireMessage> {
    let msg_w_meta =
        ProtectedMessageWithMetaData::new(protected_message.to_owned(), false, SystemTime::now());
    shared_state.delivery_to_recipients(&recipients, msg_w_meta);
    let explanation = "A user sent a message.".to_string();
    feedback_ds_msg_w_identifier(explanation, true, identifier, vec![], begin_timestamp).to_vec()
}

async fn user_reg_key_packages(
    mut key_packages: Vec<KeyPackage>,
    shared_state: &Arc<SharedDeliverServiceState>,
    begin_timestamp: Instant,
) -> Vec<OnWireMessage> {
    let binary_identity = &key_packages[0].credential().identity();
    let key_packages_map = &shared_state.user_key_packages;
    match identity_to_str(binary_identity) {
        Some(user) => match key_packages_map.entry(user) {
            Vacant(e) => {
                e.insert(key_packages);
                feedback_ds_msg("Recorded key packages on DS", true, begin_timestamp).to_vec()
            }
            Occupied(mut e) => {
                e.get_mut().append(&mut key_packages);
                while key_packages.len() > MAX_KEY_PACKAGES_PER_USER {
                    key_packages.pop();
                }
                feedback_ds_msg("Recorded key packages on DS", true, begin_timestamp).to_vec()
            }
        },
        None => feedback_ds_err(CannotDecodeIdentity, begin_timestamp).to_vec(),
    }
}

async fn user_request_key_package(
    _user_name: &str,
    queried_names: Vec<String>,
    shared_state: &Arc<SharedDeliverServiceState>,
    begin_timestamp: Instant,
) -> Vec<OnWireMessage> {
    let mut found_packages = Vec::new();
    for queried_name in queried_names {
        let key_packages = shared_state.user_key_packages.get_mut(&*queried_name);

        match key_packages {
            Some(mut key_packages) => {
                if let Some(key_package) = key_packages.pop() {
                    found_packages.push(key_package);
                } else {
                    return feedback_ds_err(NoAvailableUserKeyPackage, begin_timestamp).to_vec();
                }
            }
            None => return feedback_ds_err(NoSuchQueriedUser, begin_timestamp).to_vec(),
        }
    }
    vec![
        OnWireMessage::DSKeyPackageResponse {
            queried_user_key_packages: found_packages,
        },
        feedback_ds_msg("Found queried user's keypackage", true, begin_timestamp),
    ]
}

fn feedback_ds_err(err: UserRequestErrors, begin_timestamp: Instant) -> OnWireMessage {
    feedback_ds_msg_w_identifier(err.to_string(), false, None, vec![], begin_timestamp)
}

fn feedback_ds_msg(
    explanation: &str,
    request_valid: bool,
    begin_timestamp: Instant,
) -> OnWireMessage {
    feedback_ds_msg_w_identifier(
        explanation.to_string(),
        request_valid,
        None,
        vec![],
        begin_timestamp,
    )
}

fn feedback_ds_msg_w_identifier(
    mut explanation: String,
    request_valid: bool,
    identifier: Option<String>,
    preceding_ordered_msgs: Vec<GroupMessage>,
    begin_timestamp: Instant,
) -> OnWireMessage {
    let failed_expr = format!("Bad user request: {}", explanation);
    if !request_valid {
        explanation = failed_expr;
    };

    let _ = explanation;

    OnWireMessage::DSResult {
        request_valid,
        explanation: Some(explanation),
        identifier,
        preceding_and_sent_ordered_msgs: preceding_ordered_msgs,
        process_time_used: begin_timestamp.elapsed(),
    }
}

fn feedback_as_msg(
    explanation: String,
    request_valid: bool,
    begin_timestamp: Instant,
) -> OnWireMessage {
    OnWireMessage::ASResult {
        request_valid,
        explanation: Some(explanation),
        process_time_used: begin_timestamp.elapsed(),
    }
}
