//! This file contains functions for generating and parsing messages in
//! a no-governance baseline.
//!
//! Issue #168 documents the need to refactor this code so as not to
//! heavily duplicate logic from client_api/mod.rs

use std::ops::DerefMut;
use std::str::from_utf8;
use std::time::SystemTime;

use log::*;
use openmls::framing::{MlsMessageIn, MlsMessageOut, ProcessedMessage};
use openmls::prelude::StagedCommit;

use crate::client_api::actions::{Action, ActionMsg};
use crate::client_api::client_crypto_impl::CryptoBackend;
use crate::client_api::client_err::ClientError;
use crate::client_api::client_err::ClientError::*;
use crate::client_api::client_struct::{ClientDataProvider, ClientParsedMsg};
use crate::client_api::*;
use crate::messages::{
    decode_from_bytes, encode_to_bytes, GroupMessage, OnWireMessage, UnorderedMsgContent,
    UnorderedPrivateMessage,
};
use crate::policyengine::ClientRef;
use crate::CommGroupId;
use crate::{get_key_package_ref_identity, identity_to_str};

pub fn action_msg_to_group_msg_unchecked(
    comm_grp: &CommGroupId,
    action_msg: ActionMsg,
    backend: &mut CryptoBackend,
    client_data: &mut (impl ClientDataProvider + ?Sized),
    ordered: bool,
) -> GroupMessage {
    let bytes = encode_to_bytes(&action_msg);

    bytes_to_group_message(
        &client_data.get_user_id(),
        comm_grp,
        bytes,
        ordered,
        backend,
        client_data,
    )
}

pub fn accept_msg(
    comm_grp: &CommGroupId,
    backend: &mut CryptoBackend,
    client_data: &mut ClientRef,
) -> Vec<OnWireMessage> {
    try_activate_gov_state(comm_grp, backend, client_data).expect("Cannot Accept");

    let action = ActionMsg::Accept(AcceptAction {
        metadata: ActionMetadata::new(
            client_data.get_user_id(),
            Uuid::new_v4().to_string(),
            comm_grp.clone(),
        ),
        received_gov_state_hash: 0,
    });

    check_action_msg_and_get_mls(comm_grp, action, backend, client_data.deref_mut())
}

/// A no-op in the baseline case. Including this so that the client builds.
pub fn commit_proposed_votes(
    comm_group_id: &CommGroupId,
    backend: &mut CryptoBackend,
    client_data: &mut (impl ClientDataProvider + ?Sized),
) -> Vec<OnWireMessage> {
    vec![]
}

/// Broadcast an action to all members of a group, with authorization and action storing
/// Client should use this function to send an action (msg)
/// ActionMsg-> Bytes -> MlsMessageOut -> GroupMessage -> OnWireMessage Vec
pub fn check_action_msg_and_get_mls(
    comm_grp: &CommGroupId,
    action_msg: ActionMsg,
    backend: &mut CryptoBackend,
    client_data: &mut (impl ClientDataProvider + ?Sized),
) -> Vec<OnWireMessage> {
    client_data.store_pending_action(comm_grp, action_msg.clone());

    if action_msg.is_ordered() {
        let group_msg =
            action_msg_to_group_msg_unchecked(comm_grp, action_msg, backend, client_data, true);
        group_msg_to_ord_onwire_broadcast(group_msg, comm_grp, client_data).to_vec()
    } else {
        let private_message = UnorderedPrivateMessage {
            sender: client_data.get_user_id(),
            content: UnorderedMsgContent::UnsignedAction { action: action_msg },
            sender_timestamp: SystemTime::now(),
        };
        let encoded = private_message.to_bytes();

        // Save this message to local history before sending
        client_data.store_self_sent_msg(comm_grp, &private_message);

        let recipients = client_data.get_group_members(comm_grp);
        let private_msg = bytes_to_group_message(
            &client_data.get_user_id(),
            comm_grp,
            encoded,
            false,
            backend,
            client_data,
        );
        OnWireMessage::UserStandardSend {
            // Sealed sender possible with Application Messages, hence using None for sender
            user_msg: private_msg,
            recipients,
            identifier: Some(comm_grp.get_string()),
        }
        .to_vec()
    }
}

pub fn parse_mls_message_out(
    mls_msg: MlsMessageOut,
    comm_grp: &CommGroupId,
    sender: Option<String>,
    client_data: &mut ClientRef,
    backend: &mut CryptoBackend,
) -> Vec<ClientParsedMsg> {
    let mls_msg = MlsMessageIn::from(mls_msg);
    let mut local_plain_msgs = vec![];
    let own_user_name = client_data.get_user_id();

    match client_data.get_ref_group(comm_grp) {
        None => {
            error!("Cannot find the group of a received message.");
        }
        Some(mls_group_ref) => {
            // Group exists
            let exists_pending_commit = mls_group_ref.borrow().pending_commit().is_some();
            debug!(
                "{own_user_name} Received Message Epoch {:?} sent by {:?}, while locally the group is at {:?}",
                mls_msg.epoch(),sender,
                mls_group_ref.borrow().epoch()
            );

            let local_epoch = { mls_group_ref.borrow().epoch() };

            debug!(
                "-- User {:?} received message from User {:?}",
                &own_user_name, sender
            );

            if Some(own_user_name) == sender {
                // Is a self-sent message, MlsMessageOut cannot be deciphered
                if (mls_msg.epoch() != local_epoch && mls_msg.is_handshake_message())
                    || (mls_msg.epoch() > local_epoch)
                {
                    // Self sent message | Wrong epoch
                    debug!("Self sent message | Wrong epoch");
                    error!("The action you just attempted did not go through because there was other valid actions preceding it. Please try again");
                    mls_group_ref.borrow_mut().clear_pending_commit();
                    client_data.pop_pending_action(comm_grp);
                } else {
                    // Self sent message | Correct epoch
                    debug!("Self sent message | Correct epoch");
                    let action_popped = client_data.pop_pending_action(comm_grp);
                    match action_popped {
                        Some(action) => {
                            // Self sent message | Correct epoch | Locally Stored Action Exists
                            debug!(
                                "Self sent message | Correct epoch | Locally Stored Action Exists"
                            );
                            if exists_pending_commit {
                                policy_check_and_execute(action, &comm_grp, None, client_data);
                            } else {
                                debug!(
                                    "*Found locally saved action but cannot find the local commit"
                                );
                            }
                        }
                        None => {
                            // Self sent message | Correct epoch | NO Locally Stored Action
                            debug!("Self sent message | Correct epoch | NO Locally Stored Action");
                            client_data
                                .get_ref_group(comm_grp)
                                .unwrap()
                                .borrow_mut()
                                .merge_pending_commit()
                                .expect(
                                    "Cannot merge pending commit, and also the action is missing",
                                );

                            warn!("(Ignore if you just sent an Add/Leave/Remove/Accept/Decline) Cannot find a saved action after DS response for that group. Merged anyway.");
                        }
                    };
                }
            } else {
                // Message from other group member
                debug!("Message from other group member");
                if (mls_msg.epoch() != local_epoch && mls_msg.is_handshake_message())
                    || (mls_msg.epoch() > local_epoch)
                {
                    // Message from other group member | Wrong epoch
                    debug!("Message from other group member | Wrong epoch");
                    debug!(
                        "An action by other group member was discarded because it had Wrong Epoch"
                    );
                } else {
                    // Message from other group member | Correct epoch
                    debug!("Message from other group member | Correct epoch");
                    let unverified_r = mls_group_ref.borrow_mut().parse_message(mls_msg, backend);

                    //.expect("Cannot parse incoming MlsGroup Message");
                    let unverified = if unverified_r.is_err() {
                        debug!("Unable to decrypt a message");
                        return vec![];
                    } else {
                        unverified_r.unwrap()
                    };
                    trace!("Unverified message: {:?}", unverified);
                    // https://openmls.tech/book/user_manual/processing.html#processing-messages No sig key required
                    let processed = mls_group_ref
                        .borrow_mut()
                        .process_unverified_message(unverified, None, backend)
                        .expect("Could not process unverified message.");
                    trace!("Processed message: {:?}", processed);

                    match processed {
                        ProcessedMessage::ApplicationMessage(app_msg_mls) => {
                            // Message from other group member | Correct epoch | Unordered
                            debug!("Message from other group member | Correct epoch | Unordered");
                            let bytes = app_msg_mls.into_bytes();
                            let mut private_msg: UnorderedPrivateMessage =
                                serde_json::from_slice(&bytes).unwrap();
                            debug!("Decrypted Message from bytes: {:?}", from_utf8(&bytes));

                            local_plain_msgs.push(ClientParsedMsg::NewMsg {
                                private_msg: private_msg.to_owned(),
                                comm_grp: comm_grp.clone(),
                            });

                            //TODO use match instead
                            if let UnorderedMsgContent::UnsignedAction { action } =
                                &mut private_msg.content
                            {
                                policy_check_and_execute(
                                    action.clone(),
                                    &comm_grp,
                                    None,
                                    client_data,
                                );
                            }
                        }
                        ProcessedMessage::ProposalMessage(proposal_wrapped) => mls_group_ref
                            .borrow_mut()
                            .store_pending_proposal(*proposal_wrapped),
                        ProcessedMessage::StagedCommitMessage(staged_commit) => {
                            // Message from other group member | Correct epoch | Ordered
                            debug!("Message from other group member | Correct epoch | Ordered");

                            let ord_app_msgs: Vec<Vec<u8>> = staged_commit
                                .ord_app_msg_proposals()
                                .map(|queued_prop| {
                                    queued_prop.ord_app_msg_proposal().get_bytes().clone()
                                })
                                .collect();

                            let add_invitees: Vec<String> = staged_commit
                                .add_proposals()
                                .map(|queued_prop| {
                                    identity_to_str(
                                        queued_prop
                                            .add_proposal()
                                            .key_package()
                                            .credential()
                                            .identity(),
                                    )
                                    .unwrap()
                                })
                                .collect();

                            let mut to_removed_opt: Vec<Option<String>> = staged_commit
                                .remove_proposals()
                                .map(|queued_prop| {
                                    get_key_package_ref_identity(
                                        mls_group_ref.borrow().members(),
                                        queued_prop.remove_proposal().removed(),
                                        backend,
                                    )
                                })
                                .collect();
                            to_removed_opt.retain(|opt| opt.is_some());
                            let to_removed: Vec<String> = to_removed_opt
                                .iter()
                                .map(|opt| opt.clone().unwrap())
                                .collect();

                            debug!("The ordered app msg: {:?}", ord_app_msgs);
                            debug!("Merging commits:{:?}", &staged_commit);

                            if ord_app_msgs.is_empty() {
                                // Message from other group member | Correct epoch | HandShake | No Actions
                                // No ordered message, so check if there is add proposal

                                // NOTE: here we do not check membership to the pre-add/pre-remove lists
                                // let mut merge = !(add_invitees.is_empty() && to_removed.is_empty());

                                // for add_invitee in add_invitees {
                                //     merge = merge
                                //         && client_data
                                //             .pop_to_add_invitee_key_pack(&comm_grp, &add_invitee)
                                //             .is_some();
                                // }
                                // for remove_candidates in &to_removed {
                                //     merge = merge
                                //         && client_data
                                //             .pop_to_be_removed_member(&comm_grp, remove_candidates);
                                // }

                                // if merge {
                                client_data
                                    .get_ref_group(comm_grp)
                                    .unwrap()
                                    .borrow_mut()
                                    .merge_staged_commit(*staged_commit)
                                    .expect("Cannot merge");
                                if to_removed.contains(&client_data.get_user_id()) {
                                    // Self was removed from the group
                                    info!("You were removed from group {:?}", comm_grp);
                                    client_data.remove_group(comm_grp);
                                }
                                // } else {
                                //     debug!("An ordered message by other group member was not processed because it had no actions");
                                // }
                            } else {
                                // Message from other group member | Correct epoch | HandShake | Exists Actions
                                // Only process one/first ordered action at one commit to avoid committing half a commit
                                for bytes in &ord_app_msgs {
                                    let action_opt: Option<ActionMsg> = decode_from_bytes(bytes);
                                    if let Some(action) = action_opt {
                                        policy_check_and_execute(
                                            action,
                                            &comm_grp,
                                            Some(staged_commit),
                                            client_data,
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    local_plain_msgs
}

/// Unconditionally performs action
pub fn policy_check_and_execute(
    action: ActionMsg,
    comm_grp: &CommGroupId,
    commit: Option<Box<StagedCommit>>,
    client_data: &mut ClientRef,
) {
    action.execute(client_data.deref_mut());
    merge_commit_opt(client_data, comm_grp, commit);
    info!("An action of type {:?} went through", action.action_type());

    trace!(
        "The current governance state for this group is: {:?}",
        client_data
    );
    // Should any merge succeeded
    client_data
        .get_ref_group(&comm_grp)
        .unwrap()
        .borrow_mut()
        .clear_pending_commit();
}

/// The main difference with this version is that we don't attempt to see
/// if the governance state is initialized
/// execute all unordered messages which supposedly contain `UpdateGroupStateAction`,
/// execute all other messages (ordered),
/// and store the group.
/// Assuming that the `UpdateGroupStateAction` is sent in an UserSend message, sent with the same epoch of Welcome.
pub(crate) fn try_activate_gov_state(
    comm_grp: &CommGroupId,
    backend: &mut CryptoBackend,
    client_data: &mut ClientRef,
) -> Result<(), ClientError> {
    let mls_group = client_data.get_ref_group(comm_grp).ok_or(NoSuchInvite)?;

    let welcome_epoch = mls_group.borrow().epoch();

    let unprocessed_msgs = client_data.pop_unprocessed_msgs(comm_grp);

    let mut processed_msgs = vec![];

    // Init shared gov state by execute all non-handshake, same-epoch messages.
    for msg in &unprocessed_msgs {
        match msg {
            OnWireMessage::DSRelayedUserMsg { user_msg, .. } => match user_msg {
                GroupMessage::AppMlsMessage {
                    mls_msg, sender, ..
                } => {
                    if (!mls_msg.is_handshake_message()) && mls_msg.epoch() == welcome_epoch {
                        parse_mls_message_out(
                            mls_msg.clone(),
                            comm_grp,
                            sender.clone(),
                            client_data,
                            backend,
                        );
                        processed_msgs.push(msg.to_owned());
                    }
                }
            },
            _ => (),
        }
    }

    let mut unprocessed_msgs: Vec<OnWireMessage> = unprocessed_msgs;
    unprocessed_msgs.retain(|msg| !processed_msgs.contains(msg));
    parse_incoming_onwire_msgs(unprocessed_msgs, client_data, backend);
    Ok(())
}
