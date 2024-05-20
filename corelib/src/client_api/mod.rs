//! An un-networked module to creating requests in forms of OnWireMessages  while producing all
//! related side effects

use ed25519_dalek::PublicKey;
use log::*;
use openmls::framing::{MlsMessageIn, MlsMessageOut, ProcessedMessage};
use openmls::group::{GroupId, MlsGroup, MlsGroupConfig};
use openmls::key_packages::KeyPackage;
use openmls::prelude::{Credential, StagedCommit};
use std::collections::hash_map::DefaultHasher;
use std::fmt::Debug;
use std::hash::Hash;
use std::hash::Hasher;
use std::ops::DerefMut;
use std::str::from_utf8;
use std::time::{Instant, SystemTime};
use uuid::Uuid;

use crate::client_api::actions::{
    AcceptAction, Action, ActionMsg, DeclineAction, InviteAction, KickAction, LeaveAction,
    SetUserRoleAction,
};
use crate::client_api::client_crypto_impl::CryptoBackend;
use crate::client_api::client_err::ClientError;
use crate::client_api::client_err::ClientError::*;
use crate::client_api::client_struct::ClientParsedMsg::NewMsg;
use crate::client_api::client_struct::{ClientDataProvider, ClientParsedMsg};
use crate::messages::{
    ordered_deserialize, ordered_serialize, GroupMessage, OnWireMessage, OrderedMsgContent,
    OrderedPrivateMessage, UnorderedMsgContent, UnorderedPrivateMessage,
};
use crate::policyengine::ClientRef;
use crate::TimerType::{
    MlsGovPolicyEngineCheck, MlsGovRBACCheck, OpenMlsGroupOperation, OpenMlsMsgGeneration,
    OpenMlsMsgVerifyDecryption, ParseIncomingSingleMsgNonKpFetch, SyncGeneration,
};
use crate::{get_key_package_ref_identity, get_member_hash_ref, identity_to_str, str_to_identity};
use crate::{CommGroupId, SingleTimeMeasurement};

use self::actions::{
    ActionMetadata, ActionType, GovStateAnnouncementAction, TextMsgAction, VerifiableAction,
    VoteAction,
};

pub mod actions;
pub mod client_crypto_impl;
pub mod client_struct;

#[cfg(all(feature = "baseline", feature = "gov"))]
compile_error!("The features \"baseline\" and \"gov\" cannot be used simultaneously");

#[cfg(feature = "baseline")]
pub mod baseline;

#[cfg(feature = "baseline")]
use baseline::try_activate_gov_state;
#[cfg(feature = "baseline")]
pub use baseline::{
    accept_msg, action_msg_to_group_msg_unchecked, check_action_msg_and_get_mls,
    commit_proposed_votes, parse_mls_message_out, policy_check_and_execute,
};

#[cfg(test)]
mod action_tests;
mod client_err;
pub mod client_struct_impl;

/// Broadcast an action to all members of a group, with authorization and action storing
/// Client should use this function to send an action (msg)
/// ActionMsg-> Bytes -> MlsMessageOut -> GroupMessage -> OnWireMessage Vec
#[cfg(feature = "gov")]
pub fn check_action_msg_and_get_mls(
    comm_grp: &CommGroupId,
    action_msg: ActionMsg,
    backend: &mut CryptoBackend,
    client_data: &mut (impl ClientDataProvider + ?Sized),
) -> Vec<OnWireMessage> {
    // if !client_data.action_authorized(&action_msg) {
    //     error!("Cannot continue. Action not authorized");
    //     return vec![];
    // }
    client_data.store_pending_action(comm_grp, action_msg.clone());

    if action_msg.is_ordered() {
        let verif_action = VerifiableAction::new(action_msg, client_data.get_keypair());
        let group_msg =
            action_msg_to_group_msg_unchecked(comm_grp, verif_action, backend, client_data, true);
        group_msg_to_ord_onwire_broadcast(group_msg, comm_grp, client_data).to_vec()
    } else {
        // let sig = text_msg_action.sign(client_data.get_keypair());
        // text_msg_action.metadata.signature = Some(sig);
        let verif_action = VerifiableAction::new(action_msg, client_data.get_keypair());
        // Generate signature on action
        let private_message = UnorderedPrivateMessage {
            sender: client_data.get_user_id(),
            content: UnorderedMsgContent::TextAction {
                text_action: verif_action,
            },
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

pub fn propose_vote(
    comm_group_id: &CommGroupId,
    vote_value: &str,
    proposed_action_id: &str,
    proposed_action_type: ActionType,
    backend: &mut CryptoBackend,
    client_data: &mut (impl ClientDataProvider + ?Sized),
) -> Vec<OnWireMessage> {
    let user_name = client_data.get_user_id();
    let action = ActionMsg::Vote(VoteAction {
        vote_value: vote_value.to_owned(),
        proposed_action_id: proposed_action_id.to_owned(),
        proposed_action_type: proposed_action_type.to_owned(),
        metadata: ActionMetadata::new(
            user_name,
            Uuid::new_v4().to_string(),
            comm_group_id.to_owned(),
        ),
    });
    let verif_action = VerifiableAction::new(action, client_data.get_keypair());
    client_data.store_proposed_action(comm_group_id, verif_action.clone());
    // Generate signature on action
    let private_message = UnorderedPrivateMessage {
        sender: client_data.get_user_id(),
        content: UnorderedMsgContent::ProposedAction {
            proposed_action: verif_action,
        },
        sender_timestamp: SystemTime::now(),
    };
    let encoded = private_message.to_bytes();
    let recipients = client_data.get_group_members(comm_group_id);
    let private_msg = bytes_to_group_message(
        &client_data.get_user_id(),
        comm_group_id,
        encoded,
        false,
        backend,
        client_data,
    );
    OnWireMessage::UserStandardSend {
        // Sealed sender possible with Application Messages, hence using None for sender
        user_msg: private_msg,
        recipients,
        identifier: Some(comm_group_id.get_string()),
    }
    .to_vec()
}

#[cfg(feature = "gov")]
pub fn commit_proposed_votes(
    comm_group_id: &CommGroupId,
    backend: &mut CryptoBackend,
    client_data: &mut (impl ClientDataProvider + ?Sized),
) -> Vec<OnWireMessage> {
    // Get uncommitted proposed actions
    let proposed_messages = client_data.get_proposed_actions(comm_group_id);
    // TODO: filter for votes
    // Bundle the proposed actions into a single message
    let group_msg = action_msg_vec_to_group_msg_unchecked(
        comm_group_id,
        proposed_messages,
        backend,
        client_data,
        true,
    );
    // TODO: need to check which proposed actions to clear if this commit goes
    // through -- should mirror what pop_pending_action does
    group_msg_to_ord_onwire_broadcast(group_msg, comm_group_id, client_data).to_vec()
}

/// ActionMsg -> VerifiableAction -> Bytes -> MlsMessageOut -> GroupMessage
#[cfg(feature = "gov")]
pub(crate) fn action_msg_to_group_msg_unchecked(
    comm_grp: &CommGroupId,
    action_msg: VerifiableAction,
    backend: &mut CryptoBackend,
    client_data: &mut (impl ClientDataProvider + ?Sized),
    ordered: bool,
) -> GroupMessage {
    let ord_priv_msg = OrderedPrivateMessage {
        content: OrderedMsgContent::Action(action_msg),
    };
    let bytes = ordered_serialize(&ord_priv_msg);

    bytes_to_group_message(
        &client_data.get_user_id(),
        comm_grp,
        bytes,
        ordered,
        backend,
        client_data,
    )
}

#[cfg(feature = "gov")]
pub(crate) fn action_msg_vec_to_group_msg_unchecked(
    comm_grp: &CommGroupId,
    action_msg_vec: Vec<VerifiableAction>,
    backend: &mut CryptoBackend,
    client_data: &mut (impl ClientDataProvider + ?Sized),
    ordered: bool,
) -> GroupMessage {
    let ord_priv_msg = OrderedPrivateMessage {
        content: OrderedMsgContent::ActionVec(action_msg_vec),
    };
    let bytes = ordered_serialize(&ord_priv_msg);

    bytes_to_group_message(
        &client_data.get_user_id(),
        comm_grp,
        bytes,
        ordered,
        backend,
        client_data,
    )
}

/// Generate a an ordered `OnWireMessage` intending for all members of the group specified from group msg
/// GroupMessage -> OnWireMessage
fn group_msg_to_ord_onwire_broadcast(
    group_msg: GroupMessage,
    comm_grp: &CommGroupId,
    client_data: &(impl ClientDataProvider + ?Sized),
) -> OnWireMessage {
    OnWireMessage::UserReliableSend {
        user_name: client_data.get_user_id(),
        user_msg: group_msg,
        //  recipients does include the sender, so and when the sender receives its own message
        // it pops from the community group locally. This way gives clients a chance to give up their
        // own action should the epoch number was not high enough.
        //recipients.retain(|rec| rec != user_name);
        recipients: client_data.get_group_members(comm_grp),
    }
}

/// Generate a an ordered `GroupMsg` from bytes
/// Bytes -> MlsMessageOut -> GroupMessage
/// Does not store action/text to local.
fn bytes_to_group_message(
    user_name: &String,
    comm_grp: &CommGroupId,
    bytes: Vec<u8>,
    ordered: bool,
    backend: &mut CryptoBackend,
    client_data: &mut (impl ClientDataProvider + ?Sized),
) -> GroupMessage {
    {
        // Stop self-store message if that group does not exist
        client_data
            .get_ref_group(comm_grp)
            .expect("Cannot find that group");
    }

    let mut group_state = client_data
        .get_ref_group(comm_grp)
        .expect("Cannot find that group")
        .borrow_mut();

    let timestamp = Instant::now();
    let mls_out = if ordered {
        let mls = group_state
            .send_ord_app_msg(backend, bytes)
            .expect("Cannot generate send message");
        debug!(
            "{user_name} Generated (ordered) MlsMessage with Epoch {:?}",
            mls.epoch()
        );

        mls
    } else {
        group_state
            .create_message(backend, &bytes)
            .expect("Cannot generate send message")
    };
    SingleTimeMeasurement::new(OpenMlsMsgGeneration, timestamp.elapsed());

    GroupMessage::from_mls(mls_out, comm_grp.clone(), Some(user_name.to_owned()))
}

fn get_default_group_config() -> MlsGroupConfig {
    MlsGroupConfig::builder()
        .use_ratchet_tree_extension(true)
        .build()
}

/**
 * [user_name] of [config] must not be [None]
 */
pub fn sync_msg(
    config: &(impl ClientDataProvider + ?Sized),
    new_key_packages: Vec<KeyPackage>,
) -> OnWireMessage {
    let before_send = Instant::now();
    let result = OnWireMessage::UserSync {
        user_name: config.get_user_id(),
        new_key_packages,
    };
    let _ = SingleTimeMeasurement::new(SyncGeneration, before_send.elapsed());
    result
}

pub fn create_group_msg(
    user_name: &String,
    comm_grp: &CommGroupId,
    backend: &mut CryptoBackend,
    config: &mut (impl ClientDataProvider + ?Sized),
) -> Vec<OnWireMessage> {
    let group_id = GroupId::from_slice(comm_grp.group_id().as_bytes());
    let new_key_package =
        backend.generate_default_key_package_and_store_bundle(&config.get_credential());

    let new_mls_group = MlsGroup::new(
        backend,
        &get_default_group_config(),
        group_id,
        backend.hash_key_package(&new_key_package).as_slice(),
    )
    .expect("Cannot create new group");

    config.store_group(comm_grp, Some(0), new_mls_group); // Empty hash "0" for newly created group

    // Add creator of the group as Mod
    config.set_user_role(comm_grp, user_name.to_string(), "Mod".to_string());

    // OnWireMessage::UserCreate {
    //     user_name: user_name.to_owned(),
    //     community_name: community_name.to_owned(),
    //     group_name: group_name.to_owned(),
    //     epoch_num,
    // }
    // .to_vec()
    vec![]
}

pub fn register_msg_as(credential: Credential, verification_key: PublicKey) -> Vec<OnWireMessage> {
    OnWireMessage::UserRegisterForAS {
        credential,
        verification_key,
    }
    .to_vec()
}

pub fn register_msg_ds(key_packages: Vec<KeyPackage>) -> Vec<OnWireMessage> {
    OnWireMessage::UserKeyPackagesForDS { key_packages }.to_vec()
}

/// Generates an `OnWireMessage` that conveys an invite action
/// Note that an Invite action is **only a pre-authorization of add_member()**
/// You still need to `MlsGroup::add_member()` on the invitee after this action is passed
///
/// `user_name` is the name of the inviter
/// `invitee_name` is the name of the user being invited to the group
pub fn pre_add_invite_msg(
    user_name: &String,
    comm_grp: &CommGroupId,
    backend: &mut CryptoBackend,
    client_data: &mut (impl ClientDataProvider + Debug + ?Sized),
    third_party_key_package: Vec<KeyPackage>,
) -> Vec<OnWireMessage> {
    let action_msg = ActionMsg::Invite(InviteAction {
        metadata: ActionMetadata::new(
            user_name.to_owned(),
            Uuid::new_v4().to_string(),
            comm_grp.clone(),
        ),
        invitee_key_packages: third_party_key_package,
    });

    info!("Sending the Invite Action message. You still need to `Add Member` to complete the invitation process");
    check_action_msg_and_get_mls(comm_grp, action_msg, backend, client_data)
}

/// Generates an `OnWireMessage` that actually adds the user to the group cryptographically
///
/// `user_name` is the name of the inviter
/// `invitee_names` are the names of the user being invited to the group
pub fn add_msg(
    comm_grp: &CommGroupId,
    pre_approved_invitees: &Vec<String>,
    client_data: &mut (impl ClientDataProvider + Debug + ?Sized),
    backend: &mut CryptoBackend,
) -> Vec<OnWireMessage> {
    let invitee_key_packages: Vec<KeyPackage> = pre_approved_invitees
        .iter()
        .filter_map(|pre_approved_invitee| {
            match client_data.pop_to_add_invitee_key_pack(comm_grp, pre_approved_invitee) {
                Some(kp) => Some(kp),
                None => {
                    warn!(
                        "pop_to_add_invitee_key_pack returned None for {:?}",
                        pre_approved_invitee
                    );
                    None
                }
            }
        })
        .collect();

    let group = client_data
        .get_ref_group(comm_grp)
        .expect("Cannot find that group");

    let mls_operation_timestamp = Instant::now();

    let (update_mls, welcome) = group
        .get_mut()
        .add_members(backend, invitee_key_packages.as_slice())
        .expect("Cannot add member");

    let _ = SingleTimeMeasurement::new(OpenMlsMsgGeneration, mls_operation_timestamp.elapsed());

    let update_group = GroupMessage::from_mls(
        update_mls,
        comm_grp.clone(),
        Some(client_data.get_user_id()),
    );

    let update_onwire = group_msg_to_ord_onwire_broadcast(update_group, comm_grp, client_data);

    let welcome_onwire = OnWireMessage::UserInvite {
        user_name: client_data.get_user_id(),
        invitee_names: pre_approved_invitees.to_owned(),
        comm_grp: comm_grp.to_owned(),
        welcome,
    };

    vec![update_onwire, welcome_onwire]
}

pub fn send_text_msg_mls(
    user_name: &String,
    comm_grp: &CommGroupId,
    message: String,
    backend: &mut CryptoBackend,
    client_data: &mut (impl ClientDataProvider + ?Sized),
) -> Vec<OnWireMessage> {
    // Stop self-store message if that group does not exist
    client_data
        .get_ref_group(comm_grp)
        .expect("Cannot find that group");

    let text_msg_action = ActionMsg::TextMsg(TextMsgAction {
        msg: message,
        metadata: ActionMetadata::new(
            user_name.to_string(),
            Uuid::new_v4().to_string(),
            comm_grp.clone(),
        ),
    });

    check_action_msg_and_get_mls(comm_grp, text_msg_action, backend, client_data)
}

/// Send an update to the shared state of the group (eventually will use
/// app msg)
pub fn show_group_state(
    comm_grp: &CommGroupId,
    client_data: &mut (impl ClientDataProvider + ?Sized),
) {
    info!(
        "The shared group state:\n{:?}",
        client_data.get_shared_state(comm_grp)
    );
    info!(
        "The pending uncommitted actions:\n{:?}",
        client_data.get_proposed_actions(comm_grp)
    );
}

pub fn pre_leave_msg(
    comm_grp: &CommGroupId,
    backend: &mut CryptoBackend,
    client_data: &mut (impl ClientDataProvider + ?Sized),
) -> Vec<OnWireMessage> {
    let action = ActionMsg::Leave(LeaveAction {
        metadata: ActionMetadata::new(
            client_data.get_user_id(),
            Uuid::new_v4().to_string(),
            comm_grp.clone(),
        ),
    });

    check_action_msg_and_get_mls(comm_grp, action, backend, client_data)
}

pub fn pre_decline_msg(
    comm_grp: &CommGroupId,
    backend: &mut CryptoBackend,
    client_data: &mut ClientRef,
) -> Vec<OnWireMessage> {
    try_activate_gov_state(comm_grp, backend, client_data).expect("Cannot decline.");

    let action = ActionMsg::Decline(DeclineAction {
        metadata: ActionMetadata::new(
            client_data.get_user_id(),
            Uuid::new_v4().to_string(),
            comm_grp.clone(),
        ),
    });

    check_action_msg_and_get_mls(comm_grp, action, backend, client_data.deref_mut())
}

/// execute all unordered messages which supposedly contain `UpdateGroupStateAction`,
/// execute all other messages (ordered),
/// and store the group.
/// Assuming that the `UpdateGroupStateAction` is sent in an UserSend message, sent with the same epoch of Welcome.
#[cfg(feature = "gov")]
fn try_activate_gov_state(
    comm_grp: &CommGroupId,
    backend: &mut CryptoBackend,
    client_data: &mut ClientRef,
) -> Result<u64, ClientError> {
    let mls_group = client_data.get_ref_group(comm_grp).ok_or(NoSuchInvite)?;

    let welcome_epoch = mls_group.borrow().epoch();

    let unprocessed_msgs = client_data.pop_unprocessed_msgs(comm_grp);

    let mut processed_msgs = vec![];

    // Init shared gov state by execute all non-handshake, same-epoch messages.
    for msg in &unprocessed_msgs {
        if let OnWireMessage::DSRelayedUserMsg { user_msg, .. } = msg {
            match user_msg {
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
            }
        }
    }

    if client_data.is_shared_gov_state_initialized(comm_grp) {
        //If shared gov state now initialized, process the rest of the messages
        let mut unprocessed_msgs: Vec<OnWireMessage> = unprocessed_msgs;
        unprocessed_msgs.retain(|msg| !processed_msgs.contains(msg));
        parse_incoming_onwire_msgs(unprocessed_msgs, client_data, backend);
        Ok(client_data
            .get_shared_gov_state_init_hash(comm_grp)
            .unwrap())
    } else {
        //If shared gov state still uninitialized, store Welcome and Unprocessed Message back, and return err
        for msg in unprocessed_msgs {
            client_data.store_unprocessed_msg(comm_grp, msg)
        }
        Err(NoGroupStateAvailable)
    }
}

pub fn pre_kick_msg(
    comm_grp: &CommGroupId,
    member_name: &String,
    backend: &mut CryptoBackend,
    client_data: &mut (impl ClientDataProvider + ?Sized),
) -> Vec<OnWireMessage> {
    // Note that since the user performing the kicking action might not be in the group
    // (say community mod), then they cannot always perform the `propose_remove_member()`
    // Hence `kick` does not update the MLS group state accordingly.

    let action = ActionMsg::Kick(KickAction {
        target_user_id: member_name.to_string(),
        metadata: ActionMetadata::new(
            client_data.get_user_id(),
            Uuid::new_v4().to_string(),
            comm_grp.clone(),
        ),
    });

    check_action_msg_and_get_mls(comm_grp, action, backend, client_data)
}

pub fn set_role_msg(
    comm_grp: &CommGroupId,
    member_name: &String,
    new_role: String,
    backend: &mut CryptoBackend,
    client_data: &mut (impl ClientDataProvider + ?Sized),
) -> Vec<OnWireMessage> {
    let action = ActionMsg::SetUserRole(SetUserRoleAction {
        user_id: member_name.to_owned(),
        role_name: new_role,
        metadata: ActionMetadata::new(
            client_data.get_user_id(),
            Uuid::new_v4().to_string(),
            comm_grp.clone(),
        ),
    });

    check_action_msg_and_get_mls(comm_grp, action, backend, client_data)
}

pub fn remove_other_or_self_msg(
    comm_grp: &CommGroupId,
    member_name: &String,
    backend: &mut CryptoBackend,
    client_data: &mut (impl ClientDataProvider + ?Sized),
) -> Vec<OnWireMessage> {
    let client_user = client_data.get_user_id();

    let mls = {
        let mut group = client_data
            .get_ref_group(comm_grp)
            .expect("Cannot find that group")
            .borrow_mut();

        if member_name == &client_user {
            group
                .leave_group(backend)
                .expect("Could not generate leave group update")
        } else {
            let member_hash_ref =
                get_member_hash_ref(group.members(), &str_to_identity(member_name), backend);
            group
                .remove_members(backend, &[member_hash_ref])
                .expect("Could not generate leave group update")
                .0 //Note: ignoring .1 because our system does not allow both add and remove at same commit
        }
    };

    let update_group = GroupMessage::from_mls(mls, comm_grp.clone(), Some(client_user));

    group_msg_to_ord_onwire_broadcast(update_group, comm_grp, client_data).to_vec()
}

pub fn send_group_state_update(
    user_name: &String,
    comm_grp: &CommGroupId,
    backend: &mut CryptoBackend,
    client_data: &mut (impl ClientDataProvider + ?Sized),
) -> Vec<OnWireMessage> {
    let update = GovStateAnnouncementAction {
        group_state: client_data.get_shared_state(comm_grp).clone(),
        metadata: ActionMetadata::new(
            user_name.to_string(),
            Uuid::new_v4().to_string(),
            comm_grp.clone(),
        ),
    };

    let action_msg = ActionMsg::GovStateAnnouncement(update);
    check_action_msg_and_get_mls(comm_grp, action_msg, backend, client_data)
}

#[cfg(feature = "gov")]
pub fn accept_msg(
    comm_grp: &CommGroupId,
    backend: &mut CryptoBackend,
    client_data: &mut ClientRef,
) -> Vec<OnWireMessage> {
    let received_gov_state_hash =
        try_activate_gov_state(comm_grp, backend, client_data).expect("Cannot Accept");

    let action = ActionMsg::Accept(AcceptAction {
        metadata: ActionMetadata::new(
            client_data.get_user_id(),
            Uuid::new_v4().to_string(),
            comm_grp.clone(),
        ),
        received_gov_state_hash,
    });

    check_action_msg_and_get_mls(comm_grp, action, backend, client_data.deref_mut())
}

pub fn parse_incoming_onwire_msgs(
    msgs: Vec<OnWireMessage>,
    client_data: &mut ClientRef,
    backend: &mut CryptoBackend,
) -> Vec<ClientParsedMsg> {
    let mut local_plain_msgs = vec![];
    for onwire_msg in &msgs {
        let parse_begin_timestamp = Instant::now();
        match onwire_msg {
            OnWireMessage::DSRelayedUserWelcome {
                comm_grp,
                sender,
                welcome,
            } => {
                if let Ok(mls_group) = MlsGroup::new_from_welcome(
                    backend,
                    &get_default_group_config(),
                    welcome.clone(),
                    None,
                ) {
                    SingleTimeMeasurement::new(
                        OpenMlsMsgVerifyDecryption,
                        parse_begin_timestamp.elapsed(),
                    );
                    client_data.store_group(comm_grp, None, mls_group);
                    local_plain_msgs.push(ClientParsedMsg::NewInvite {
                        inviter: sender.to_string(),
                        comm_grp: comm_grp.to_owned(),
                    })
                } else {
                    local_plain_msgs.push(ClientParsedMsg::Invalid {
                        external_error: true,
                        retry_possible: false,
                        description: "Received an invalid Welcome".to_string(),
                    });
                }
            }
            OnWireMessage::DSRelayedUserMsg {
                user_msg,
                server_timestamp: _,
            } => local_plain_msgs.extend(match user_msg {
                GroupMessage::AppMlsMessage {
                    mls_msg,
                    comm_grp,
                    sender,
                } => {
                    if client_data.is_shared_gov_state_initialized(comm_grp) {
                        let msgs = parse_mls_message_out(
                            mls_msg.clone(),
                            comm_grp,
                            sender.to_owned(),
                            client_data,
                            backend,
                        );
                        for msg in &msgs {
                            if let NewMsg {
                                private_msg,
                                comm_grp,
                            } = msg
                            {
                                if private_msg.sender != client_data.get_user_id() {
                                    client_data.store_received_msg(
                                        comm_grp,
                                        &private_msg.sender,
                                        private_msg,
                                    )
                                }
                            }
                        }
                        msgs
                    } else {
                        client_data.store_unprocessed_msg(comm_grp, onwire_msg.clone());
                        vec![]
                    }
                }
            }),
            OnWireMessage::DSResult {
                request_valid,
                explanation,
                identifier,
                preceding_and_sent_ordered_msgs,
                process_time_used,
            } => {
                if !request_valid {
                    // DS says Invalid
                    debug!("Process received DS err: {:?}", explanation);
                    if let Some(group_id_str) = identifier.clone() {
                        // DS says invalid | Identifier Available
                        let comm_grp = CommGroupId::from_string(&group_id_str);
                        let clear_commit_timestamp = Instant::now();
                        client_data
                            .get_ref_group(&comm_grp)
                            .unwrap()
                            .borrow_mut()
                            .clear_pending_commit();
                        client_data.pop_pending_action(&comm_grp);
                        SingleTimeMeasurement::new(
                            OpenMlsGroupOperation,
                            clear_commit_timestamp.elapsed(),
                        );
                    };
                } else {
                    // DS says valid
                    if preceding_and_sent_ordered_msgs.is_empty() {
                        // Was sent using `UserSend`/`UserInvite`/etc.,
                        // If was sent with UserSend, supposedly there was an unordered action.
                        // Pop action and execute, if any
                        if let Some(group_id_str) = identifier.clone() {
                            // DS says valid | No message echoed | Identifier Available
                            let comm_grp = CommGroupId::from_string(&group_id_str);

                            if let Some(action) = client_data.pop_pending_action(&comm_grp) {
                                // DS says valid | No message echoed | Identifier Available | Action found
                                policy_check_and_execute(action, &comm_grp, None, client_data);
                            }
                        }
                    } else {
                        // DS says valid | Sent messages echoed back
                        for group_msg in preceding_and_sent_ordered_msgs {
                            match group_msg {
                                GroupMessage::AppMlsMessage {
                                    comm_grp,
                                    sender,
                                    mls_msg,
                                } => {
                                    local_plain_msgs.extend(parse_mls_message_out(
                                        mls_msg.clone(),
                                        comm_grp,
                                        sender.clone(),
                                        client_data,
                                        backend,
                                    ));
                                }
                            }
                        }
                    }
                }

                local_plain_msgs.push(ClientParsedMsg::DSFeedback {
                    request_valid: *request_valid,
                    explanation: explanation.clone(),
                    process_time: process_time_used.to_owned(),
                })
            }
            OnWireMessage::ASResult {
                request_valid,
                explanation,
                process_time_used,
            } => {
                if !request_valid {
                    debug!("Silent process received AS err: {:?}", explanation);
                };
                local_plain_msgs.push(ClientParsedMsg::ASFeedback {
                    request_valid: *request_valid,
                    explanation: explanation.clone(),
                    process_time: process_time_used.to_owned(),
                })
            }

            OnWireMessage::UserKeyPackagesForDS { .. }
            | OnWireMessage::UserRegisterForAS { .. }
            | OnWireMessage::UserCredentialLookup { .. }
            | OnWireMessage::UserKeyPackageLookup { .. }
            | OnWireMessage::UserSyncCredentials { .. }
            | OnWireMessage::UserSync { .. }
            | OnWireMessage::UserInvite { .. }
            | OnWireMessage::UserStandardSend { .. }
            | OnWireMessage::UserReliableSend { .. } => panic!("Received user requests at client"),
            OnWireMessage::ASCredentialResponse { .. } => (),
            OnWireMessage::ASCredentialSyncResponse { credentials } => {
                client_data.set_credential_entries(credentials.clone());
            }
            OnWireMessage::DSKeyPackageResponse { .. } => (),
        }
        SingleTimeMeasurement::new(
            ParseIncomingSingleMsgNonKpFetch,
            parse_begin_timestamp.elapsed(),
        );
    }
    local_plain_msgs
}

#[cfg(feature = "gov")]
fn parse_mls_message_out(
    mls_msg: MlsMessageOut,
    comm_grp: &CommGroupId,
    sender: Option<String>,
    client_data: &mut ClientRef,
    backend: &mut CryptoBackend,
) -> Vec<ClientParsedMsg> {
    let mls_msg = MlsMessageIn::from(mls_msg);
    let mut local_plain_msgs = vec![];
    let own_user_name = client_data.get_user_id();

    let get_ref_group_timestamp = Instant::now();
    match client_data.get_ref_group(comm_grp) {
        None => {
            return vec![ClientParsedMsg::Invalid {
                external_error: true,
                retry_possible: false,
                description: "Cannot find the group of a received message.".to_string(),
            }];
        }
        Some(mls_group_ref) => {
            // Group exists
            let exists_pending_commit = mls_group_ref.borrow().pending_commit().is_some();
            debug!(
                "{own_user_name} Received Message Epoch {:?} sent by {:?}, while locally the group is at {:?}",
                mls_msg.epoch(),sender,
                mls_group_ref.borrow().epoch()
            );

            let local_epoch = mls_group_ref.borrow().epoch();

            if Some(own_user_name) == sender {
                // Is a self-sent message, MlsMessageOut cannot be deciphered
                if (mls_msg.epoch() != local_epoch && mls_msg.is_handshake_message())
                    || (mls_msg.epoch() > local_epoch)
                {
                    // Self sent message | Wrong epoch
                    debug!("Self sent message | Wrong epoch");
                    local_plain_msgs.push(ClientParsedMsg::Invalid {
                        external_error: false,
                        retry_possible: true,
                        description: "The action you just attempted did not go through because there was other valid actions preceding it. Please try again".to_string(),
                    });
                    //error!("The action you just attempted did not go through because there was other valid actions preceding it. Please try again");
                    mls_group_ref.borrow_mut().clear_pending_commit();
                    client_data.pop_pending_action(comm_grp);
                    SingleTimeMeasurement::new(
                        OpenMlsGroupOperation,
                        get_ref_group_timestamp.elapsed(),
                    );
                } else {
                    // Self sent message | Correct epoch
                    debug!("Self sent message | Correct epoch");
                    let action_popped = client_data.pop_pending_action(comm_grp);
                    let mut commit_ord_priv_msg: Option<OrderedPrivateMessage> = None;
                    if let Some(pending_commit) = client_data
                        .get_ref_group(comm_grp)
                        .unwrap()
                        .borrow_mut()
                        .pending_commit()
                    {
                        let mut ord_priv_msgs: Vec<Option<OrderedPrivateMessage>> = pending_commit
                            .ord_app_msg_proposals()
                            .map(|queued_prop| {
                                ordered_deserialize(queued_prop.ord_app_msg_proposal().get_bytes())
                            })
                            .collect();
                        if ord_priv_msgs.len() == 1 && ord_priv_msgs[0].is_some() {
                            commit_ord_priv_msg = ord_priv_msgs.remove(0);
                        }
                    }
                    match action_popped {
                        Some(action) => {
                            // Self sent message | Correct epoch | Locally Stored Action Exists
                            debug!(
                                "Self sent message | Correct epoch | Locally Stored Action Exists"
                            );
                            if exists_pending_commit {
                                if let Some(OrderedPrivateMessage {
                                    content:
                                        OrderedMsgContent::Action(VerifiableAction {
                                            action: act_msg,
                                            signature: _,
                                        }),
                                }) = commit_ord_priv_msg
                                {
                                    assert_eq!(act_msg, action, "The stored pending action was not the same as the action in the pending commit");
                                    policy_check_and_execute(action, comm_grp, None, client_data);
                                }
                            } else {
                                debug!(
                                    "*Found locally saved action but cannot find the local commit"
                                );
                            }
                        }
                        None => {
                            // Self sent message | Correct epoch | NO Locally Stored Action
                            debug!("Self sent message | Correct epoch | NO Locally Stored Action");
                            // Inspect staged commit to extract ordered app messages
                            // Clear those actions
                            if let Some(OrderedPrivateMessage {
                                content: OrderedMsgContent::ActionVec(proposed_actions),
                            }) = commit_ord_priv_msg
                            {
                                info!("Clearing proposed actions for self-sent message");
                                client_data.remove_proposed_actions(comm_grp, &proposed_actions);
                                evaluate_proposed_actions(
                                    proposed_actions,
                                    comm_grp,
                                    None,
                                    client_data,
                                );
                            } else {
                                debug!("No locally saved action or pending commit");
                            }

                            client_data
                                .get_ref_group(comm_grp)
                                .unwrap()
                                .borrow_mut()
                                .merge_pending_commit()
                                .expect(
                                    "Cannot merge pending commit, and also the action is missing",
                                );

                            // TODO: check that this is right place to handle this
                            if exists_pending_commit {
                                let proposed_actions = client_data.get_proposed_actions(comm_grp);
                                info!("Clearing proposed actions for self-sent message");
                                client_data.clear_proposed_actions(comm_grp);
                                evaluate_proposed_actions(
                                    proposed_actions,
                                    comm_grp,
                                    None,
                                    client_data,
                                );
                            } else {
                                debug!("No locally saved action or pending commit");
                            }

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
                    local_plain_msgs.push(ClientParsedMsg::Invalid {
                        external_error: true,
                        retry_possible: false,
                        description: "An action by other group member was discarded because it had Wrong Epoch".to_string(),
                    });
                } else {
                    // Message from other group member | Correct epoch
                    debug!("Message from other group member | Correct epoch");
                    let unverified_r = mls_group_ref.borrow_mut().parse_message(mls_msg, backend);

                    //.expect("Cannot parse incoming MlsGroup Message");
                    let unverified = if unverified_r.is_err() {
                        debug!("Unable to decrypt a message");
                        return vec![ClientParsedMsg::Invalid {
                            external_error: true,
                            retry_possible: false,
                            description: "Unable to decrypt an incoming message".to_string(),
                        }];
                    } else {
                        unverified_r.unwrap()
                    };
                    trace!("Unverified message: {:?}", unverified);
                    // https://openmls.tech/book/user_manual/processing.html#processing-messages No sig key required
                    let processed_result = mls_group_ref
                        .borrow_mut()
                        .process_unverified_message(unverified, None, backend);

                    let processed = match processed_result {
                        Ok(r) => r,
                        Err(_) => {
                            return vec![ClientParsedMsg::Invalid {
                                external_error: true,
                                retry_possible: false,
                                description: "Unable to verify an incoming message".to_string(),
                            }];
                        }
                    };
                    trace!("Processed message: {:?}", processed);
                    SingleTimeMeasurement::new(
                        OpenMlsMsgVerifyDecryption,
                        get_ref_group_timestamp.elapsed(),
                    );
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
                            if let UnorderedMsgContent::TextAction { text_action } =
                                &mut private_msg.content
                            {
                                let public_key = client_data
                                    .get_user_verify_key(&text_action.action.get_metadata().sender)
                                    .expect("Do not have the public key locally");
                                if text_action.verify(public_key) {
                                    info!("signature is valid");
                                    policy_check_and_execute(
                                        text_action.action.clone(),
                                        comm_grp,
                                        None,
                                        client_data,
                                    );
                                } else {
                                    debug!("invalid signature");
                                }
                            } else if let UnorderedMsgContent::ProposedAction { proposed_action } =
                                &mut private_msg.content
                            {
                                // TODO: filter for votes
                                client_data
                                    .store_proposed_action(comm_grp, proposed_action.clone());
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

                            trace!("The ordered app msg: {:?}", ord_app_msgs);

                            if ord_app_msgs.is_empty() {
                                // Message from other group member | Correct epoch | HandShake | No Actions
                                // No ordered message, so check if there is add proposal
                                let mut merge = !(add_invitees.is_empty() && to_removed.is_empty());

                                for add_invitee in add_invitees {
                                    merge = merge
                                        && client_data
                                            .pop_to_add_invitee_key_pack(comm_grp, &add_invitee)
                                            .is_some();
                                }
                                for remove_candidates in &to_removed {
                                    merge = merge
                                        && client_data
                                            .pop_to_be_removed_member(comm_grp, remove_candidates);
                                }

                                if merge {
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
                                } else {
                                    debug!("An ordered message by other group member was not processed because it had no actions");
                                }
                            } else {
                                // Message from other group member | Correct epoch | HandShake | Exists Actions
                                // Only process one/first ordered action at one commit to avoid committing half a commit
                                for bytes in &ord_app_msgs {
                                    let action_opt: Option<OrderedPrivateMessage> =
                                        ordered_deserialize(bytes);

                                    if let Some(OrderedPrivateMessage {
                                        content: OrderedMsgContent::Action(verifiable_action),
                                    }) = action_opt
                                    {
                                        let public_key = client_data
                                            .get_user_verify_key(
                                                &verifiable_action.action.get_metadata().sender,
                                            )
                                            .expect("Do not have the public key locally");
                                        if verifiable_action.verify(public_key) {
                                            // Message from other group member | Correct epoch | HandShake | Exists Actions| Signature checks out
                                            policy_check_and_execute(
                                                verifiable_action.action,
                                                comm_grp,
                                                Some(staged_commit),
                                                client_data,
                                            );
                                            break;
                                        } else {
                                            info!(
                                                "A message from a member in the group was invalid"
                                            )
                                        }
                                    } else if let Some(OrderedPrivateMessage {
                                        content: OrderedMsgContent::ActionVec(action_vec),
                                    }) = action_opt
                                    {
                                        evaluate_proposed_actions(
                                            action_vec,
                                            comm_grp,
                                            Some(staged_commit),
                                            client_data,
                                        );
                                        break;
                                    }
                                }
                            };
                            let mut hasher = DefaultHasher::new();
                            serde_json::to_string(client_data.get_shared_state(comm_grp))
                                .expect("Cannot serialize group state")
                                .hash(&mut hasher);
                            info!(
                                "Group state hash after the ordered update: {:?}",
                                hasher.finish()
                            );
                        }
                    }
                }
            }
        }
    };
    local_plain_msgs
}

/// Check authorization and execute the action, then merge the (staged (hence external)) commit.
/// if the commit is `None`, then merge the pending (hence self-init'ed) commit
#[cfg(feature = "gov")]
fn policy_check_and_execute(
    action: ActionMsg,
    comm_grp: &CommGroupId,
    commit: Option<Box<StagedCommit>>,
    client_data: &mut ClientRef,
) {
    let pre_auth_timestamp = Instant::now();
    if client_data.action_authorized(&action) {
        SingleTimeMeasurement::new(MlsGovRBACCheck, pre_auth_timestamp.elapsed());

        action.execute(client_data.deref_mut());
        merge_commit_opt(client_data, comm_grp, commit);
        info!("An action of type {:?} went through", action.action_type());

        trace!(
            "The current governance state for this group is: {:?}",
            client_data
        );

        let clear_commit_timestamp = Instant::now();
        // Should any merge succeeded
        client_data
            .get_ref_group(comm_grp)
            .unwrap()
            .borrow_mut()
            .clear_pending_commit();
        SingleTimeMeasurement::new(OpenMlsGroupOperation, clear_commit_timestamp.elapsed());
    } else {
        SingleTimeMeasurement::new(MlsGovRBACCheck, pre_auth_timestamp.elapsed());
        let policy_engine_timestamp = Instant::now();
        info!("That action is not authorized, so it will be evaluated by the PolicyEngine");
        // Obtain a reference to the policy engine
        let policy_engine_ref = client_data.get_policy_engine_ref_clone(comm_grp);

        // Evaluate this action
        let mut policy_eng_mut = policy_engine_ref.borrow_mut();

        policy_eng_mut.evaluate_action(action, client_data);

        // Evaluate all proposed actions
        policy_eng_mut.evaluate_all_proposed_actions(client_data);

        SingleTimeMeasurement::new(MlsGovPolicyEngineCheck, policy_engine_timestamp.elapsed());

        // TODO: make sure that it is not an Add commit (if not filtered otherwise)
        merge_commit_opt(client_data, comm_grp, commit);
    }
}

/// Check authorization and execute the action, then merge the (staged (hence external)) commit.
/// if the commit is `None`, then merge the pending (hence self-init'ed) commit
/// TODO: dedup with above
#[cfg(feature = "gov")]
fn evaluate_proposed_actions(
    action_vec: Vec<VerifiableAction>,
    comm_grp: &CommGroupId,
    commit: Option<Box<StagedCommit>>,
    client_data: &mut ClientRef,
) {
    // SingleTimeMeasurement::new(MlsGovRBACCheck, pre_auth_timestamp.elapsed());
    let policy_engine_timestamp = Instant::now();
    info!("That action is not authorized, so it will be evaluated by the PolicyEngine");
    // Obtain a reference to the policy engine
    let policy_engine_ref = client_data.get_policy_engine_ref_clone(comm_grp);

    // Evaluate this action
    let mut policy_eng_mut = policy_engine_ref.borrow_mut();

    // TODO: is this the proper place to clear?
    client_data.remove_proposed_actions(comm_grp, &action_vec);

    for verifiable_action in action_vec {
        if let Some(public_key) =
            client_data.get_user_verify_key(&verifiable_action.action.get_metadata().sender)
        {
            if verifiable_action.verify(public_key) {
                policy_eng_mut.evaluate_action(verifiable_action.action, client_data);
            }
        } else {
            info!(
                "Public key not found for sender of action {:?}",
                verifiable_action
            );
        }
    }

    // Evaluate all proposed actions
    policy_eng_mut.evaluate_all_proposed_actions(client_data);

    SingleTimeMeasurement::new(MlsGovPolicyEngineCheck, policy_engine_timestamp.elapsed());

    // TODO: make sure that it is not an Add commit (if not filtered otherwise)
    merge_commit_opt(client_data, comm_grp, commit);
}

fn merge_commit_opt(
    client_data: &mut ClientRef,
    comm_grp: &CommGroupId,
    commit: Option<Box<StagedCommit>>,
) {
    let timestamp = Instant::now();
    match commit {
        None => {
            client_data
                .get_ref_group(comm_grp)
                .unwrap()
                .borrow_mut()
                .merge_pending_commit()
                .expect("Cannot merge pending commit");
        }
        Some(commit_box) => {
            client_data
                .get_ref_group(comm_grp)
                .unwrap()
                .borrow_mut()
                .merge_staged_commit(*commit_box)
                .expect("Cannot merge staged commit");
        }
    }
    SingleTimeMeasurement::new(OpenMlsGroupOperation, timestamp.elapsed());
}
