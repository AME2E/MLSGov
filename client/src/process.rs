use core::panic;
use std::ops::DerefMut;

use openmls::prelude::KeyPackage;
use uuid::Uuid;

use corelib::client_api::actions::ActionMetadata;
use corelib::client_api::actions::ActionMsg;
use corelib::client_api::actions::CustomAction;
use corelib::client_api::actions::DefRoleAction;
use corelib::client_api::actions::ReportAction;
use corelib::client_api::actions::SetTopicGroupAction;
use corelib::client_api::actions::TakedownTextMsgAction;
use corelib::client_api::actions::{RenameGroupAction, VoteAction};
use corelib::client_api::client_crypto_impl::CryptoBackend;
use corelib::client_api::*;
use corelib::messages::*;
use corelib::policyengine::ClientRef;
use corelib::CommGroupId;

use crate::local_struct::ClientInputCommand;

pub(crate) fn group_onwire_msgs_for_ds(
    command: &ClientInputCommand,
    backend: &mut CryptoBackend,
    client_data: &mut ClientRef,
    external_key_packages_opt: Option<Vec<KeyPackage>>,
) -> Vec<OnWireMessage> {
    let user_name = client_data.get_user_id();
    let result = match command {
        ClientInputCommand::Register { .. }
        | ClientInputCommand::Sync
        | ClientInputCommand::ShowGroupState { .. }
        | ClientInputCommand::Read { .. }
        | ClientInputCommand::Create { .. } => {
            panic!("Not a group command")
        }

        ClientInputCommand::Invite {
            community_id,
            group_id,
            invitee_names: _,
        } => pre_add_invite_msg(
            &user_name,
            &CommGroupId::new(community_id, group_id),
            backend,
            client_data.deref_mut(),
            external_key_packages_opt.expect("Should have looked up key package for invitee"),
        ),
        ClientInputCommand::Add {
            community_id,
            group_id,
            invitee_names,
        } => add_msg(
            &CommGroupId::new(community_id, group_id),
            invitee_names,
            client_data.deref_mut(),
            backend,
        ),
        ClientInputCommand::Send {
            community_id,
            group_id,
            message,
        } => send_text_msg_mls(
            &user_name,
            &CommGroupId::new(community_id, group_id),
            message.to_string(),
            backend,
            client_data.deref_mut(),
        ),
        ClientInputCommand::RenameGroup {
            community_id,
            group_id,
            new_group_id,
        } => {
            let action = ActionMsg::RenameGroup(RenameGroupAction {
                new_name: new_group_id.to_owned(),
                metadata: ActionMetadata::new(
                    user_name.to_owned(),
                    Uuid::new_v4().to_string(),
                    CommGroupId::new(community_id, group_id),
                ),
            });

            check_action_msg_and_get_mls(
                &CommGroupId::new(community_id, group_id),
                action,
                backend,
                client_data.deref_mut(),
            )
        }

        ClientInputCommand::ChangeGroupTopic {
            community_id,
            group_id,
            new_group_topic,
        } => {
            let action = ActionMsg::SetTopicGroup(SetTopicGroupAction {
                new_topic: new_group_topic.to_owned(),
                metadata: ActionMetadata::new(
                    user_name.to_owned(),
                    Uuid::new_v4().to_string(),
                    CommGroupId::new(community_id, group_id),
                ),
            });
            check_action_msg_and_get_mls(
                &CommGroupId::new(community_id, group_id),
                action,
                backend,
                client_data.deref_mut(),
            )
        }

        ClientInputCommand::Leave {
            community_id,
            group_id,
        } => pre_leave_msg(
            &CommGroupId::new(community_id, group_id),
            backend,
            client_data.deref_mut(),
        ),

        ClientInputCommand::Accept {
            group_id,
            community_id,
        } => accept_msg(
            &CommGroupId::new(community_id, group_id),
            backend,
            client_data,
        ),
        ClientInputCommand::Decline {
            community_id,
            group_id,
        } => pre_decline_msg(
            &CommGroupId::new(community_id, group_id),
            backend,
            client_data,
        ),
        ClientInputCommand::Kick {
            community_id,
            group_id,
            member_name,
        } => pre_kick_msg(
            &CommGroupId::new(community_id, group_id),
            member_name,
            backend,
            client_data.deref_mut(),
        ),
        ClientInputCommand::SetRole {
            community_id,
            group_id,
            member_name,
            new_role,
        } => set_role_msg(
            &CommGroupId::new(community_id, group_id),
            member_name,
            new_role.to_string(),
            backend,
            client_data.deref_mut(),
        ),

        ClientInputCommand::Remove {
            community_id,
            group_id,
            member_name,
        } => remove_other_or_self_msg(
            &CommGroupId::new(community_id, group_id),
            member_name,
            backend,
            client_data.deref_mut(),
        ),

        ClientInputCommand::UpdateGroupState {
            community_id,
            group_id,
        } => send_group_state_update(
            &user_name,
            &CommGroupId::new(community_id, group_id),
            backend,
            client_data.deref_mut(),
        ),
        ClientInputCommand::Vote {
            community_id,
            group_id,
            vote_value,
            proposed_action_id,
            proposed_action_type,
        } => {
            let action = ActionMsg::Vote(VoteAction {
                vote_value: vote_value.to_owned(),
                proposed_action_id: proposed_action_id.to_owned(),
                proposed_action_type: proposed_action_type.to_owned(),
                metadata: ActionMetadata::new(
                    user_name.to_owned(),
                    Uuid::new_v4().to_string(),
                    CommGroupId::new(community_id, group_id),
                ),
            });

            check_action_msg_and_get_mls(
                &CommGroupId::new(community_id, group_id),
                action,
                backend,
                client_data.deref_mut(),
            )
        }
        ClientInputCommand::DefRole {
            community_id,
            group_id,
            role_name,
            action_types,
        } => {
            let action = ActionMsg::DefRole(DefRoleAction {
                role_name: role_name.to_owned(),
                action_types: action_types.to_owned(),
                metadata: ActionMetadata::new(
                    user_name.to_owned(),
                    Uuid::new_v4().to_string(),
                    CommGroupId::new(community_id, group_id),
                ),
            });

            check_action_msg_and_get_mls(
                &CommGroupId::new(community_id, group_id),
                action,
                backend,
                client_data.deref_mut(),
            )
        }
        ClientInputCommand::Report {
            community_id,
            group_id,
            ver_action_str,
            reason,
        } => {
            let action = ActionMsg::Report(ReportAction {
                ver_action_str: ver_action_str.to_owned(),
                reason: reason.to_owned(),
                metadata: ActionMetadata::new(
                    user_name.to_owned(),
                    Uuid::new_v4().to_string(),
                    CommGroupId::new(community_id, group_id),
                ),
            });

            check_action_msg_and_get_mls(
                &CommGroupId::new(community_id, group_id),
                action,
                backend,
                client_data.deref_mut(),
            )
        }
        ClientInputCommand::Custom {
            community_id,
            group_id,
            data,
        } => {
            let action = ActionMsg::Custom(CustomAction {
                data: data.to_owned(),
                metadata: ActionMetadata::new(
                    user_name.to_owned(),
                    Uuid::new_v4().to_string(),
                    CommGroupId::new(community_id, group_id),
                ),
            });

            check_action_msg_and_get_mls(
                &CommGroupId::new(community_id, group_id),
                action,
                backend,
                client_data.deref_mut(),
            )
        }
        ClientInputCommand::TakedownText {
            community_id,
            group_id,
            message_id,
            reason,
        } => {
            let action = ActionMsg::TakedownTextMsg(TakedownTextMsgAction {
                message_id: message_id.to_owned(),
                reason: reason.to_owned(),
                metadata: ActionMetadata::new(
                    user_name.to_owned(),
                    Uuid::new_v4().to_string(),
                    CommGroupId::new(community_id, group_id),
                ),
            });

            check_action_msg_and_get_mls(
                &CommGroupId::new(community_id, group_id),
                action,
                backend,
                client_data.deref_mut(),
            )
        }
        ClientInputCommand::ProposeVote {
            community_id,
            group_id,
            vote_value,
            proposed_action_id,
            proposed_action_type,
        } => propose_vote(
            &CommGroupId::new(community_id, group_id),
            vote_value,
            proposed_action_id,
            proposed_action_type.to_owned(),
            backend,
            client_data.deref_mut(),
        ),
        ClientInputCommand::CommitPendingVotes {
            community_id,
            group_id,
        } => commit_proposed_votes(
            &CommGroupId::new(community_id, group_id),
            backend,
            client_data.deref_mut(),
        ),
    };
    result
}
