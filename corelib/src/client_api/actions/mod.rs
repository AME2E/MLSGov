use std::collections::hash_map::DefaultHasher;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::time::Instant;

use clap::ValueEnum;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use log::{debug, info};
use openmls::prelude::KeyPackage;
use serde::{Deserialize, Serialize};

use crate::client_api::client_struct::SharedGroupState;
use crate::messages::encode_to_bytes;
use crate::TimerType::MlsGovVerifiableActionGeneration;
use crate::{identity_to_str, CommGroupId, SingleTimeMeasurement};

use super::client_struct::ClientDataProvider;

/// The `Action` trait is implemented by structs that convey platform
/// actions as interpreted by the client.
pub trait Action: Serialize + Clone + Debug {
    /// Updates the client state and consumes the action.
    fn execute(&self, client_data: &mut (impl ClientDataProvider + ?Sized));
    /// Retrieves the metadata assocaited with the action.
    fn get_metadata(&self) -> ActionMetadata;
    /// Generates the client-server API message associated with the action
    /// so that other group members may receive the action
    fn is_ordered(&self) -> bool;
    /// Generates a signature on the action
    fn sign(&self, keypair: &Keypair) -> Signature {
        // serialize to bytes
        let action_bytes = encode_to_bytes(&self);
        // sign the bytes
        keypair.sign(&action_bytes)
    }
    /// Verifies that the signature on the action is valid
    /// Assumes that the signature in the metadata is set to None
    /// The caller is expected to place the signature back in the signature
    /// feild.
    fn verify_sig(&self, signature: &Signature, verification_key: PublicKey) -> bool {
        let action_bytes = encode_to_bytes(&self);
        verification_key.verify(&action_bytes, signature).is_ok()
    }
}

/// An enum for supported actions (following the definition of proposal types
/// in the MLS spec)
/// See: https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-proposals
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ActionMsg {
    TextMsg(TextMsgAction),
    RenameGroup(RenameGroupAction),
    Report(ReportAction),
    SetTopicGroup(SetTopicGroupAction),
    TakedownTextMsg(TakedownTextMsgAction),
    Invite(InviteAction),
    Kick(KickAction),
    DefRole(DefRoleAction),
    SetUserRole(SetUserRoleAction),
    Accept(AcceptAction),
    Decline(DeclineAction),
    Leave(LeaveAction),
    Vote(VoteAction),
    GovStateAnnouncement(GovStateAnnouncementAction),
    Custom(CustomAction),
}

pub type VoteValue = String;

impl Action for ActionMsg {
    fn execute(&self, client_data: &mut (impl ClientDataProvider + ?Sized)) {
        if !self.is_ordered() {
            //TODO store group state and restore it after an unordered action executed.
            debug!("Warning: giving unordered action mutable access to client state");
        }
        match self {
            ActionMsg::TextMsg(action) => action.execute(client_data),
            ActionMsg::RenameGroup(action) => action.execute(client_data),
            ActionMsg::Report(action) => action.execute(client_data),
            ActionMsg::SetTopicGroup(action) => action.execute(client_data),
            ActionMsg::TakedownTextMsg(action) => action.execute(client_data),
            ActionMsg::Custom(action) => action.execute(client_data),
            ActionMsg::Invite(action) => action.execute(client_data),
            ActionMsg::Kick(action) => action.execute(client_data),
            ActionMsg::DefRole(action) => action.execute(client_data),
            ActionMsg::SetUserRole(action) => action.execute(client_data),
            ActionMsg::Accept(action) => action.execute(client_data),
            ActionMsg::Decline(action) => action.execute(client_data),
            ActionMsg::Leave(action) => action.execute(client_data),
            ActionMsg::Vote(action) => action.execute(client_data),
            ActionMsg::GovStateAnnouncement(action) => action.execute(client_data),
        }
    }

    fn get_metadata(&self) -> ActionMetadata {
        match self {
            ActionMsg::TextMsg(action) => action.get_metadata(),
            ActionMsg::RenameGroup(action) => action.get_metadata(),
            ActionMsg::Report(action) => action.get_metadata(),
            ActionMsg::SetTopicGroup(action) => action.get_metadata(),
            ActionMsg::TakedownTextMsg(action) => action.get_metadata(),
            ActionMsg::Custom(action) => action.get_metadata(),
            ActionMsg::Invite(action) => action.get_metadata(),
            ActionMsg::Kick(action) => action.get_metadata(),
            ActionMsg::DefRole(action) => action.get_metadata(),
            ActionMsg::SetUserRole(action) => action.get_metadata(),
            ActionMsg::Accept(action) => action.get_metadata(),
            ActionMsg::Decline(action) => action.get_metadata(),
            ActionMsg::Leave(action) => action.get_metadata(),
            ActionMsg::Vote(action) => action.get_metadata(),
            ActionMsg::GovStateAnnouncement(action) => action.get_metadata(),
        }
    }

    fn is_ordered(&self) -> bool {
        match self {
            ActionMsg::TextMsg(action) => action.is_ordered(),
            ActionMsg::RenameGroup(action) => action.is_ordered(),
            ActionMsg::Report(action) => action.is_ordered(),
            ActionMsg::SetTopicGroup(action) => action.is_ordered(),
            ActionMsg::TakedownTextMsg(action) => action.is_ordered(),
            ActionMsg::Custom(action) => action.is_ordered(),
            ActionMsg::Invite(action) => action.is_ordered(),
            ActionMsg::Kick(action) => action.is_ordered(),
            ActionMsg::DefRole(action) => action.is_ordered(),
            ActionMsg::SetUserRole(action) => action.is_ordered(),
            ActionMsg::Accept(action) => action.is_ordered(),
            ActionMsg::Decline(action) => action.is_ordered(),
            ActionMsg::Leave(action) => action.is_ordered(),
            ActionMsg::Vote(action) => action.is_ordered(),
            ActionMsg::GovStateAnnouncement(action) => action.is_ordered(),
        }
    }
}

impl ActionMsg {
    pub fn action_type(&self) -> ActionType {
        match self {
            ActionMsg::TextMsg(ref _t) => ActionType::TextMsg,
            ActionMsg::RenameGroup(ref _r) => ActionType::RenameGroup,
            ActionMsg::Report(ref _r) => ActionType::Report,
            ActionMsg::SetTopicGroup(ref _s) => ActionType::SetTopicGroup,
            ActionMsg::TakedownTextMsg(ref _t) => ActionType::TakedownTextMsg,
            ActionMsg::Invite(ref _i) => ActionType::Invite,
            ActionMsg::Kick(ref _k) => ActionType::Kick,
            ActionMsg::DefRole(ref _d) => ActionType::DefRole,
            ActionMsg::SetUserRole(ref _s) => ActionType::SetUserRole,
            ActionMsg::Custom(ref _c) => ActionType::Custom,
            ActionMsg::Accept(ref _a) => ActionType::Accept,
            ActionMsg::Decline(ref _d) => ActionType::Decline,
            ActionMsg::Leave(ref _l) => ActionType::Leave,
            ActionMsg::Vote(_) => ActionType::Vote,
            ActionMsg::GovStateAnnouncement(_) => ActionType::UpdateGroupState,
        }
    }
}

/// ActionType provides a label for actions that will help enable actions
/// whose contents refer to other types of actions e.g. those pertaining to
/// role-based access control.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, ValueEnum)]
pub enum ActionType {
    TextMsg,
    RenameGroup,
    Report,
    SetTopicGroup,
    TakedownTextMsg,
    Invite,
    Kick,
    DefRole,
    SetUserRole,
    Accept,
    Decline,
    Leave,
    Vote,
    UpdateGroupState,
    Custom,
}

/// The [ActionMetadata] struct contains relevant metadata that is common
/// to all actions
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ActionMetadata {
    pub sender: String,
    pub action_id: String,
    pub community_group_id: CommGroupId,
    /// The data associated with the action, which may be modified by the
    /// Policy Engine
    pub data: String,
}

impl ActionMetadata {
    pub fn new(sender: String, action_id: String, community_group_id: CommGroupId) -> Self {
        ActionMetadata {
            sender,
            action_id,
            community_group_id,
            data: "".to_string(),
        }
    }
}

/// This struct consists of an action/signature pair and aids with signing
/// and verifying signatures on actions
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VerifiableAction {
    pub action: ActionMsg,
    pub signature: Signature,
}

impl VerifiableAction {
    /// Generates a new verifiable action and produces a signature
    pub fn new(action: ActionMsg, keypair: &Keypair) -> Self {
        let start_timestamp = Instant::now();
        let signature = action.sign(keypair);
        let _ =
            SingleTimeMeasurement::new(MlsGovVerifiableActionGeneration, start_timestamp.elapsed());
        VerifiableAction { action, signature }
    }

    pub fn verify(&self, verification_key: PublicKey) -> bool {
        self.action.verify_sig(&self.signature, verification_key)
    }
}

/// An `Action` struct for text messages
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TextMsgAction {
    pub msg: String,
    pub metadata: ActionMetadata,
}

impl Action for TextMsgAction {
    fn execute(&self, _client_data: &mut (impl ClientDataProvider + ?Sized)) {
        debug!("Verified message: {}", self.msg);
    }

    fn get_metadata(&self) -> ActionMetadata {
        self.metadata.clone()
    }

    fn is_ordered(&self) -> bool {
        false
    }
}

/// An `Action` struct for a command that renames the group
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RenameGroupAction {
    pub new_name: String,
    pub metadata: ActionMetadata,
}

impl Action for RenameGroupAction {
    fn execute(&self, client_data: &mut (impl ClientDataProvider + ?Sized)) {
        info!(
            "{} Executing RenameGroupAction: to {}",
            client_data.get_user_id(),
            self.new_name.to_string()
        );
        client_data.set_group_name(&self.metadata.community_group_id, self.new_name.to_string());
    }

    fn get_metadata(&self) -> ActionMetadata {
        self.metadata.clone()
    }

    fn is_ordered(&self) -> bool {
        true
    }
}

/// An `Action` struct for reports
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ReportAction {
    /// Verifiable action serialized as a String
    pub ver_action_str: String,
    /// The reason for reporting this action
    pub reason: String,
    pub metadata: ActionMetadata,
}

impl Action for ReportAction {
    fn execute(&self, _client_data: &mut (impl ClientDataProvider + ?Sized)) {}

    fn get_metadata(&self) -> ActionMetadata {
        self.metadata.clone()
    }

    fn is_ordered(&self) -> bool {
        false
    }
}

/// An `Action` for modifying the topic associated with a group
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SetTopicGroupAction {
    pub new_topic: String,
    pub metadata: ActionMetadata,
}

impl Action for SetTopicGroupAction {
    fn execute(&self, client_data: &mut (impl ClientDataProvider + ?Sized)) {
        client_data.set_group_topic(
            &self.metadata.community_group_id,
            self.new_topic.to_string(),
        );
    }

    fn get_metadata(&self) -> ActionMetadata {
        self.metadata.clone()
    }

    fn is_ordered(&self) -> bool {
        true
    }
}

/// An `Action` for taking down messages within a group
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TakedownTextMsgAction {
    pub message_id: String,
    pub reason: String,
    pub metadata: ActionMetadata,
}

impl Action for TakedownTextMsgAction {
    fn execute(&self, client_data: &mut (impl ClientDataProvider + ?Sized)) {
        client_data.remove_history_message_with_id(
            &self.metadata.community_group_id,
            self.message_id.clone(),
        )
    }

    fn get_metadata(&self) -> ActionMetadata {
        self.metadata.clone()
    }

    fn is_ordered(&self) -> bool {
        false
    }
}

/// The `CustomAction` type enables those who build off of our framework
/// to define arbitrary new action types (along with policies governing
/// those actions) without having to modify our code.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CustomAction {
    pub data: String,
    pub metadata: ActionMetadata,
}

impl Action for CustomAction {
    fn execute(&self, _client_data: &mut (impl ClientDataProvider + ?Sized)) {}

    fn get_metadata(&self) -> ActionMetadata {
        self.metadata.clone()
    }

    fn is_ordered(&self) -> bool {
        true
    }
}

/// The application-layer `Action` for inviting someone to a group
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct InviteAction {
    pub metadata: ActionMetadata,
    pub invitee_key_packages: Vec<KeyPackage>,
}

impl Action for InviteAction {
    fn execute(&self, client_data: &mut (impl ClientDataProvider + ?Sized)) {
        for invitee_key_package in &self.invitee_key_packages {
            client_data.set_user_role(
                &self.metadata.community_group_id,
                identity_to_str(invitee_key_package.credential().identity())
                    .expect("Failed to convert identity to string"),
                "BaseUser".to_string(), //TODO create a generic method for each plugin "init_for_new_invitee"?
            );
            client_data.store_to_add_invitee_key_pack(
                &self.metadata.community_group_id,
                invitee_key_package.clone(),
            );
        }
    }

    fn get_metadata(&self) -> ActionMetadata {
        self.metadata.clone()
    }

    fn is_ordered(&self) -> bool {
        true
    }
}

/// The application-layer `Action` for removing someone from a group
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct KickAction {
    pub target_user_id: String,
    pub metadata: ActionMetadata,
}

impl Action for KickAction {
    fn execute(&self, client_data: &mut (impl ClientDataProvider + ?Sized)) {
        client_data
            .store_to_be_removed_member(&self.metadata.community_group_id, &self.target_user_id);
        if self.target_user_id == client_data.get_user_id() {
            info!("Kick you was authorized in the group.");
        } else {
            info!("Kick {} was authorized. One must use Remove (Target) to remove them from the group", self.target_user_id);
        }
    }

    fn get_metadata(&self) -> ActionMetadata {
        self.metadata.clone()
    }

    fn is_ordered(&self) -> bool {
        true
    }
}

/// The `Action` for defining a user role
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DefRoleAction {
    pub role_name: String,
    pub action_types: Vec<ActionType>,
    pub metadata: ActionMetadata,
}

impl Action for DefRoleAction {
    fn execute(&self, client_data: &mut (impl ClientDataProvider + ?Sized)) {
        client_data.def_role(
            &self.metadata.community_group_id,
            self.role_name.to_string(),
            self.action_types.clone(),
        )
    }

    fn get_metadata(&self) -> ActionMetadata {
        self.metadata.clone()
    }

    fn is_ordered(&self) -> bool {
        true
    }
}

/// The `Action` for assigning a role to a user. Currently, a user can hold
/// exactly one role at any given time.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SetUserRoleAction {
    pub user_id: String,
    pub role_name: String,
    pub metadata: ActionMetadata,
}

impl Action for SetUserRoleAction {
    fn execute(&self, client_data: &mut (impl ClientDataProvider + ?Sized)) {
        client_data.set_user_role(
            &self.metadata.community_group_id,
            self.user_id.to_string(),
            self.role_name.to_string(),
        )
    }

    fn get_metadata(&self) -> ActionMetadata {
        self.metadata.clone()
    }

    fn is_ordered(&self) -> bool {
        true
    }
}

/// Leave the group given in the metadata
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LeaveAction {
    pub metadata: ActionMetadata,
}

impl Action for LeaveAction {
    fn execute(&self, client_data: &mut (impl ClientDataProvider + ?Sized)) {
        client_data
            .store_to_be_removed_member(&self.metadata.community_group_id, &self.metadata.sender);
        if self.metadata.sender == client_data.get_user_id() {
            info!("Leave Action was successful. You will still need to use Remove (Self) to remove your cryptographical info completely from the group and thus stop reiceiving messages");
        }
    }

    fn get_metadata(&self) -> ActionMetadata {
        self.metadata.clone()
    }

    fn is_ordered(&self) -> bool {
        true
    }
}

/// Accept invite to the group
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AcceptAction {
    pub metadata: ActionMetadata,
    pub received_gov_state_hash: u64,
}

impl Action for AcceptAction {
    fn execute(&self, _client_data: &mut (impl ClientDataProvider + ?Sized)) {
        info!(
            "{} acknowledged that they received the invite to {}, and received gov state hash [{:?}]",
            self.metadata.sender,
            self.metadata.community_group_id.get_string(),
            self.received_gov_state_hash
        )
    }

    fn get_metadata(&self) -> ActionMetadata {
        self.metadata.clone()
    }

    fn is_ordered(&self) -> bool {
        false
    }
}

/// Decline invite to the group
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DeclineAction {
    pub metadata: ActionMetadata,
}

impl Action for DeclineAction {
    fn execute(&self, client_data: &mut (impl ClientDataProvider + ?Sized)) {
        client_data
            .store_to_be_removed_member(&self.metadata.community_group_id, &self.metadata.sender);

        if self.metadata.sender == client_data.get_user_id() {
            info!("You will still need to use Remove (Self) to remove your cryptographical info completely from the group and thus stop reiceiving messages");
        }
    }

    fn get_metadata(&self) -> ActionMetadata {
        self.metadata.clone()
    }

    fn is_ordered(&self) -> bool {
        true
    }
}

/// An action to aid with policies that deal with voting
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VoteAction {
    /// The value of the vote: can be "yes" or "no", for instance
    pub vote_value: VoteValue,
    /// The identifier of the proposed action to which this vote pertains
    pub proposed_action_id: String,
    /// The type of the proposed action, in order to aid with filtering
    pub proposed_action_type: ActionType,
    pub metadata: ActionMetadata,
}

impl Action for VoteAction {
    fn execute(&self, _client_data: &mut (impl ClientDataProvider + ?Sized)) {}

    fn get_metadata(&self) -> ActionMetadata {
        self.metadata.clone()
    }

    fn is_ordered(&self) -> bool {
        true
    }
}

/// An action to aid with policies that deal with voting
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GovStateAnnouncementAction {
    /// The new group state
    pub group_state: SharedGroupState,
    pub metadata: ActionMetadata,
}

impl Action for GovStateAnnouncementAction {
    fn execute(&self, client_data: &mut (impl ClientDataProvider + ?Sized)) {
        if !client_data.is_shared_gov_state_initialized(&self.metadata.community_group_id) {
            debug!(
                "The previous group state was {:?}",
                client_data.get_shared_state(&self.metadata.community_group_id)
            );
            let mut hasher = DefaultHasher::new();
            serde_json::to_string(&self.group_state)
                .expect("Cannot serialize group state")
                .hash(&mut hasher);
            client_data
                .load_shared_state(&self.metadata.community_group_id, self.group_state.clone());

            client_data.set_shared_gov_state_init_hash(
                &self.metadata.community_group_id,
                Some(hasher.finish()),
            );

            debug!(
                "The current group state is now {:?}",
                client_data.get_shared_state(&self.metadata.community_group_id)
            );
        } else {
            let mut hasher = DefaultHasher::new();
            serde_json::to_string(&self.group_state)
                .expect("Cannot serialize group state")
                .hash(&mut hasher);
            client_data
                .load_shared_state(&self.metadata.community_group_id, self.group_state.clone());
            info!(
                "Hash of the shared group state from {}: {:?}",
                self.metadata.sender,
                hasher.finish()
            );
        }
    }

    fn get_metadata(&self) -> ActionMetadata {
        self.metadata.clone()
    }

    fn is_ordered(&self) -> bool {
        false
    }
}
