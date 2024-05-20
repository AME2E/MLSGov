//! A module to declare all client-level data structures,
//! and their helper functions

// Credit: Crypto Service structure adapted from
// - OpenMLS Memory Keystore
//   https://github.com/openmls/openmls/blob/83faeae98af97b517f127f9a9f54bd9a6f1140eb/memory_keystore/src/lib.rs
// - OpenMLS Rust Crypto
//   https://github.com/openmls/openmls/blob/83faeae98af97b517f127f9a9f54bd9a6f1140eb/openmls_rust_crypto/src/lib.rs
use crate::client_api::actions::{ActionMsg, ActionType};
use crate::client_api::client_crypto_impl::BackendError;
use crate::messages::UnorderedPrivateMessage;
use crate::policyengine::{Policy, PolicyEngine};
use crate::servers_api::as_struct::CredentialEntry;
use crate::{BytesVisitor, CommGroupId};
use ed25519_dalek::{Keypair, PublicKey};
#[cfg(test)]
use mockall::automock;
use openmls::group::MlsGroup;
use openmls::key_packages::KeyPackage;
use openmls::prelude::{Credential, Welcome};
use serde::{Deserialize, Serialize};
use serde_json_any_key::any_key_map;
use std::any::Any;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::rc::Rc;
use std::time::Duration;
use std::vec;

use crate::messages::OnWireMessage;

use crate::client_api::VerifiableAction;
use crate::policyengine::policy_eng_deserialize;
use crate::policyengine::policy_eng_serialize;

#[cfg_attr(test, automock)]

pub trait ClientDataProvider: Debug {
    fn store_group(
        &mut self,
        comm_grp: &CommGroupId,
        gov_state_init_hash: Option<u64>,
        mls_group: MlsGroup,
    );
    fn remove_group(&mut self, comm_grp: &CommGroupId);
    /// Loads in `shared_state` for the governance state associated with
    /// the specified community and group
    fn load_shared_state(&mut self, comm_grp: &CommGroupId, shared_state: SharedGroupState);
    /// Return the current shared state within the group
    fn get_shared_state(&self, comm_grp: &CommGroupId) -> &SharedGroupState;

    fn get_ref_group<'a>(&'a mut self, comm_grp: &CommGroupId)
        -> Option<&'a mut RefCell<MlsGroup>>;

    fn store_welcome(&mut self, comm_grp: &CommGroupId, welcome: Welcome);
    fn contains_welcome(&self, comm_grp: &CommGroupId) -> bool;
    fn get_welcome_clone(&self, comm_grp: &CommGroupId) -> Option<Welcome>;
    fn remove_welcome(&mut self, comm_grp: &CommGroupId) -> Option<Welcome>;
    /// Return the user id associated with this client
    fn get_user_id(&self) -> String;
    fn get_credential(&self) -> Credential;
    fn update_governance_state(&mut self, comm_grp: &CommGroupId, key: String, value: String);

    fn store_to_add_invitee_key_pack(&mut self, comm_grp: &CommGroupId, key_package: KeyPackage);

    fn pop_to_add_invitee_key_pack(
        &mut self,
        comm_grp: &CommGroupId,
        invitee_name: &str,
    ) -> Option<KeyPackage>;

    fn store_to_be_removed_member(&mut self, comm_grp: &CommGroupId, member: &String);

    fn pop_to_be_removed_member(&mut self, comm_grp: &CommGroupId, member: &String) -> bool;

    /// A function called when the current client
    /// sending a message, specifically to store a self-sent message
    /// as DS will not relay them back
    fn store_self_sent_msg(
        &mut self,
        comm_grp: &CommGroupId,
        private_msg: &UnorderedPrivateMessage,
    );

    /// A function called to store the action corresponding to a pending
    /// commit. The merging of the pending commit occurs at the MLS layer.
    /// This function allows us to get the corresponding action at the
    /// application layer and apply it once we know our commit has been
    /// relayed.
    fn store_pending_action(
        &mut self,
        comm_grp: &CommGroupId,
        action: crate::client_api::ActionMsg,
    );

    /// A function called to retrieve and remove a pending action if any.
    /// Currently this action is returned as a [ClientParsedMsg], however
    /// we will soon replace this with a new Action type.
    fn pop_pending_action(
        &mut self,
        comm_grp: &CommGroupId,
    ) -> Option<crate::client_api::ActionMsg>;

    /// A function called during parsing when received a new message from DS
    fn store_received_msg(
        &mut self,
        comm_grp: &CommGroupId,
        sender: &str,
        private_msg: &UnorderedPrivateMessage,
    );

    /// Change the name associated with the given group
    fn set_group_name(&mut self, comm_grp: &CommGroupId, new_name: String);

    /// Obtain the name of the group
    fn get_group_name(&self, comm_grp: &CommGroupId) -> &str;

    /// Change the topic associated with the given group
    fn set_group_topic(&mut self, comm_grp: &CommGroupId, new_topic: String);

    /// Obtain the topic of the group
    fn get_group_topic(&self, comm_grp: &CommGroupId) -> &str;

    /// Define a role within a group as a vector of action types
    fn def_role(
        &mut self,
        comm_grp: &CommGroupId,
        role_name: String,
        action_types: Vec<crate::client_api::ActionType>,
    );

    /// Assign roles to users within a gruop
    fn set_user_role(&mut self, comm_grp: &CommGroupId, user_id: String, role_name: String);

    /// Determines if action is authorized according to the permissions
    /// in the group
    fn action_authorized(&mut self, action: &crate::client_api::ActionMsg) -> bool;

    /// Return the cloned Rbac state
    fn get_roles(&self, comm_grp: &CommGroupId) -> RbacState;

    /// Returns the members belonging to the specified group
    fn get_group_members(&self, comm_grp: &CommGroupId) -> Vec<String>;

    /// Obtains a reference to the ED25519 keypair associated with this client
    fn get_keypair(&self) -> &Keypair;

    /// Obtains a reference to the specified user's ED25519 verification keypair
    fn get_user_verify_key(&self, user_name: &str) -> Option<PublicKey>;

    /// Sets the credential entries within the client
    fn set_credential_entries(&mut self, credentials: BTreeMap<String, CredentialEntry>);

    /// Returns a serialization of the object -- note that in
    /// order to make this trait object safe, we cannot make
    /// `Serialize` a supertrait.
    fn to_string(&self) -> String;

    /// Sets the policies governing a particular client. The policies are
    /// assumed to be empty innitializations.
    fn set_client_policies(&mut self, policies: Vec<Box<dyn Policy>>);

    /// As any to allow proper downcasting
    fn as_any(&self) -> &dyn Any;

    /// As mut any to allow proper downcasting
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Store but not process a received message
    fn store_unprocessed_msg(&mut self, comm_grp: &CommGroupId, msg: OnWireMessage);

    /// Pop stored messages
    fn pop_unprocessed_msgs(&mut self, comm_grp: &CommGroupId) -> Vec<OnWireMessage>;

    /// return whether the group's gov_state is initialized
    fn is_shared_gov_state_initialized(&self, comm_grp: &CommGroupId) -> bool {
        self.get_shared_gov_state_init_hash(comm_grp).is_some()
    }

    /// Store a proposed action
    fn store_proposed_action(&mut self, comm_grp: &CommGroupId, action: VerifiableAction);

    /// Commit all stored proposed actions
    fn get_proposed_actions(&mut self, comm_grp: &CommGroupId) -> Vec<VerifiableAction>;

    /// Remove the specified proposed action from the proposed action vector
    fn remove_proposed_actions(&mut self, comm_grp: &CommGroupId, actions: &Vec<VerifiableAction>);

    /// Clear all proposed actions
    fn clear_proposed_actions(&mut self, comm_grp: &CommGroupId);

    /// set the group's gov_state init hash
    fn set_shared_gov_state_init_hash(&mut self, comm_grp: &CommGroupId, init_hash: Option<u64>);

    /// set the group's gov_state init hash
    fn get_shared_gov_state_init_hash(&self, comm_grp: &CommGroupId) -> Option<u64>;

    /// Remove a single messaage
    fn remove_history_message_with_id(&mut self, comm_grp: &CommGroupId, to_remove_id: String);

    /// Remove a single messaage
    fn get_policy_engine_ref_clone(&self, comm_grp: &CommGroupId) -> Rc<RefCell<PolicyEngine>>;
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ClientParsedMsg {
    NewInvite {
        inviter: String,
        comm_grp: CommGroupId,
    },
    NewMsg {
        private_msg: UnorderedPrivateMessage,
        comm_grp: CommGroupId,
    },
    NewOrdMsg {
        private_msg: String,
        sender: String,
        comm_grp: CommGroupId,
    },
    ASFeedback {
        request_valid: bool,
        explanation: Option<String>,
        process_time: Duration,
    },
    DSFeedback {
        request_valid: bool,
        explanation: Option<String>,
        process_time: Duration,
    },
    Invalid {
        external_error: bool,
        retry_possible: bool,
        description: String,
    },
}

impl From<BackendError> for String {
    fn from(back_err: BackendError) -> Self {
        back_err.to_string()
    }
}

/// Custom deserialization for [MlsGroup], to be used with `serde_with`
pub fn mls_group_deserialize<'a, D>(deserializer: D) -> Result<RefCell<MlsGroup>, D::Error>
where
    D: serde::Deserializer<'a>,
{
    let v = deserializer
        .deserialize_byte_buf(BytesVisitor)
        .expect("Cannot get byte buf");
    match MlsGroup::load(&*v) {
        Ok(mls_group) => Ok(RefCell::new(mls_group)),
        Err(e) => panic!("Cannot load group:{:?}", e),
    }
}

/// Custom serialization for [MlsGroup], to be used with `serde_with`
pub fn mls_group_serialize<S>(x: &RefCell<MlsGroup>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut writer: Vec<u8> = vec![];
    let mut m = x.borrow_mut();
    m.save(&mut writer)
        .expect("Cannot serialize mls using its default save method");

    s.serialize_bytes(&writer)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SharedGroupState {
    /// The human-interpretable name of the group (which can change over time)
    pub name: String,
    /// The topic associated with the group
    pub topic: String,
    /// Rbac state
    pub rbac: RbacState,

    /// A key value store that maps strings to strings -- this is for
    /// storing arbitrary shared state that may be defined for particular
    /// policies
    #[serde(with = "any_key_map")]
    pub governance_state: BTreeMap<String, String>,

    /// A map of pre-approved invitees, mapping their names to their key packages
    pub to_add_invitees: BTreeMap<String, KeyPackage>,

    /// The `PolicyEngine` -- we have it as an `Rc<RefCell<...>>` in order
    /// to deal with the borrow checking implcations of the
    /// `ClientDataProvider` owning the `PolicyEngine` while the
    /// `PolicyEngine` has functions that accept a mutable reference to the
    /// `ClientDataProvider`.
    #[serde(serialize_with = "policy_eng_serialize")]
    #[serde(deserialize_with = "policy_eng_deserialize")]
    pub policy_engine: Rc<RefCell<PolicyEngine>>,

    /// A list of members pre-approved to be removed
    pub to_be_removed_members: Vec<String>,
}

// TODO: better comparison for policy engines
impl PartialEq for SharedGroupState {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.topic == other.topic
            && self.rbac == other.rbac
            && self.governance_state == other.governance_state
            && self.to_add_invitees == other.to_add_invitees
            && self.to_be_removed_members == other.to_be_removed_members
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RbacState {
    /// A mapping from role names to sets of action types
    #[serde(with = "any_key_map")]
    pub role_defs: BTreeMap<String, Vec<ActionType>>,
    #[serde(with = "any_key_map")]
    pub user_to_role: BTreeMap<String, String>,
}

impl RbacState {
    /// Constructs a new Rbac state
    pub fn new() -> Self {
        let mut result = RbacState {
            role_defs: BTreeMap::new(),
            user_to_role: BTreeMap::new(),
        };
        // Currently sets default roles
        result.set_default_roles();
        result
    }

    /// Assigns a role to a user
    pub fn set_user_role(&mut self, user_id: String, role_name: String) {
        self.user_to_role.insert(user_id, role_name);
    }

    /// Defines a role as a vector of action types
    pub fn def_role(&mut self, role_name: String, action_types: Vec<ActionType>) {
        self.role_defs.insert(role_name, action_types);
    }

    /// Returns true if the sender is authorized to perform the given action
    /// and false otherwise.
    pub fn action_authorized(&mut self, sender: &String, action: &ActionMsg) -> bool {
        // Insert user if they don't already exist
        let role = self
            .user_to_role
            .entry(sender.to_owned())
            .or_insert_with(|| "BaseUser".to_string());
        // Check if the role vector contains this action type
        self.role_defs
            .get(role)
            .expect("Role does not exist")
            .contains(&action.action_type())
    }

    /// Initializes default roles for the group
    pub fn set_default_roles(&mut self) {
        self.role_defs.insert(
            "BaseUser".to_string(),
            vec![
                ActionType::TextMsg,
                ActionType::Accept,
                ActionType::UpdateGroupState,
                ActionType::Report,
            ],
        );
        self.role_defs.insert(
            "Mod".to_string(),
            vec![
                ActionType::TextMsg,
                ActionType::RenameGroup,
                ActionType::SetTopicGroup,
                ActionType::TakedownTextMsg,
                ActionType::Invite,
                ActionType::Kick,
                ActionType::DefRole,
                ActionType::SetUserRole,
                ActionType::Accept,
                ActionType::UpdateGroupState,
                ActionType::Report,
            ],
        );
    }
}

impl Default for RbacState {
    fn default() -> Self {
        Self::new()
    }
}
