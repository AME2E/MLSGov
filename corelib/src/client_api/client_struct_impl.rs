use crate::client_api::client_struct::{mls_group_deserialize, mls_group_serialize};
use crate::messages::{welcome_deserialize, welcome_serialize};

use core::cell::RefCell;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::SystemTime;

use crate::client_api::client_struct::{ClientDataProvider, RbacState, SharedGroupState};
use crate::identity_to_str;
use crate::messages::{OnWireMessage, UnorderedMsgContent, UnorderedPrivateMessage};
use crate::policyengine::{Policy, PolicyEngine};
use crate::servers_api::as_struct::CredentialEntry;
use crate::servers_api::mls_helpers::user_names_from_mls_group;
use crate::CommGroupId;
use ed25519_dalek::{Keypair, PublicKey};
use openmls::credentials::Credential;
use openmls::key_packages::KeyPackage;
use openmls::messages::Welcome;
use openmls::prelude::MlsGroup;
use serde::{Deserialize, Serialize};
use serde_json_any_key::any_key_map;

use crate::client_api::actions::{Action, ActionMsg, ActionType, VerifiableAction};

/// The `ClientData` struct stores all the state relevent to this client
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientData {
    /// The user name associated with this client
    pub user_name: String,
    /// The `Credential` object for this client
    pub credential: Credential,
    /// The ED25519 keypair for authenticating the  actions of this client
    /// and reporting
    pub verif_keypair: Keypair,
    /// A set of policies supported by this client
    pub policies: Vec<Box<dyn Policy>>,
    /// A mapping from user names to credential entries
    pub credential_entries: BTreeMap<String, CredentialEntry>,
    #[serde(with = "any_key_map")]
    pub community_states: BTreeMap<String, LocalCommunityState>,
    #[serde(with = "any_key_map")]
    pub pending_welcomes: BTreeMap<(String, String), LocalWelcome>,
    #[serde(with = "any_key_map")]
    pub community_general_channel_names: BTreeMap<String, String>,
    #[serde(with = "any_key_map")]
    pub community_group_pending_actions: BTreeMap<String, BTreeMap<String, Option<ActionMsg>>>,
    /// Dev only. Skip updating msg history. Shall be reset to false at start every time.
    pub skip_updating_msg_history: bool,
}

// Workaround for confy's [Default] requirement on structure
impl Default for ClientData {
    fn default() -> Self {
        panic!("Unable to load [confy]: ClientData's [default()] is called.")
    }
}

pub trait FullAccessClientData {
    fn get_group_state(&self, comm_grp: &CommGroupId) -> &LocalGroupState;

    fn get_mut_group_state(&mut self, comm_grp: &CommGroupId) -> &mut LocalGroupState;
}

impl FullAccessClientData for ClientData {
    /// Returns an immutable borrow of the local group state
    fn get_group_state(&self, comm_grp: &CommGroupId) -> &LocalGroupState {
        self.community_states
            .get(&*comm_grp.community_id())
            .expect("Community not found")
            .group_states
            .get(&*comm_grp.group_id())
            .expect("Group not found")
    }

    /// Returns a mutable borrow of the local group state
    fn get_mut_group_state(&mut self, comm_grp: &CommGroupId) -> &mut LocalGroupState {
        self.community_states
            .get_mut(&*comm_grp.community_id())
            .unwrap_or_else(|| panic!("Community {} not found", comm_grp.community_id()))
            .group_states
            .get_mut(&*comm_grp.group_id())
            .expect("Group not found")
    }
}

impl ClientDataProvider for ClientData {
    fn store_group(
        &mut self,
        comm_grp: &CommGroupId,
        gov_state_init_hash: Option<u64>,
        mls_group: MlsGroup,
    ) {
        // Initialize the group members referenced by the `mls_group`
        let new_group_state = LocalGroupState::new(mls_group, gov_state_init_hash, &self.policies);
        self.community_states
            .entry(comm_grp.community_id())
            .or_insert_with(LocalCommunityState::default)
            .group_states
            .insert(comm_grp.group_id(), new_group_state);
        self.community_group_pending_actions
            .entry(comm_grp.community_id())
            .or_insert_with(BTreeMap::default)
            .insert(comm_grp.group_id(), None);
    }

    fn remove_group(&mut self, comm_grp: &CommGroupId) {
        if let Some(community) = self.community_states.get_mut(&*comm_grp.community_id()) {
            community.group_states.remove(&*comm_grp.group_id());
        }
    }

    fn load_shared_state(&mut self, comm_grp: &CommGroupId, shared_state: SharedGroupState) {
        self.community_states
            .get_mut(&*comm_grp.community_id())
            .unwrap()
            .group_states
            .get_mut(&*comm_grp.group_id())
            .unwrap()
            .shared = shared_state;
    }

    fn get_shared_state(&self, comm_grp: &CommGroupId) -> &SharedGroupState {
        &self.get_group_state(comm_grp).shared
    }

    fn get_ref_group(&mut self, comm_grp: &CommGroupId) -> Option<&mut RefCell<MlsGroup>> {
        if let Some(community) = self.community_states.get_mut(&comm_grp.community_id()) {
            if let Some(group) = community.group_states.get_mut(&comm_grp.group_id()) {
                return Some(&mut group.mls_state);
            }
        }
        None
    }

    fn store_welcome(&mut self, comm_grp: &CommGroupId, welcome: Welcome) {
        let community_name = comm_grp.community_id();
        let group_name = comm_grp.community_id();
        if let Entry::Vacant(e) = self
            .community_general_channel_names
            .entry(community_name.to_owned())
        {
            e.insert(group_name.to_owned());
        }; // TODO: Need to handle else case of store_welcome function? #79
        self.pending_welcomes
            .insert((community_name, group_name), LocalWelcome { welcome });
    }

    fn contains_welcome(&self, comm_grp: &CommGroupId) -> bool {
        let community_name = comm_grp.community_id();
        let group_name = comm_grp.community_id();
        self.pending_welcomes
            .contains_key(&(community_name, group_name))
    }

    fn get_welcome_clone(&self, comm_grp: &CommGroupId) -> Option<Welcome> {
        let community_name = comm_grp.community_id();
        let group_name = comm_grp.community_id();
        self.pending_welcomes
            .get(&(community_name, group_name))
            .map(|local_welcome| local_welcome.welcome.clone())
    }

    fn remove_welcome(&mut self, comm_grp: &CommGroupId) -> Option<Welcome> {
        let community_name = comm_grp.community_id();
        let group_name = comm_grp.community_id();
        if let Some(local_welcome) = self.pending_welcomes.remove(&(community_name, group_name)) {
            Some(local_welcome.welcome)
        } else {
            None
        }
    }

    fn get_user_id(&self) -> String {
        self.user_name.to_owned()
    }

    fn get_credential(&self) -> Credential {
        self.credential.clone()
    }

    fn update_governance_state(&mut self, comm_grp: &CommGroupId, key: String, value: String) {
        let local_group_state = self.get_mut_group_state(comm_grp);
        local_group_state.shared.governance_state.insert(key, value);
    }

    fn store_to_add_invitee_key_pack(&mut self, comm_grp: &CommGroupId, key_package: KeyPackage) {
        let local_group_state = self.get_mut_group_state(comm_grp);

        local_group_state.shared.to_add_invitees.insert(
            identity_to_str(key_package.credential().identity())
                .unwrap_or_else(|| String::from("Unnamed")),
            key_package,
        );
    }

    fn pop_to_add_invitee_key_pack(
        &mut self,
        comm_grp: &CommGroupId,
        invitee_name: &str,
    ) -> Option<KeyPackage> {
        let local_group_state = self.get_mut_group_state(comm_grp);

        local_group_state
            .shared
            .to_add_invitees
            .remove(invitee_name)
    }

    fn store_to_be_removed_member(&mut self, comm_grp: &CommGroupId, member: &String) {
        let local_group_state = self.get_mut_group_state(comm_grp);
        local_group_state
            .shared
            .to_be_removed_members
            .push(member.to_string());
    }

    fn pop_to_be_removed_member(&mut self, comm_grp: &CommGroupId, member: &String) -> bool {
        let local_group_state = self.get_mut_group_state(comm_grp);
        match local_group_state
            .shared
            .to_be_removed_members
            .iter()
            .position(|r| r == member)
        {
            None => false,
            Some(i) => {
                local_group_state.shared.to_be_removed_members.remove(i);
                true
            }
        }
    }

    fn store_self_sent_msg(
        &mut self,
        comm_grp: &CommGroupId,
        private_msg: &UnorderedPrivateMessage,
    ) {
        let sender = &self.user_name.clone();
        self.store_received_msg_w_counter(comm_grp, sender, private_msg, false)
    }

    fn store_pending_action(&mut self, comm_grp: &CommGroupId, action: ActionMsg) {
        let value = self
            .community_group_pending_actions
            .get_mut(&*comm_grp.community_id())
            .expect("Community name does not exist")
            .get_mut(&*comm_grp.group_id())
            .expect("Group name does not exist");
        // Make sure that we don't already have a pending action
        assert!(value.is_none());
        *value = Some(action);
    }

    fn pop_pending_action(&mut self, comm_grp: &CommGroupId) -> Option<ActionMsg> {
        let result = self
            .community_group_pending_actions
            .get_mut(&*comm_grp.community_id())
            .expect("Community name does not exist")
            .remove(&*comm_grp.group_id())
            .expect("Group name does not exist");
        // Replace the removed value with None
        self.community_group_pending_actions
            .get_mut(&*comm_grp.community_id())
            .unwrap()
            .insert(comm_grp.group_id(), None);
        result
    }

    fn store_received_msg(
        &mut self,
        comm_grp: &CommGroupId,
        sender: &str,
        private_msg: &UnorderedPrivateMessage,
    ) {
        self.store_received_msg_w_counter(comm_grp, sender, private_msg, true)
    }

    fn set_group_name(&mut self, comm_grp: &CommGroupId, new_name: String) {
        let local_group_state = self.get_mut_group_state(comm_grp);
        local_group_state.shared.name = new_name;
    }

    fn get_group_name(&self, comm_grp: &CommGroupId) -> &str {
        let local_group_state = self.get_group_state(comm_grp);
        &local_group_state.shared.name
    }

    fn set_group_topic(&mut self, comm_grp: &CommGroupId, new_topic: String) {
        let local_group_state = self.get_mut_group_state(comm_grp);
        local_group_state.shared.topic = new_topic;
    }

    fn get_group_topic(&self, comm_grp: &CommGroupId) -> &str {
        let local_group_state = self.get_group_state(comm_grp);
        &local_group_state.shared.topic
    }

    fn def_role(
        &mut self,
        comm_grp: &CommGroupId,
        role_name: String,
        action_types: Vec<ActionType>,
    ) {
        let local_group_state = self.get_mut_group_state(comm_grp);
        local_group_state
            .shared
            .rbac
            .def_role(role_name, action_types);
    }

    fn set_user_role(&mut self, comm_grp: &CommGroupId, user_id: String, role_name: String) {
        let local_group_state = self.get_mut_group_state(comm_grp);
        local_group_state
            .shared
            .rbac
            .set_user_role(user_id, role_name);
    }

    fn action_authorized(&mut self, action: &ActionMsg) -> bool {
        let metadata = action.get_metadata();
        let community_id = metadata.community_group_id.community_id();
        let group_id = metadata.community_group_id.group_id();
        let local_group_state = self
            .community_states
            .get_mut(&community_id)
            .expect("Communty not found")
            .group_states
            .get_mut(&group_id)
            .expect("Group not found");
        let sender = metadata.sender;
        local_group_state
            .shared
            .rbac
            .action_authorized(&sender, action)
    }

    fn get_roles(&self, comm_grp: &CommGroupId) -> RbacState {
        let local_group_state = self.get_group_state(comm_grp);
        local_group_state.shared.rbac.clone()
    }

    fn get_group_members(&self, comm_grp: &CommGroupId) -> Vec<String> {
        let local_group_state = self.get_group_state(comm_grp);
        user_names_from_mls_group(&local_group_state.mls_state.borrow())
    }

    fn get_keypair(&self) -> &Keypair {
        &self.verif_keypair
    }

    fn get_user_verify_key(&self, user_name: &str) -> Option<PublicKey> {
        self.credential_entries
            .get(user_name)
            .map(|entry| entry.verification_key)
    }

    fn set_credential_entries(&mut self, credentials: BTreeMap<String, CredentialEntry>) {
        self.credential_entries = credentials;
    }

    fn to_string(&self) -> String {
        serde_json::to_string(&self).expect("Could not serialize")
    }

    fn set_client_policies(&mut self, policies: Vec<Box<dyn Policy>>) {
        self.policies = policies;
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    /// Store but not process a mls message message
    fn store_unprocessed_msg(&mut self, comm_grp: &CommGroupId, msg: OnWireMessage) {
        let local_group_state = self.get_mut_group_state(comm_grp);
        local_group_state.unprocessed_messages.push(msg);
    }

    /// Store but not process a mls message message
    fn pop_unprocessed_msgs(&mut self, comm_grp: &CommGroupId) -> Vec<OnWireMessage> {
        let local_group_state = self.get_mut_group_state(comm_grp);
        // let mut result = vec![];
        // while !local_group_state.unprocessed_messages.is_empty() {
        //     result.push(local_group_state.unprocessed_messages.pop().unwrap());
        // }
        // result
        std::mem::take(&mut local_group_state.unprocessed_messages)
    }

    fn get_shared_gov_state_init_hash(&self, comm_grp: &CommGroupId) -> Option<u64> {
        let community_id = &comm_grp.community_id();
        let group_id = &comm_grp.group_id();
        // Might be called on non-existed group
        if let Some(community) = self.community_states.get(community_id) {
            if let Some(group) = community.group_states.get(group_id) {
                return group.gov_state_init_hash;
            }
        }
        None
    }

    fn set_shared_gov_state_init_hash(&mut self, comm_grp: &CommGroupId, init_hash: Option<u64>) {
        let local_group_state = self.get_mut_group_state(comm_grp);
        local_group_state.gov_state_init_hash = init_hash;
    }

    fn store_proposed_action(&mut self, comm_grp: &CommGroupId, action: VerifiableAction) {
        let local_group_state = self.get_mut_group_state(comm_grp);
        local_group_state.proposed_actions.push(action);
    }

    fn get_proposed_actions(&mut self, comm_grp: &CommGroupId) -> Vec<VerifiableAction> {
        let local_group_state = self.get_mut_group_state(comm_grp);
        local_group_state.proposed_actions.clone()
    }

    fn remove_proposed_actions(
        &mut self,
        comm_grp: &CommGroupId,
        committed_actions: &Vec<VerifiableAction>,
    ) {
        let local_group_state = self.get_mut_group_state(comm_grp);
        local_group_state
            .proposed_actions
            .retain(|action| !committed_actions.contains(action))
    }

    fn clear_proposed_actions(&mut self, comm_grp: &CommGroupId) {
        let local_group_state = self.get_mut_group_state(comm_grp);
        local_group_state.proposed_actions.clear()
    }

    fn remove_history_message_with_id(&mut self, comm_grp: &CommGroupId, to_remove_id: String) {
        let state = self.get_mut_group_state(comm_grp);
        // Remove the referenced message the local group history
        state
            .history
            .retain(|local_message| match &local_message.message.content {
                UnorderedMsgContent::TextAction { text_action } => {
                    let metadata = text_action.action.get_metadata();
                    metadata.action_id != to_remove_id
                }
                _ => true,
            });
    }

    fn get_policy_engine_ref_clone(&self, comm_grp: &CommGroupId) -> Rc<RefCell<PolicyEngine>> {
        return self.get_group_state(comm_grp).shared.policy_engine.clone();
    }
}

// pub trait PolicyClient {
//     fn evaluate_action(&mut self,comm_grp: &CommGroupId, action: ActionMsg);
// }

// impl PolicyClient for Box<dyn ClientDataProvider> {
//     fn evaluate_action(&mut self,comm_grp: &CommGroupId, action: ActionMsg) {
//         self.get_mut_group_state(comm_grp)
//             .shared
//             .policy_engine
//             .evaluate_action(action, self);
//     }
// }

impl ClientData {
    pub fn store_received_msg_w_counter(
        &mut self,
        comm_grp: &CommGroupId,
        sender: &str,
        private_msg: &UnorderedPrivateMessage,
        increase_counter: bool,
    ) {
        // Dev/benchmarking purpose only
        if self.skip_updating_msg_history {
            return;
        }
        let local_group_state = self
            .community_states
            .get_mut(&*comm_grp.community_id())
            .unwrap()
            .group_states
            .get_mut(&*comm_grp.group_id())
            .unwrap();
        local_group_state.history.insert(
            0,
            LocalHistoryMessage::new_and_timestamp(private_msg, &sender.to_string()),
        );
        if increase_counter {
            local_group_state.unread_msgs_count += 1;
        }
    }

    pub fn new(name: String, credential: Credential, verif_keypair: Keypair) -> Self {
        assert_eq!(name, identity_to_str(credential.identity()).unwrap());
        ClientData {
            user_name: name,
            credential,
            verif_keypair,
            credential_entries: BTreeMap::new(),
            community_states: BTreeMap::new(),
            pending_welcomes: BTreeMap::new(),
            community_general_channel_names: BTreeMap::new(),
            community_group_pending_actions: BTreeMap::new(),
            policies: Vec::new(),
            skip_updating_msg_history: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct LocalCommunityState {
    #[serde(with = "any_key_map")]
    group_states: BTreeMap<String, LocalGroupState>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocalGroupState {
    #[serde(deserialize_with = "mls_group_deserialize")]
    #[serde(serialize_with = "mls_group_serialize")]
    pub mls_state: RefCell<MlsGroup>,
    /// Group state that is shared by all members of the group
    pub shared: SharedGroupState,

    /// Oldest message first for performance reasons
    pub history: Vec<LocalHistoryMessage>,

    /// How many message the user has not `Read`, excluding self messages
    pub unread_msgs_count: u64,

    /// A local container to store (unprocessed) messages.
    /// Should be always empty and not used when `gov_state_initialized`==`True`
    pub unprocessed_messages: Vec<OnWireMessage>,

    /// Uncommitted proposed actions
    pub proposed_actions: Vec<VerifiableAction>,

    /// Initial hash of the governance state received. 0 if user is the creator of the group.
    pub gov_state_init_hash: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocalHistoryMessage {
    pub message: UnorderedPrivateMessage,
    pub sender: String,
    pub received_timestamp: SystemTime,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LocalWelcome {
    #[serde(serialize_with = "welcome_serialize")]
    #[serde(deserialize_with = "welcome_deserialize")]
    pub welcome: Welcome,
}

impl LocalHistoryMessage {
    pub fn new_and_timestamp(message: &UnorderedPrivateMessage, sender: &String) -> Self {
        Self {
            message: message.to_owned(),
            sender: sender.to_owned(),
            received_timestamp: SystemTime::now(),
        }
    }
}

impl LocalGroupState {
    pub fn new(
        mls_group: MlsGroup,
        gov_state_init_hash: Option<u64>,
        policies: &[Box<dyn Policy>],
    ) -> Self {
        // Clone policies and wrap in Rc<RefCell<...>>
        let policy_refs = policies
            .iter()
            .map(|policy| Rc::new(RefCell::new(policy.get_policy_obj())))
            .collect();
        Self {
            mls_state: RefCell::new(mls_group),
            shared: SharedGroupState {
                name: "".to_string(),
                topic: "".to_string(),
                rbac: RbacState::new(),
                governance_state: BTreeMap::new(),
                to_add_invitees: BTreeMap::new(),
                policy_engine: Rc::new(RefCell::new(PolicyEngine::new(policy_refs))),
                to_be_removed_members: vec![],
            },
            history: vec![],
            unprocessed_messages: vec![],
            unread_msgs_count: 0,
            proposed_actions: vec![],
            gov_state_init_hash,
        }
    }
}
