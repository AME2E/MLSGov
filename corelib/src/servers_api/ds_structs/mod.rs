use std::collections::HashSet;
use std::ops::{Deref, DerefMut};

use dashmap::DashMap;
use openmls::key_packages::KeyPackage;
use uuid::Uuid;

use local_message_struct::{Invite, ProtectedMessageWithMetaData};

use crate::messages::GroupMessage;
use crate::{identity_to_str, CommGroupId};

pub(crate) mod local_message_struct;

pub type MessageID = String;

#[derive(Default, Debug, serde_derive::Serialize, serde_derive::Deserialize, Clone)]
pub struct DeliveryServiceState {
    /// Maps from User IDs to their unretrieved messages IDs
    pub unordered_message_indvl_queues: DashMap<String, Vec<MessageID>>,

    // Maps from User IDs to group IDs from which they received messages*
    // *technically messages are not sent from groups
    pub indvl_groups: DashMap<String, Vec<CommGroupId>>,

    // Maps from GroupID to known recipients and (existing) ordered message IDs.
    pub groups_to_ordered_messages: DashMap<CommGroupId, (HashSet<String>, Vec<MessageID>)>,

    /// Maps from User IDs to their unretrieved messages
    pub invite_indvl_queues: DashMap<String, Vec<Invite>>,

    /// Maps from user ID to their initial key packages at sign-up
    pub user_key_packages: DashMap<String, Vec<KeyPackage>>,

    /// Maps from message IDs to (unretrieved recipients, message).
    /// an empty recipient list means the message can be and will be deleted from DS.
    pub message_id_to_message: DashMap<MessageID, (HashSet<String>, ProtectedMessageWithMetaData)>,
}

#[derive(Default, Debug, Clone)]
pub struct DeliveryServiceParam {
    /// Repeatable flag to turn verbose output on (Max: 2)
    pub verbose: u8,
    /// Whether to store persistent state
    pub persistent_state: bool,
}

pub type SharedDeliverServiceState = DeliveryServiceState;

impl DeliveryServiceState {
    pub fn new() -> DeliveryServiceState {
        DeliveryServiceState {
            unordered_message_indvl_queues: DashMap::new(),
            indvl_groups: DashMap::new(),
            groups_to_ordered_messages: DashMap::new(),
            invite_indvl_queues: DashMap::new(),
            user_key_packages: DashMap::new(),
            message_id_to_message: DashMap::new(),
        }
    }

    /// Places the message `msg_w_meta` in the receiving inbox
    /// queues for all members in `recipients`.
    pub fn delivery_to_recipients(
        &self,
        recipients: &Vec<String>,
        mut msg_w_meta: ProtectedMessageWithMetaData,
    ) {
        if recipients.is_empty() {
            return;
        }
        let msg_com_grp = msg_w_meta.community_group_id.to_owned();

        // Generate a message id and store the message
        let mut message_id = Uuid::new_v4().to_string();
        while self.message_id_to_message.get(&message_id).is_some() {
            message_id = Uuid::new_v4().to_string()
        }

        if msg_w_meta.ordered {
            let community_group_id = msg_com_grp.clone();
            let default_values = (HashSet::new(), Vec::new());

            let mut group_messages_entry = self
                .groups_to_ordered_messages
                .entry(community_group_id)
                .or_insert(default_values);

            let (known_recipients, group_messages) = group_messages_entry.deref_mut();

            for recipient in recipients {
                if !known_recipients.contains(recipient) {
                    self.indvl_groups
                        .entry(recipient.to_owned())
                        .or_insert(Vec::new())
                        .push(msg_com_grp.clone());
                    known_recipients.insert(recipient.to_owned());
                }
            }
            msg_w_meta.update_timestamp(); // Ensure "group lock" obtained before finalizing timestamp
            self.message_id_to_message.insert(
                message_id.clone(),
                (HashSet::from_iter(recipients.iter().cloned()), msg_w_meta),
            );
            group_messages.push(message_id);
        } else {
            self.message_id_to_message.insert(
                message_id.clone(),
                (HashSet::from_iter(recipients.iter().cloned()), msg_w_meta),
            );
            for recipient in recipients {
                self.unordered_message_indvl_queues
                    .entry(recipient.to_string())
                    .or_insert(Vec::new())
                    .push(message_id.clone());
            }
        }
    }

    pub fn pop_all_ordered_msg(
        &self,
        user: &String,
        comm_group_id: &CommGroupId,
    ) -> Vec<GroupMessage> {
        self.pop_all_ordered_msg_w_meta(user, comm_group_id)
            .into_iter()
            .map(|msg_w_meta| msg_w_meta.protected_msg)
            .collect()
    }

    pub fn pop_all_ordered_msg_w_meta(
        &self,
        user: &String,
        comm_group_id: &CommGroupId,
    ) -> Vec<ProtectedMessageWithMetaData> {
        if let Some(mut ref_mut) = self.groups_to_ordered_messages.get_mut(comm_group_id) {
            let (known_user, msg_ids) = ref_mut.deref_mut();
            if known_user.contains(user) {
                known_user.remove(user);
                return msg_ids
                    .iter()
                    .filter_map(|msg_id| self.pop_message_by_id(msg_id, user))
                    .collect();
            }
        }
        Vec::new()
    }

    pub fn pop_message_by_id(
        &self,
        message_id: &String,
        user: &String,
    ) -> Option<ProtectedMessageWithMetaData> {
        let mut is_intended_recipient = false;
        let mut remove_msg = false;

        // Read only Lock for efficient lookup
        if let Some(entry_ref) = self.message_id_to_message.get(message_id) {
            let (unretrieved_recipients, _) = entry_ref.deref();
            is_intended_recipient = unretrieved_recipients.contains(user);
        };
        if !is_intended_recipient {
            return None;
        }

        // Write Lock
        let result = self
            .message_id_to_message
            .get_mut(message_id)
            .map(|mut entry_ref| {
                let (unretrieved_recipients, msg) = entry_ref.deref_mut();
                unretrieved_recipients.remove(user);
                remove_msg = unretrieved_recipients.is_empty();
                msg.clone()
            });

        if remove_msg {
            self.message_id_to_message.remove(message_id);
        };

        result
    }

    pub fn add_key_packages(
        &self,
        mut new_key_packages: Vec<KeyPackage>,
        max_packages: usize,
    ) -> bool {
        assert!(max_packages >= 1);
        if new_key_packages.is_empty() {
            return true;
        }
        if let Some(name) = identity_to_str(new_key_packages[0].credential().identity()) {
            let mut entry = self.user_key_packages.entry(name).or_insert_with(Vec::new);
            entry.append(&mut new_key_packages);
            entry.truncate(max_packages);
            true
        } else {
            false
        }
    }
}
