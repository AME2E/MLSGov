use std::time::SystemTime;

use openmls::messages::Welcome;

use crate::messages::GroupMessage;
use crate::CommGroupId;

#[derive(Debug, serde_derive::Serialize, serde_derive::Deserialize, PartialEq, Clone)]
/// Delivery Service API's data structure to store a [ProtectedMessage]
/// for future relaying
pub struct ProtectedMessageWithMetaData {
    pub protected_msg: GroupMessage,
    pub ordered: bool,
    pub community_group_id: CommGroupId,
    /// For ordered messages, server timestamp must be in the same order with group messages.
    pub server_timestamp: SystemTime,
}

#[derive(Debug, serde_derive::Serialize, serde_derive::Deserialize, Clone)]
pub struct Invite {
    #[serde(serialize_with = "crate::messages::welcome_serialize")]
    #[serde(deserialize_with = "crate::messages::welcome_deserialize")]
    pub welcome_obj: Welcome,
    pub invitee: String,
    pub inviter: String,
    pub comm_grp: CommGroupId,
}

impl ProtectedMessageWithMetaData {
    pub fn new(protected_msg: GroupMessage, ordered: bool, server_timestamp: SystemTime) -> Self {
        let community_group_id = protected_msg.get_group_id();
        ProtectedMessageWithMetaData {
            protected_msg,
            community_group_id,
            ordered,
            server_timestamp,
        }
    }

    pub fn is_ordered(&self) -> bool {
        self.ordered
    }

    pub fn update_timestamp(&mut self) {
        self.server_timestamp = SystemTime::now();
    }
}

impl From<ProtectedMessageWithMetaData> for GroupMessage {
    fn from(protected_msg: ProtectedMessageWithMetaData) -> Self {
        protected_msg.protected_msg
    }
}
