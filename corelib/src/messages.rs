use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};
use std::{fmt, u8};

use ed25519_dalek::PublicKey;
use log::*;
use openmls::credentials::Credential;
use openmls::framing::MlsMessageOut;
use openmls::key_packages::KeyPackage;
use openmls::messages::Welcome;
use serde;
use tls_codec::Serialize;
use tls_codec::{self, Deserialize};

use crate::client_api::actions::{ActionMsg, VerifiableAction};
use crate::servers_api::as_struct::CredentialEntry;
use crate::{BytesVisitor, CommGroupId};

/// One Vec of Bytes in an Ordered Message commit
/// (`StagedCommitMessage`'s commit's `ord_app_msg_proposals()`)
/// should be serialized to
pub type OrderedPreSerializationType = OrderedPrivateMessage;

/// Bytes of an unordered Application message
/// (msg of An `ProcessedMessage::ApplicationMessage(msg)`)
/// should be serialized to
pub type UnorderedPreSerializationType = UnorderedPrivateMessage;

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
/// A version-controlled, all-encompassing message structure used for information exchange
/// between clients and the platform (authentic services, delivery services, etc.)
pub struct OnWireMessageWithMetaData {
    pub onwire_msg: OnWireMessage,
    pub sender_timestamp: SystemTime,
    pub version: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Clone)]
/// A specialized message structure used represent specific commands
/// between clients and the platform (authentic services, delivery services, etc.)
pub enum OnWireMessage {
    /// A register request from client
    UserKeyPackagesForDS {
        key_packages: Vec<KeyPackage>,
    },
    UserRegisterForAS {
        credential: Credential,
        verification_key: PublicKey,
    },
    UserCredentialLookup {
        user_name: String,
        queried_users: Vec<String>,
    },
    UserSyncCredentials,
    UserKeyPackageLookup {
        user_name: String,
        queried_users: Vec<String>,
    },
    // /// A create group request from client
    // UserCreate {
    //     user_name: String,
    //     community_name: String,
    //     group_name: String,
    //     epoch_num: u64,
    // },
    /// A sync request from client
    UserSync {
        user_name: String,
        new_key_packages: Vec<KeyPackage>,
    },
    /// A invite new group member request from client
    UserInvite {
        user_name: String,
        invitee_names: Vec<String>,
        comm_grp: CommGroupId,
        #[serde(serialize_with = "welcome_serialize")]
        #[serde(deserialize_with = "welcome_deserialize")]
        welcome: Welcome,
    },
    /// A send message request from client
    UserStandardSend {
        recipients: Vec<String>,
        identifier: Option<String>,
        user_msg: GroupMessage,
    },
    UserReliableSend {
        user_name: String,
        recipients: Vec<String>,
        user_msg: GroupMessage,
    },

    /// A result message from delivery service,
    /// indicating whether the request was valid
    /// identifier is Some when a group's pending commits should be merged
    DSResult {
        request_valid: bool,
        explanation: Option<String>,
        // Echo back the identifier.
        // Client-defined. Helpful for clients to locate group to merge commits/execute actions
        identifier: Option<String>,
        /// When request was an Ordered Message, the reply includes all sender's unseen ordered msg
        /// to help enforce ordering
        preceding_and_sent_ordered_msgs: Vec<GroupMessage>,
        process_time_used: Duration,
    },
    /// A relayed (single) user (group) non-membership-related
    /// message from delivery service
    DSRelayedUserMsg {
        user_msg: GroupMessage,
        server_timestamp: SystemTime,
    },
    /// A relayed (single) user (group) non-membership-related
    /// message from delivery service
    DSRelayedUserWelcome {
        comm_grp: CommGroupId,
        sender: String,

        #[serde(serialize_with = "welcome_serialize")]
        #[serde(deserialize_with = "welcome_deserialize")]
        welcome: Welcome,
    },
    /// A result message from authentication service,
    /// indicating whether the request was valid
    ASResult {
        request_valid: bool,
        explanation: Option<String>,
        process_time_used: Duration,
    },
    /// A response with queried Credential from authentication service
    ASCredentialResponse {
        queried_user_credentials: Vec<Credential>,
    },
    ASCredentialSyncResponse {
        credentials: BTreeMap<String, CredentialEntry>,
    },
    DSKeyPackageResponse {
        queried_user_key_packages: Vec<KeyPackage>,
    },
}

#[derive(Debug, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub enum GroupMessage {
    AppMlsMessage {
        comm_grp: CommGroupId,
        sender: Option<String>,
        #[serde(serialize_with = "mls_msg_serialize")]
        #[serde(deserialize_with = "mls_msg_deserialize")]
        mls_msg: MlsMessageOut,
    },
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
/// A message structure whose content is private and unordered within a group.
pub struct UnorderedPrivateMessage {
    pub content: UnorderedMsgContent,
    pub sender_timestamp: SystemTime,
    pub sender: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
/// A basic message structure to represent a user-generated, group-unrelated message
pub enum UnorderedMsgContent {
    /// Raw text
    Text { text_content: String },
    /// A text message
    TextAction { text_action: VerifiableAction },
    /// A group state udpate
    GroupState { shared: VerifiableAction },
    /// An action without any signature
    UnsignedAction { action: ActionMsg },
    /// A ProposedAction contains an action that has yet to be committed
    ProposedAction { proposed_action: VerifiableAction },
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]

pub struct OrderedPrivateMessage {
    pub content: OrderedMsgContent,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub enum OrderedMsgContent {
    Action(VerifiableAction),
    ActionVec(Vec<VerifiableAction>),
}

impl OnWireMessage {
    pub fn is_user_msg(&self) -> bool {
        match self {
            OnWireMessage::UserKeyPackagesForDS { .. }
            | OnWireMessage::UserRegisterForAS { .. }
            | OnWireMessage::UserCredentialLookup { .. }
            | OnWireMessage::UserKeyPackageLookup { .. }
            | OnWireMessage::UserSyncCredentials { .. }
            | OnWireMessage::UserSync { .. }
            | OnWireMessage::UserInvite { .. }
            | OnWireMessage::UserReliableSend { .. }
            | OnWireMessage::UserStandardSend { .. } => true,

            OnWireMessage::DSResult { .. }
            | OnWireMessage::DSRelayedUserMsg { .. }
            | OnWireMessage::DSKeyPackageResponse { .. }
            | OnWireMessage::DSRelayedUserWelcome { .. }
            | OnWireMessage::ASResult { .. }
            | OnWireMessage::ASCredentialSyncResponse { .. }
            | OnWireMessage::ASCredentialResponse { .. } => false,
        }
    }

    pub fn to_vec(self) -> Vec<Self> {
        vec![self]
    }
}

impl GroupMessage {
    pub fn from_mls(msg: MlsMessageOut, comm_grp: CommGroupId, sender: Option<String>) -> Self {
        debug!(
            "{:?} Generated MlsMessage with Epoch {:?}",
            sender,
            msg.epoch()
        );
        Self::AppMlsMessage {
            comm_grp,
            mls_msg: msg,
            sender,
        }
    }

    pub fn get_group_id(&self) -> CommGroupId {
        match self {
            GroupMessage::AppMlsMessage { comm_grp, .. } => comm_grp.clone(),
        }
    }
}

/// Custom serialization for [MlsMessageOut], to be used with `serde_with`
pub fn mls_msg_serialize<S>(x: &MlsMessageOut, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let encoded = x.tls_serialize_detached().unwrap();
    s.serialize_bytes(&encoded)
}

/// Custom deserialization for [MlsMessageOut], to be used with `serde_with`
pub fn mls_msg_deserialize<'a, D>(deserializer: D) -> Result<MlsMessageOut, D::Error>
where
    D: serde::Deserializer<'a>,
{
    let v = deserializer
        .deserialize_byte_buf(BytesVisitor)
        .expect("Cannot get byte buf");
    let decoded: MlsMessageOut = MlsMessageOut::tls_deserialize(&mut &*v).unwrap();
    Ok(decoded)
}

/// Custom serialization for [Welcome], to be used with `serde_with`
pub fn welcome_serialize<S>(x: &Welcome, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let encoded = x.tls_serialize_detached().unwrap();
    s.serialize_bytes(&encoded)
}

/// Custom deserialization for [Welcome], to be used with `serde_with`
pub fn welcome_deserialize<'a, D>(deserializer: D) -> Result<Welcome, D::Error>
where
    D: serde::Deserializer<'a>,
{
    let v = deserializer
        .deserialize_byte_buf(BytesVisitor)
        .expect("Cannot get byte buf");
    let mut s = &*v;
    let decoded: Welcome = Welcome::tls_deserialize(&mut s).unwrap();
    Ok(decoded)
}

impl UnorderedPrivateMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        unordered_serialize(self)
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        unordered_deserialize(b)
    }
}

pub fn ordered_serialize(msg: &OrderedPreSerializationType) -> Vec<u8> {
    encode_to_bytes(msg)
}

pub fn ordered_deserialize(bytes: &[u8]) -> Option<OrderedPreSerializationType> {
    decode_from_bytes(bytes)
}

pub fn unordered_serialize(msg: &UnorderedPreSerializationType) -> Vec<u8> {
    encode_to_bytes(msg)
}

pub fn unordered_deserialize(bytes: &[u8]) -> Option<UnorderedPreSerializationType> {
    decode_from_bytes(bytes)
}

pub(crate) fn encode_to_bytes<T: serde::Serialize>(obj: &T) -> Vec<u8> {
    serde_json::to_vec(obj).expect("Cannot encode")
}

pub(crate) fn decode_from_bytes<'de, T>(b: &'de [u8]) -> Option<T>
where
    T: serde::Deserialize<'de>,
{
    match serde_json::from_slice(b) {
        Ok(pm) => Some(pm),
        Err(e) => {
            error!("Error: {:?}", e);
            None
        }
    }
}

#[derive(Debug)]
pub enum UserRequestErrors {
    UnknownUser,
    NoSuchCommunity,
    NoSuchGroup,
    NoSuchQueriedUser,
    NoSuchInvitation,
    NoAvailableUserKeyPackage,
    NotInOrganisation,
    NoRelatedPermission,
    RoleAlreadySetOrIsHigher,
    IdentityAlreadyExist,
    GroupAlreadyExist,
    CannotKickYourself,
    CannotReinvite,
    CannotDecodeIdentity,
    IncompatibleEpochNumber,
}

impl fmt::Display for UserRequestErrors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            UserRequestErrors::UnknownUser => {
                write!(
                    f,
                    "Unknown user. Did you register (with DS via KeyPackage)?"
                )
            }
            UserRequestErrors::NoSuchGroup => {
                write!(f, "Cannot find this group in the community.")
            }
            UserRequestErrors::NoSuchQueriedUser => {
                write!(f, "No such queried user.")
            }
            UserRequestErrors::NoSuchInvitation => {
                write!(f, "User invitation not found on the server.")
            }
            UserRequestErrors::NoAvailableUserKeyPackage => {
                write!(f, "All key package from the queried user has been consumed. They need to sync with server.")
            }
            UserRequestErrors::NotInOrganisation => {
                write!(f, "Not authorized. You are not a member.")
            }
            UserRequestErrors::CannotReinvite => {
                write!(
                    f,
                    "Cannot add invitee to the group because they are already invited/a member"
                )
            }
            UserRequestErrors::IncompatibleEpochNumber => {
                write!(
                    f,
                    "Cannot record your request: wrong epoch number. Sync and try again"
                )
            }
            UserRequestErrors::RoleAlreadySetOrIsHigher => {
                write!(
                    f,
                    "The member has equal or higher role than the role you are trying to set for them"
                )
            }
            UserRequestErrors::CannotKickYourself => {
                write!(f, "Do not use Kick to remove yourself. Instead use Leave!")
            }
            _ => write!(f, "{:?}", self),
        }
    }
}
