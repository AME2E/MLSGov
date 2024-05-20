extern crate core;

use std::fmt;
use std::str::from_utf8;
use std::time::Duration;

use ed25519_dalek::Keypair;
use log::debug;
use openmls::key_packages::KeyPackage;
use openmls::prelude::KeyPackageRef;
use openmls_traits::OpenMlsCryptoProvider;
use rand_07::rngs::OsRng;
use serde::de::Visitor;
use serde::{Deserialize, Serialize};

use crate::client_api::client_crypto_impl::CryptoBackend;

pub mod client_api;
mod integrated_tests;
pub mod messages;
pub mod policyengine;
pub mod servers_api;
pub mod test_helpers;

pub struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a byte buf or some seq")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut v = vec![];

        while let Some(b) = seq.next_element()? {
            v.push(b);
        }
        Ok(v)
    }
}

pub fn identity_to_str(identity: &[u8]) -> Option<String> {
    match from_utf8(identity) {
        Ok(name) => Some(name.to_string()),
        Err(e) => {
            log::error!("Unable to decode name. {:?}", e);
            None
        }
    }
}

pub fn str_to_identity(name: &String) -> Vec<u8> {
    name.to_owned().into_bytes()
}

fn get_member_hash_ref(
    group_members: Vec<&KeyPackage>,
    target_id: &[u8],
    backend: &CryptoBackend,
) -> KeyPackageRef {
    group_members
        .into_iter()
        .find_map(|member_key_package| {
            if member_key_package.credential().identity() == target_id {
                Some(
                    member_key_package
                        .hash_ref(backend.crypto())
                        .expect("Cannot get hash ref"),
                )
            } else {
                None
            }
        })
        .unwrap()
}

fn get_key_package_ref_identity(
    group_members: Vec<&KeyPackage>,
    target_ref: &KeyPackageRef,
    backend: &CryptoBackend,
) -> Option<String> {
    group_members.into_iter().find_map(|member_key_package| {
        if &member_key_package
            .hash_ref(backend.crypto())
            .expect("Cannot hash")
            == target_ref
        {
            identity_to_str(member_key_package.credential().identity())
        } else {
            None
        }
    })
}

pub fn generate_verification_key() -> Keypair {
    let mut csprng = OsRng {};
    Keypair::generate(&mut csprng)
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommGroupId {
    community_id: String,
    group_id: String,
}

impl CommGroupId {
    pub fn get_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn from_string(str: &str) -> Self {
        serde_json::from_str(str).unwrap()
    }

    pub fn community_id(&self) -> String {
        self.community_id.to_string()
    }

    pub fn group_id(&self) -> String {
        self.group_id.to_string()
    }

    pub fn new(community_id: &String, group_id: &String) -> Self {
        Self {
            community_id: community_id.to_string(),
            group_id: group_id.to_string(),
        }
    }

    pub fn default() -> Self {
        panic!("No name")
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SingleTimeMeasurement {
    description: String,
    nanoseconds: u128,
}

impl SingleTimeMeasurement {
    pub fn new(des: TimerType, dur: Duration) -> Self {
        let new_self = Self {
            description: format!("{:?}", des),
            nanoseconds: dur.as_nanos(),
        };
        debug!("[Timer-JSON]{}", serde_json::to_string(&new_self).unwrap());
        new_self
    }
}

#[derive(Debug)]
pub enum TimerType {
    SingleSendMessageDelay,
    ReadWebSocketMsgsDelay,
    EstablishWebsockets,
    CloseWebsockets,
    InterRetryDelay,
    NonSyncKPFetchRequestTurnaround,
    KeyPackageRequestTurnaround,
    PreSyncTurnaround,
    SingleUserRequestDSProcessTime,
    SingleUserRequestASProcessTime,
    TotalEndToEnd,
    ParseIncomingMsgsPreSync,
    ParseIncomingMsgsKeyPackage,
    ParseIncomingSingleMsgNonKpFetch,
    MlsGovNonSyncKpFetchRequestGeneration,
    MlsGovVerifiableActionGeneration,
    MlsGovRBACCheck,
    MlsGovPolicyEngineCheck,
    OpenMlsMsgGeneration,
    OpenMlsGroupOperation,
    OpenMlsMsgVerifyDecryption,
    SyncGeneration,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SingleMsgSizeMeasurement {
    description: String,
    num_bytes: usize,
}

#[derive(Debug)]
pub enum MsgSizeType {
    OutgoingMsg,
    IncomingMsg,
}

impl SingleMsgSizeMeasurement {
    pub fn new(des: MsgSizeType, size: usize) -> Self {
        let new_self = Self {
            description: format!("{:?}", des),
            num_bytes: size,
        };
        debug!(
            "[Bandwidth-JSON]{}",
            serde_json::to_string(&new_self).unwrap()
        );
        new_self
    }
}
