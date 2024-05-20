//! A module to declare all authentication server data structures,
//! and their helper functions
use std::collections::BTreeMap;

use dashmap::DashMap;
use ed25519_dalek::PublicKey;
use openmls::credentials::Credential;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone)]
pub struct AuthServiceParam {
    /// Repeatable flag to turn verbose output on (Max: 2)
    pub verbose: u8,
    /// Whether to store persistent states
    pub persistent_state: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct CredentialEntry {
    pub(crate) credential: Credential,
    pub(crate) verification_key: PublicKey,
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct AuthServiceState {
    // Maps from User IDs to their public credential
    //#[serde(with = "any_key_map")]
    pub credential_entries: DashMap<String, CredentialEntry>,
}

impl AuthServiceState {
    pub fn new() -> AuthServiceState {
        AuthServiceState {
            credential_entries: DashMap::new(),
        }
    }
    pub fn get_credential_copy(&self, user: String) -> Option<Credential> {
        Some(self.credential_entries.get(&user)?.credential.to_owned())
    }

    pub fn get_all_credentials_copy(&self) -> BTreeMap<String, CredentialEntry> {
        let mut btree_map = BTreeMap::new();
        for (k, v) in self.credential_entries.clone().into_iter() {
            btree_map.insert(k, v);
        }
        btree_map
    }
}

pub type SharedAuthServiceState = AuthServiceState;
