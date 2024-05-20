use openmls::ciphersuite::hash_ref::HashReference;
use openmls::credentials::{Credential, CredentialBundle, CredentialType};
use openmls::extensions::{Extension, LifetimeExtension};
use openmls::key_packages::{KeyPackage, KeyPackageBundle};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::key_store::{FromKeyStoreValue, OpenMlsKeyStore, ToKeyStoreValue};
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsCryptoProvider;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::RwLock;
use std::{fmt, u8};
use tls_codec::Serialize;

/// Choice of ED25519 is because when creating KeyPackageBundle, OpenMLS checks if the first of
/// [supported_ciphersuites] is the same type of CredentialBundle. As of the initial implementation,
/// The first [supported_ciphersuites] is ED25519. See [`generate_key_package_bundle`]
const DEFAULT_SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::ED25519;
const DEFAULT_CREDENTIAL_TYPE: CredentialType = CredentialType::Basic;

const DEFAULT_LIFETIME: u64 = 60 * 60 * 24 * 90;

/// Errors thrown by the key store.
/// Credit: OpenMLS Memory Keystore
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BackendError {
    UnsupportedValueTypeBytes,
    UnsupportedMethod,
    SerializationError,
}

impl std::error::Error for BackendError {}

/// Credit: OpenMLS Memory Keystore
#[derive(Default, Debug)]
pub struct KeyStore {
    values: RwLock<KeyStoreType>,
}

pub type KeyStoreType = HashMap<Vec<u8>, Vec<u8>>;

#[derive(Default, Debug)]
pub struct CryptoBackend {
    pub crypto: RustCrypto,
    pub key_store: KeyStore,
}

/// Credit: OpenMLS Memory Keystore
impl OpenMlsKeyStore for KeyStore {
    type Error = BackendError;

    fn store<V: ToKeyStoreValue>(&self, k: &[u8], v: &V) -> Result<(), Self::Error>
    where
        Self: Sized,
    {
        let value = v
            .to_key_store_value()
            .map_err(|_| BackendError::SerializationError)?;
        // We unwrap here, because this is the only function claiming a write
        // lock on `credential_bundles`. It only holds the lock very briefly and
        // should not panic during that period.
        let mut values = self.values.write().unwrap();
        values.insert(k.to_vec(), value);
        Ok(())
    }

    fn read<V: FromKeyStoreValue>(&self, k: &[u8]) -> Option<V>
    where
        Self: Sized,
    {
        let values = self.values.read().unwrap();
        if let Some(value) = values.get(k) {
            V::from_key_store_value(value).ok()
        } else {
            let values = self.values.read().unwrap();
            if let Some(value) = values.get(k) {
                V::from_key_store_value(value).ok()
            } else {
                None
            }
        }
    }

    fn delete(&self, k: &[u8]) -> Result<(), Self::Error> {
        let mut values = self.values.write().unwrap();
        values.remove(k);
        Ok(())
    }
}

/// To provide easier saving to persistent states
impl KeyStore {
    pub fn get_key_store_copy(&self) -> KeyStoreType {
        self.values.read().unwrap().to_owned()
    }

    pub fn replace_from(&mut self, hm: KeyStoreType) {
        self.values = RwLock::new(hm);
    }
}

/// Credit: OpenMLS Rust Crypto
impl OpenMlsCryptoProvider for CryptoBackend {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type KeyStoreProvider = KeyStore;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn key_store(&self) -> &Self::KeyStoreProvider {
        &self.key_store
    }
}

impl CryptoBackend {
    pub fn store_credential_bundle(&mut self, credential_bundle: &CredentialBundle) {
        let credential = credential_bundle.credential().to_owned();
        self.key_store()
            .store(
                &credential
                    .signature_key()
                    .tls_serialize_detached()
                    .expect("Error serializing signature key."),
                credential_bundle,
            )
            .expect("An unexpected error occurred.");
    }

    pub fn read_credential_bundle(&mut self, credential: &Credential) -> CredentialBundle {
        self.key_store()
            .read(
                &credential
                    .signature_key()
                    .tls_serialize_detached()
                    .expect("Error serializing signature key."),
            )
            .expect("Credential not found in key store.")
    }

    pub fn store_key_package_bundle(&mut self, key_package_bundle: &KeyPackageBundle) {
        let key_package = key_package_bundle.key_package().to_owned();

        // Store it in the key store
        self.key_store()
            .store(
                key_package
                    .hash_ref(self.crypto())
                    .expect("Could not hash KeyPackage.")
                    .as_slice(),
                key_package_bundle,
            )
            .expect("An unexpected error occurred.");
    }

    pub fn generate_credential_bundle(
        &mut self,
        user_identity: Vec<u8>,
        credential_type: Option<CredentialType>,
        sig_scheme: Option<SignatureScheme>,
    ) -> CredentialBundle {
        CredentialBundle::new(
            user_identity,
            credential_type.unwrap_or(DEFAULT_CREDENTIAL_TYPE),
            sig_scheme.unwrap_or(DEFAULT_SIGNATURE_SCHEME),
            self,
        )
        .unwrap()
    }

    pub fn generate_key_package_bundle(
        &mut self,
        credential_bundle: &CredentialBundle,
        extension: Vec<Extension>,
    ) -> KeyPackageBundle {
        KeyPackageBundle::new(
            &self.crypto().supported_ciphersuites(),
            credential_bundle,
            self,
            extension,
        )
        .expect("Cannot create new [KeyPackageBundle]")
    }

    pub fn generate_default_key_package_and_store_bundle(
        &mut self,
        credential: &Credential,
    ) -> KeyPackage {
        let extensions = vec![Extension::LifeTime(LifetimeExtension::new(
            DEFAULT_LIFETIME, // Maximum lifetime of 90 days, expressed in seconds
        ))];

        // Fetch the credential bundle from the key store
        let credential_bundle = self.read_credential_bundle(credential);

        // Create the key package bundle
        let key_package_bundle = self.generate_key_package_bundle(&credential_bundle, extensions);

        // Store it in the key store
        self.store_key_package_bundle(&key_package_bundle);

        key_package_bundle.key_package().to_owned()
    }

    pub fn hash_key_package(&self, key_package: &KeyPackage) -> HashReference {
        key_package
            .hash_ref(self.crypto())
            .expect("Could not hash KeyPackage.")
    }
}

// Credit: https://stackoverflow.com/questions/32710187/how-do-i-get-an-enum-as-a-string
impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(self, f)
    }
}
