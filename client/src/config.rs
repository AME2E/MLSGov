use serde_derive::{Deserialize, Serialize};

/// This struct contains configuration information for the client
#[derive(Serialize, Deserialize, Default)]
pub(crate) struct ClientConfig {
    /// The URL of the delivery service
    pub ds_url_str: String,
    /// The URL of hte authentication service
    pub as_url_str: String,
    /// The number of new key packages to send with every sync
    pub new_key_packages_per_sync: usize,
    /// Path to the file containing this client's data
    pub data_path: String,
    /// Path to the file containing this client's keystore
    pub keystore_path: String,
}
