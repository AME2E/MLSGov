use serde_derive::{Deserialize, Serialize};

/// This struct contains information pertaining to the delivery
/// service configuration.
#[derive(Serialize, Deserialize, Default, Clone)]
pub(crate) struct DeliveryServiceConfig {
    pub data_path: String,
    pub ip_address: String,
    pub port: u16,
}
