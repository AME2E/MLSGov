use crate::identity_to_str;
use openmls::prelude::MlsGroup;

/// Extracts user names from an `MlsGroup` object
pub fn user_names_from_mls_group(mls_group: &MlsGroup) -> Vec<String> {
    mls_group
        .members()
        .iter()
        .map(|key_package| identity_to_str(key_package.credential().identity()).unwrap())
        .collect()
}
