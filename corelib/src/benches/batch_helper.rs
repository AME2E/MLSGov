use crate::Mutex;
use corelib::client_api;
use corelib::client_api::client_struct::ClientParsedMsg;
use corelib::messages::OnWireMessage;
use corelib::servers_api::as_struct::{AuthServiceState, SharedAuthServiceState};
use corelib::servers_api::ds_structs::{DeliveryServiceState, SharedDeliverServiceState};
use corelib::servers_api::{handle_onwire_msg_as_local, handle_onwire_msg_ds_local};
use corelib::test_helpers::{assert_all_feedback_ok, TestClientBundle};
use openmls::key_packages::KeyPackage;
use std::ops::DerefMut;
use std::sync::Arc;

pub fn create_test_bundles(num: usize) -> Vec<TestClientBundle> {
    let mut n = num;
    let mut result = vec![];
    while n > 0 {
        result.push(TestClientBundle::new(format!("{}", num - n).as_str()));
        n -= 1;
    }
    result
}

pub fn register_all_as_msgs(client_bundles: &Vec<TestClientBundle>) -> Vec<Vec<OnWireMessage>> {
    client_bundles
        .iter()
        .map(|client| {
            client_api::register_msg_as(
                client.credential().to_owned(),
                client.configs.get_keypair().public_key(),
            )
        })
        .collect()
}

pub async fn get_all_sync_as_msgs(
    client_bundles: &mut Vec<TestClientBundle>,
    as_state: &Arc<SharedAuthServiceState>,
) -> Vec<Vec<OnWireMessage>> {
    let mut sync_responses = vec![];
    for client in client_bundles {
        sync_responses.push(client.sync_as_credentials_responses(as_state).await);
    }
    sync_responses
}

pub fn register_all_ds_msgs(client_bundles: &mut Vec<TestClientBundle>) -> Vec<Vec<OnWireMessage>> {
    client_bundles
        .iter_mut()
        .map(|client| client_api::register_msg_ds(client.new_kps(5)))
        .collect()
}

pub fn sync_all_ds_msgs(client_bundles: &mut [TestClientBundle]) -> Vec<Vec<OnWireMessage>> {
    client_bundles
        .iter_mut()
        .map(|client| {
            let kps = client.new_kps(0);
            vec![client_api::sync_msg(client.configs.deref_mut(), kps)]
        })
        .collect()
}

pub async fn ds_process_all_msgs(
    msgs_list: Vec<Vec<OnWireMessage>>,
    ds_state: &Arc<SharedDeliverServiceState>,
) -> Vec<Vec<OnWireMessage>> {
    let mut result = vec![];
    for msgs in msgs_list {
        if !msgs.is_empty() {
            let inner_vec = ds_process_msgs(msgs, ds_state).await;
            result.push(inner_vec)
        } else {
            result.push(vec![])
        }
    }
    result
}

pub async fn ds_process_msgs(
    msgs: Vec<OnWireMessage>,
    ds_state: &Arc<SharedDeliverServiceState>,
) -> Vec<OnWireMessage> {
    let mut result = vec![];
    for msg in msgs {
        result.extend(handle_onwire_msg_ds_local(msg, ds_state).await);
    }
    result
}

pub async fn as_process_all_msgs(
    msgs_list: Vec<Vec<OnWireMessage>>,
    as_state: &Arc<SharedAuthServiceState>,
) -> Vec<Vec<OnWireMessage>> {
    let mut result = vec![];
    for msgs in msgs_list {
        if !msgs.is_empty() {
            let mut inner_vec = vec![];
            for msg in msgs {
                inner_vec.extend(handle_onwire_msg_as_local(msg, as_state).await);
            }
            result.push(inner_vec)
        } else {
            result.push(vec![])
        }
    }
    result
}

pub fn clients_process_all_msgs(
    msgss: Vec<Vec<OnWireMessage>>,
    client_bundles: &mut Vec<TestClientBundle>,
) -> Vec<Vec<ClientParsedMsg>> {
    msgss
        .iter()
        .enumerate()
        .map(|(i, msgs)| {
            let result = client_bundles.get_mut(i).unwrap().parse_msgs(msgs);
            result
        })
        .collect()
}

pub fn maybe_assert_all(local_msgs: Vec<Vec<ClientParsedMsg>>, enable_assert: bool) {
    if enable_assert {
        local_msgs.iter().for_each(assert_all_feedback_ok);
    }
}

pub fn pre_invite_keypackages(
    admin_bundle_i: usize,
    client_bundles: &mut Vec<TestClientBundle>,
) -> Vec<KeyPackage> {
    let mut key_packages = vec![];
    for (i, bundle) in client_bundles.iter_mut().enumerate() {
        if i != admin_bundle_i {
            key_packages.push(bundle.new_key_package().clone());
        }
    }
    key_packages
}
