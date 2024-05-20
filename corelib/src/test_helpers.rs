use core::fmt::Debug;
use core::marker::Sized;
use core::option::Option::None;
use std::sync::Arc;
use std::time::SystemTime;

use openmls::credentials::{Credential, CredentialBundle};
use openmls::key_packages::KeyPackage;
use versions::Versioning;

use crate::client_api::actions::ActionMsg;
use crate::client_api::client_crypto_impl::CryptoBackend;
use crate::client_api::client_struct::{ClientDataProvider, ClientParsedMsg};
use crate::client_api::client_struct_impl::ClientData;
use crate::client_api::parse_incoming_onwire_msgs;
use crate::messages::{
    OnWireMessage, OnWireMessageWithMetaData, UnorderedMsgContent, UnorderedPrivateMessage,
};
use crate::policyengine::ClientRef;
use crate::servers_api::as_struct::SharedAuthServiceState;
use crate::servers_api::ds_structs::SharedDeliverServiceState;
use crate::{generate_verification_key, servers_api, CommGroupId};

#[derive(Debug)]
pub struct TestClientBundle {
    pub configs: Box<dyn ClientDataProvider>,
    pub name: String,
    pub backend: CryptoBackend,
    pub credential_bundle: CredentialBundle,
}

impl TestClientBundle {
    pub fn new(name: &str) -> Self {
        let mut client_backend = CryptoBackend::default();
        let credential_bundle =
            client_backend.generate_credential_bundle(name.to_owned().into_bytes(), None, None);
        client_backend.store_credential_bundle(&credential_bundle);

        let client_credential = credential_bundle.credential();

        let client_config = ClientData::new(
            name.to_owned(),
            client_credential.to_owned(),
            generate_verification_key(),
        );

        Self {
            configs: Box::new(client_config) as ClientRef,
            name: name.to_string(),
            backend: client_backend,
            credential_bundle: credential_bundle.clone(),
        }
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn credential(&self) -> &Credential {
        self.credential_bundle.credential()
    }
    pub fn credential_bundle(&self) -> &CredentialBundle {
        &self.credential_bundle
    }

    pub fn new_key_package(&mut self) -> KeyPackage {
        let credential = self.credential_bundle.credential();
        self.backend
            .generate_default_key_package_and_store_bundle(credential)
    }

    pub fn new_kps(&mut self, num: u64) -> Vec<KeyPackage> {
        let credential = self.credential_bundle.credential();

        let mut result = vec![];
        while result.len() < num as usize {
            result.push(
                self.backend
                    .generate_default_key_package_and_store_bundle(credential),
            )
        }
        result
    }

    pub fn parse_msgs(&mut self, msgs: &Vec<OnWireMessage>) -> Vec<ClientParsedMsg> {
        parse_incoming_onwire_msgs(msgs.to_vec(), &mut self.configs, &mut self.backend)
    }

    pub async fn send_and_parse(
        &mut self,
        onwire_msg: OnWireMessage,
        ds_state: &Arc<SharedDeliverServiceState>,
    ) {
        let msgs = servers_api::handle_onwire_msg_ds_local(onwire_msg, ds_state).await;
        let _ = &self.parse_msgs(&msgs);
    }

    pub async fn send_assert_ok(
        &mut self,
        onwire_msg: OnWireMessage,
        ds_state: &Arc<SharedDeliverServiceState>,
    ) {
        let msgs = servers_api::handle_onwire_msg_ds_local(onwire_msg, ds_state).await;
        assert_all_feedback_ok(&self.parse_msgs(&msgs));
    }

    pub async fn send_all_assert_ok(
        &mut self,
        msgs: Vec<OnWireMessage>,
        ds_state: &Arc<SharedDeliverServiceState>,
    ) {
        for onwire_msg in msgs {
            self.send_assert_ok(onwire_msg, ds_state).await;
        }
    }

    pub async fn sync_ds_assert_ok(&mut self, ds_state: &Arc<SharedDeliverServiceState>) {
        let kps = self.new_kps(5);
        sync_and_assert_ok(
            self.name(),
            &mut self.configs,
            &mut self.backend,
            ds_state,
            kps,
        )
        .await;
    }

    pub async fn sync_as_credentials_responses(
        &mut self,
        as_state: &Arc<SharedAuthServiceState>,
    ) -> Vec<OnWireMessage> {
        servers_api::handle_onwire_msg_as_local(OnWireMessage::UserSyncCredentials, as_state).await
    }

    pub async fn sync_as_assert_ok(&mut self, as_state: &Arc<SharedAuthServiceState>) {
        let client_sync_response = parse_incoming_onwire_msgs(
            self.sync_as_credentials_responses(as_state).await,
            &mut self.configs,
            &mut self.backend,
        );

        assert_all_feedback_ok(&client_sync_response);
    }
}

pub fn sync_msg(user_name: String, key_packages: Vec<KeyPackage>) -> Vec<OnWireMessage> {
    OnWireMessage::UserSync {
        user_name,
        new_key_packages: key_packages,
    }
    .to_vec()
}

/// return test group name object
pub fn comm_grp() -> CommGroupId {
    CommGroupId::new(&"community".to_string(), &"group".to_string())
}

pub fn concat_string_in_decrypted_msgs(local_msgs: Vec<ClientParsedMsg>) -> String {
    let mut result_str = "".to_string();
    for local_msg in local_msgs {
        match local_msg {
            ClientParsedMsg::NewInvite { .. } => {}
            ClientParsedMsg::NewMsg {
                private_msg,
                comm_grp: _,
            } => {
                let UnorderedPrivateMessage { content, .. } = private_msg;
                match content {
                    UnorderedMsgContent::Text { text_content } => {
                        result_str.push_str(&text_content)
                    }
                    UnorderedMsgContent::TextAction { text_action } => {
                        if let ActionMsg::TextMsg(action) = &text_action.action {
                            result_str.push_str(&action.msg)
                        }
                    }
                    UnorderedMsgContent::GroupState { shared: _ } => (),
                    _ => (),
                };
            }
            ClientParsedMsg::NewOrdMsg {
                private_msg,
                sender: _,
                comm_grp: _,
            } => result_str.push_str(&private_msg),
            ClientParsedMsg::ASFeedback { .. } => {}
            ClientParsedMsg::DSFeedback { .. } => {}
            ClientParsedMsg::Invalid { description, .. } => result_str.push_str(&*description),
        }
    }

    result_str
}

pub fn assert_all_feedback_ok(local_msgs: &Vec<ClientParsedMsg>) {
    {
        for local_msg in local_msgs {
            match local_msg {
                ClientParsedMsg::NewInvite { .. } => {}
                ClientParsedMsg::NewMsg { .. } => {}
                ClientParsedMsg::NewOrdMsg { .. } => {}
                ClientParsedMsg::ASFeedback {
                    request_valid,
                    explanation,
                    ..
                }
                | ClientParsedMsg::DSFeedback {
                    request_valid,
                    explanation,
                    ..
                } => {
                    let expl = explanation
                        .to_owned()
                        .unwrap_or_else(|| "Invalid request".to_string());
                    assert!(request_valid, "{expl}")
                }
                ClientParsedMsg::Invalid { .. } => {}
            }
        }
    }
}

pub fn assert_credential_exist_in_config(
    client_configs: &mut (impl ClientDataProvider + Debug + ?Sized),
    comm_grp: &CommGroupId,
    credential: &Credential,
) {
    let mut exist = false;
    for key_package in client_configs
        .get_ref_group(comm_grp)
        .unwrap()
        .borrow()
        .members()
    {
        exist = exist || key_package.credential() == credential;
    }
    assert!(exist);
}

pub async fn sync_and_assert_ok(
    user_name: String,
    client_configs: &mut ClientRef,
    client_backend: &mut CryptoBackend,
    ds_state: &Arc<SharedDeliverServiceState>,
    key_packages: Vec<KeyPackage>,
) {
    let client_sync_response = parse_incoming_onwire_msgs(
        servers_api::handle_onwire_msg_ds_local(
            sync_msg(user_name.to_owned(), key_packages)[0].to_owned(),
            ds_state,
        )
        .await,
        client_configs,
        client_backend,
    );

    assert_all_feedback_ok(&client_sync_response);
}

pub fn flatten<T>(vec_of_vec: Vec<Vec<T>>) -> Vec<T> {
    let mut result = vec![];
    for v in vec_of_vec {
        result.extend(v);
    }
    result
}

/// Computes the bandwidth for sending the specified message
pub fn onwire_msg_bandwidth(msg: &OnWireMessage) -> usize {
    let app_msg_w_meta = OnWireMessageWithMetaData {
        onwire_msg: msg.to_owned(),
        sender_timestamp: SystemTime::now(),
        version: Versioning::new("0.3.0").unwrap().to_string(),
    };
    let encoded = serde_json::to_vec(&app_msg_w_meta).expect("Cannot encode app msg");
    encoded.len()
}

pub fn onwire_msgs_bandwidth(msgs: &Vec<OnWireMessage>) -> usize {
    msgs.iter().map(onwire_msg_bandwidth).sum()
}
