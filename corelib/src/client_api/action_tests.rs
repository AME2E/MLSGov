#[cfg(test)]
mod action_tests {
    use ed25519_dalek::Keypair;
    use rand_07::rngs::OsRng;

    use crate::client_api::actions::{Action, ActionMetadata, TextMsgAction};
    use crate::CommGroupId;

    #[test]
    fn test_action_sign_and_verify() {
        let text_msg = TextMsgAction {
            msg: "test".to_string(),
            metadata: ActionMetadata {
                sender: "alice".to_string(),
                action_id: "id1".to_string(),
                community_group_id: CommGroupId::new(
                    &"Community".to_string(),
                    &"Group".to_string(),
                ),
                data: "".to_string(),
            },
        };
        let mut csprng = OsRng {};
        let keypair = Keypair::generate(&mut csprng);
        let text_msg_sig = text_msg.sign(&keypair);
        // Verify the signature
        assert!(text_msg.verify_sig(&text_msg_sig, keypair.public_key()));
    }
}
