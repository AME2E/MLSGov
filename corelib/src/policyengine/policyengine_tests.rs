#[cfg(test)]
mod policyengine_tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::client_api::actions::{
        ActionMetadata, ActionMsg, ActionType, CustomAction, RenameGroupAction, VoteAction,
    };
    use crate::client_api::client_struct::{ClientDataProvider, MockClientDataProvider};
    use crate::policyengine::policies::{
        PassAllPolicy, ReputationChangeAction, ReputationNameChangePolicy, VoteOnNameChangePolicy,
    };
    use crate::policyengine::{Policy, PolicyEngine};
    use crate::CommGroupId;

    #[test]
    fn test_pass_all_actions() {
        // Initialize a mock client
        let mut mock_client = MockClientDataProvider::new();
        mock_client
            .expect_set_group_name()
            .withf(|comm_grp_id: &CommGroupId, new_name: &String| {
                comm_grp_id.community_id() == "test_community".to_string()
                    && comm_grp_id.group_id() == "test_group".to_string()
                    && new_name.eq("new name")
            })
            .times(1)
            .returning(|_, _| ());
        let mut mock_client_ref = Box::new(mock_client) as Box<dyn ClientDataProvider>;

        // Initialize a new policy
        let pass_all = PassAllPolicy {};
        let pass_all_ref = Rc::new(RefCell::new(Box::new(pass_all) as Box<dyn Policy>));
        // Initialize a policy engine
        let mut policy_engine = PolicyEngine::new(vec![pass_all_ref.clone()]);

        // Generate a test action
        let rename_action = ActionMsg::RenameGroup(RenameGroupAction {
            new_name: "new name".to_string(),
            metadata: ActionMetadata {
                sender: "sender".to_string(),
                action_id: "rename_action_id".to_string(),
                community_group_id: CommGroupId::new(
                    &"test_community".to_string(),
                    &"test_group".to_string(),
                ),
                data: "".to_string(),
            },
        });

        // Evaluate the action in the policy action
        policy_engine.evaluate_action(rename_action, &mut mock_client_ref);

        // Ensure that the action got passed
        println!("test passed")
    }

    /// Test a policy that mandates a vote for changing the name of a group
    #[test]
    fn test_vote_on_name_change() {
        // Set up the client and policy
        let mut mock_client = MockClientDataProvider::new();

        // set client expectations
        mock_client.expect_get_group_members().return_const(vec![
            "alice".to_string(),
            "bob".to_string(),
            "charlie".to_string(),
        ]);
        mock_client
            .expect_set_group_name()
            .withf(|comm_grp_id: &CommGroupId, new_name: &String| {
                comm_grp_id.community_id() == "test_community".to_string()
                    && comm_grp_id.group_id() == "test_group".to_string()
                    && new_name.eq("new name")
            })
            .times(1)
            .returning(|_, _| ());
        let mut mock_client_ref = Box::new(mock_client) as Box<dyn ClientDataProvider>;

        let vote_policy = VoteOnNameChangePolicy::new();
        let vote_policy_ref = Rc::new(RefCell::new(Box::new(vote_policy) as Box<dyn Policy>));

        // Generate a test action
        let rename_action = ActionMsg::RenameGroup(RenameGroupAction {
            new_name: "new name".to_string(),
            metadata: ActionMetadata {
                sender: "sender".to_string(),
                action_id: "rename_action_id".to_string(),
                community_group_id: CommGroupId::new(
                    &"test_community".to_string(),
                    &"test_group".to_string(),
                ),
                data: "".to_string(),
            },
        });

        let mut policy_engine = PolicyEngine::new(vec![vote_policy_ref.clone()]);

        // Evaluate the action in the policy action
        policy_engine.evaluate_action(rename_action, &mut mock_client_ref);

        // Generate the vote actions
        let alice_vote_action = ActionMsg::Vote(VoteAction {
            vote_value: "yes".to_string(),
            proposed_action_id: "rename_action_id".to_string(),
            proposed_action_type: ActionType::RenameGroup,
            metadata: ActionMetadata {
                sender: "alice".to_string(),
                action_id: "alice_vote_id".to_string(),
                community_group_id: CommGroupId::new(
                    &"test_community".to_string(),
                    &"test_group".to_string(),
                ),
                data: "".to_string(),
            },
        });

        let bob_vote_action = ActionMsg::Vote(VoteAction {
            vote_value: "no".to_string(),
            proposed_action_id: "rename_action_id".to_string(),
            proposed_action_type: ActionType::RenameGroup,
            metadata: ActionMetadata {
                sender: "bob".to_string(),
                action_id: "bob_vote_id".to_string(),
                community_group_id: CommGroupId::new(
                    &"test_community".to_string(),
                    &"test_group".to_string(),
                ),
                data: "".to_string(),
            },
        });

        let charlie_vote_action = ActionMsg::Vote(VoteAction {
            vote_value: "yes".to_string(),
            proposed_action_id: "rename_action_id".to_string(),
            proposed_action_type: ActionType::RenameGroup,
            metadata: ActionMetadata {
                sender: "charlie".to_string(),
                action_id: "charlie_vote_id".to_string(),
                community_group_id: CommGroupId::new(
                    &"test_community".to_string(),
                    &"test_group".to_string(),
                ),
                data: "".to_string(),
            },
        });

        // Vote on the name change
        policy_engine.evaluate_action(alice_vote_action, &mut mock_client_ref);
        policy_engine.evaluate_action(bob_vote_action, &mut mock_client_ref);
        policy_engine.evaluate_action(charlie_vote_action, &mut mock_client_ref);

        // Evaluate the pending action
        PolicyEngine::evaluate_proposed_action(
            &mut policy_engine.proposed_actions[0],
            &mut mock_client_ref,
            false,
        );
    }

    #[test]
    fn test_reputation_policy() {
        let mut mock_client = MockClientDataProvider::new();

        mock_client
            .expect_set_group_name()
            .withf(|comm_grp_id: &CommGroupId, new_name: &String| {
                comm_grp_id.community_id() == "test_community".to_string()
                    && comm_grp_id.group_id() == "test_group".to_string()
                    && new_name.eq("new name")
            })
            .times(1)
            .returning(|_, _| ());

        let mut mock_client_ref = Box::new(mock_client) as Box<dyn ClientDataProvider>;
        let alice_rep_action = ActionMsg::Custom(CustomAction {
            data: serde_json::to_string(&ReputationChangeAction {
                user_id: "diane".to_string(),
                reputation_change: 1,
            })
            .unwrap(),
            metadata: ActionMetadata {
                sender: "alice".to_string(),
                action_id: "alice_rep_id".to_string(),
                community_group_id: CommGroupId::new(
                    &"test_community".to_string(),
                    &"test_group".to_string(),
                ),
                data: "".to_string(),
            },
        });

        let bob_rep_action = ActionMsg::Custom(CustomAction {
            data: serde_json::to_string(&ReputationChangeAction {
                user_id: "diane".to_string(),
                reputation_change: 1,
            })
            .unwrap(),
            metadata: ActionMetadata {
                sender: "bob".to_string(),
                action_id: "bob_rep_id".to_string(),
                community_group_id: CommGroupId::new(
                    &"test_community".to_string(),
                    &"test_group".to_string(),
                ),
                data: "".to_string(),
            },
        });

        let charlie_rep_action = ActionMsg::Custom(CustomAction {
            data: serde_json::to_string(&ReputationChangeAction {
                user_id: "diane".to_string(),
                reputation_change: 1,
            })
            .unwrap(),
            metadata: ActionMetadata {
                sender: "charlie".to_string(),
                action_id: "charlie_rep_id".to_string(),
                community_group_id: CommGroupId::new(
                    &"test_community".to_string(),
                    &"test_group".to_string(),
                ),
                data: "".to_string(),
            },
        });

        let diane_rename_action = ActionMsg::RenameGroup(RenameGroupAction {
            new_name: "new name".to_string(),
            metadata: ActionMetadata {
                sender: "diane".to_string(),
                action_id: "diane_rename_id".to_string(),
                community_group_id: CommGroupId::new(
                    &"test_community".to_string(),
                    &"test_group".to_string(),
                ),
                data: "".to_string(),
            },
        });

        let rep_policy = ReputationNameChangePolicy::new();
        let rep_policy_ref = Rc::new(RefCell::new(Box::new(rep_policy) as Box<dyn Policy>));

        let mut policy_engine = PolicyEngine::new(vec![rep_policy_ref]);
        policy_engine.evaluate_action(alice_rep_action, &mut mock_client_ref);
        policy_engine.evaluate_action(bob_rep_action, &mut mock_client_ref);
        policy_engine.evaluate_action(charlie_rep_action, &mut mock_client_ref);
        policy_engine.evaluate_action(diane_rename_action, &mut mock_client_ref);
    }
}
