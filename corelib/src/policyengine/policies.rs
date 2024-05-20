use std::collections::BTreeMap;
use std::ops::DerefMut;

use log::info;
use serde::{Deserialize, Serialize};

use crate::client_api::actions::{Action, ActionMsg, ActionType};
use crate::policyengine::{ClientRef, Policy, ProposedAction, ProposedActionStatus};

#[derive(Serialize, Deserialize, Clone)]
pub struct PassAllPolicy {}

#[typetag::serde]
impl Policy for PassAllPolicy {
    fn filter(&self, _action: &ActionMsg, _client_data: &mut ClientRef) -> bool {
        true
    }

    fn init(&mut self, _proposed_action: &mut ProposedAction, _client_data: &mut ClientRef) {}

    fn check(
        &mut self,
        _proposed_action: &mut ProposedAction,
        _client_data: &mut ClientRef,
    ) -> ProposedActionStatus {
        ProposedActionStatus::PASSED
    }

    fn pass(&mut self, proposed_action: &mut ProposedAction, client_data: &mut ClientRef) {
        proposed_action.action.execute(client_data.deref_mut());
    }

    fn fail(&mut self, _proposed_action: &mut ProposedAction, _client_data: &mut ClientRef) {}

    fn get_policy_obj(&self) -> Box<dyn Policy> {
        Box::new(self.clone())
    }

    fn get_policy_name(&self) -> &str {
        "PassAllPolicy"
    }
}

/// This voting policy governs how name changes can be passed by popular
/// vote. In order to do so it monitors two kinds of actions: the
#[derive(Serialize, Deserialize, Clone)]
pub struct VoteOnNameChangePolicy {
    /// Maps action ids to polls
    action_id_to_poll: BTreeMap<String, Poll>,
}

/// The Poll object keeps track of a running vote for a particular action
#[derive(Serialize, Deserialize, Clone)]
pub struct Poll {
    /// Keeps a running tally of the overall vote count
    option_to_vote_count: BTreeMap<String, usize>,
    /// Keeps track of which members are eligible to vote and which ones
    /// have voted. For this current policy, members cannot change their
    /// votes. If a member has not voted, the value for their key is None.
    member_to_vote: BTreeMap<String, Option<String>>,
}

impl Poll {
    /// Initializes a new poll based on a vector of eligible voters
    pub fn new(eligible_voters: &Vec<String>) -> Self {
        let member_to_vote: BTreeMap<String, Option<String>> = eligible_voters
            .iter()
            .map(|member| (member.clone(), None))
            .collect();
        Poll {
            option_to_vote_count: BTreeMap::from([("yes".to_string(), 0), ("no".to_string(), 0)]),
            member_to_vote,
        }
    }

    /// Records vote and returns true if the vote was able to be recorded
    /// successfully and false otherwise
    pub fn record_vote(&mut self, member: &String, vote_to_cast: &String) -> bool {
        // Ensure that the vote_to_cast is valid
        if !self.option_to_vote_count.contains_key(vote_to_cast) {
            return false;
        }
        // Make sure that the member is eligible to vote and hasn't voted yet
        if let Some(vote) = self.member_to_vote.get_mut(member) {
            if vote.is_none() {
                *vote = Some(vote_to_cast.clone());
                *self.option_to_vote_count.get_mut(vote_to_cast).unwrap() += 1;
                return true;
            }
        }
        false
    }

    pub fn get_yes_votes(&self) -> usize {
        *self.option_to_vote_count.get(&"yes".to_string()).unwrap()
    }

    pub fn get_no_votes(&self) -> usize {
        *self.option_to_vote_count.get(&"no".to_string()).unwrap()
    }

    pub fn get_num_eligible_voters(&self) -> usize {
        self.member_to_vote.len()
    }
}

impl VoteOnNameChangePolicy {
    pub fn new() -> Self {
        VoteOnNameChangePolicy {
            action_id_to_poll: BTreeMap::new(),
        }
    }
}

#[typetag::serde]
impl Policy for VoteOnNameChangePolicy {
    /// Allow RenameGroup actions and Vote actions that have to do with
    /// renaming the group
    fn filter(&self, action: &ActionMsg, _client_data: &mut ClientRef) -> bool {
        match action {
            ActionMsg::RenameGroup(_) => true,
            ActionMsg::Vote(vote_action) => {
                vote_action.proposed_action_type == ActionType::RenameGroup
            }
            _ => false,
        }
    }

    /// Initialize an empty voting state for this proposed action, if
    /// that action is a rename
    fn init(&mut self, action: &mut ProposedAction, client_data: &mut ClientRef) {
        if let ActionMsg::RenameGroup(rename_action) = &action.action {
            let action_id = rename_action.get_metadata().action_id;
            // Generate poll -- only the members present at the initialization
            // of the poll are eligible to vote.
            self.action_id_to_poll.insert(
                action_id,
                Poll::new(
                    &client_data
                        .get_group_members(&action.action.get_metadata().community_group_id),
                ),
            );
            info!(
                "Voting is happening for action ID: {}",
                &action.action.get_metadata().action_id
            );
        }
    }

    fn check(
        &mut self,
        action: &mut ProposedAction,
        _client_data: &mut ClientRef,
    ) -> ProposedActionStatus {
        let action_metadata = action.action.get_metadata();
        match &action.action {
            ActionMsg::RenameGroup(_) => {
                // Retrieve the poll and check if it has completed
                let poll = self
                    .action_id_to_poll
                    .get_mut(&action_metadata.action_id)
                    .unwrap();
                let yes_votes = poll.get_yes_votes();
                let no_votes = poll.get_no_votes();
                let num_eligible_voters = poll.get_num_eligible_voters();
                if yes_votes + no_votes < num_eligible_voters {
                    ProposedActionStatus::PROPOSED
                } else if yes_votes >= no_votes {
                    ProposedActionStatus::PASSED
                } else {
                    ProposedActionStatus::FAILED
                }
            }
            ActionMsg::Vote(vote_action) => {
                // Register the vote
                log::info!("registering a vote: {:?}", vote_action);
                // Register the vote
                let result = self
                    .action_id_to_poll
                    .get_mut(&vote_action.proposed_action_id)
                    .unwrap()
                    .record_vote(&vote_action.get_metadata().sender, &vote_action.vote_value);
                if result {
                    log::info!("vote registered successfully");
                } else {
                    log::info!("vote not registered");
                }
                ProposedActionStatus::PASSED
            }
            _ => ProposedActionStatus::PROPOSED,
        }
    }

    fn pass(&mut self, action: &mut ProposedAction, client_data: &mut ClientRef) {
        if let ActionMsg::RenameGroup(rename_action) = &action.action {
            rename_action.execute(client_data.deref_mut());
            self.action_id_to_poll
                .remove(&rename_action.get_metadata().action_id);
        }
    }

    fn fail(&mut self, action: &mut ProposedAction, _client_data: &mut ClientRef) {
        if let ActionMsg::RenameGroup(rename_action) = &action.action {
            self.action_id_to_poll
                .remove(&rename_action.get_metadata().action_id);
        }
    }

    fn get_policy_obj(&self) -> Box<dyn Policy> {
        Box::new(self.clone())
    }

    fn get_policy_name(&self) -> &str {
        "VoteOnNameChangePolicy"
    }
}

/// A policy that keeps track of user reputation via a custom action message
#[derive(Serialize, Deserialize, Clone)]
pub struct ReputationNameChangePolicy {
    /// User reputations: a mapping from the user id as a String to the
    /// reputation, which is a sigend 32-bit integer (reputations are allowed
    /// to be negative)
    user_id_to_reputation: BTreeMap<String, i32>,
}

/// An action conveying a reputation change
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReputationChangeAction {
    /// The user affected by the action
    pub user_id: String,
    /// The amount by which to change the user's reputation
    pub reputation_change: i32,
}

impl ReputationNameChangePolicy {
    pub fn new() -> Self {
        ReputationNameChangePolicy {
            user_id_to_reputation: BTreeMap::new(),
        }
    }
}

impl Default for ReputationNameChangePolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[typetag::serde]
impl Policy for ReputationNameChangePolicy {
    fn filter(&self, action: &ActionMsg, _client_data: &mut ClientRef) -> bool {
        match action {
            ActionMsg::RenameGroup(_) => true,
            ActionMsg::Custom(custom) => {
                serde_json::from_str::<ReputationChangeAction>(&custom.data).is_ok()
            }
            _ => false,
        }
    }

    fn init(&mut self, _action: &mut ProposedAction, _client_data: &mut ClientRef) {}

    fn check(
        &mut self,
        action: &mut ProposedAction,
        _client_data: &mut ClientRef,
    ) -> ProposedActionStatus {
        let action_metadata = action.action.get_metadata();
        match &action.action {
            ActionMsg::RenameGroup(_) => {
                // Obtain the reputation of this group member
                let rep = *self
                    .user_id_to_reputation
                    .entry(action_metadata.sender)
                    .or_insert(0);
                if rep > 2 {
                    ProposedActionStatus::PASSED
                } else {
                    ProposedActionStatus::FAILED
                }
            }
            ActionMsg::Custom(custom) => {
                // Already checked is this the right type of action in filter
                let change_rep: ReputationChangeAction =
                    serde_json::from_str(&custom.data).unwrap();
                // Don't allow reputation changes that are too large
                if change_rep.reputation_change > 2 || change_rep.reputation_change < -2 {
                    return ProposedActionStatus::FAILED;
                }
                // Perform the update in the map
                *self
                    .user_id_to_reputation
                    .entry(change_rep.user_id)
                    .or_insert(0) += change_rep.reputation_change;
                ProposedActionStatus::PASSED
            }
            _ => ProposedActionStatus::FAILED,
        }
    }

    fn pass(&mut self, action: &mut ProposedAction, client_data: &mut ClientRef) {
        if let ActionMsg::RenameGroup(rename_action) = &action.action {
            rename_action.execute(client_data.deref_mut());
        }
    }

    fn fail(&mut self, _action: &mut ProposedAction, _client_data: &mut ClientRef) {}

    fn get_policy_obj(&self) -> Box<dyn Policy> {
        Box::new(self.clone())
    }

    fn get_policy_name(&self) -> &str {
        "ReputationNameChangePolicy"
    }
}

/// A policy that maintains a community word filter
#[derive(Serialize, Deserialize, Clone)]
pub struct WordFilterPolicy {
    /// The set of words that are not allowed in the community
    filtered_words: BTreeMap<String, ()>,
}

/// An action conveying a reputation change
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WordFilterAction {
    /// Updated word filter
    pub new_filtered_words: BTreeMap<String, ()>,
}

#[typetag::serde]
impl Policy for WordFilterPolicy {
    fn filter(&self, action: &ActionMsg, _client_data: &mut ClientRef) -> bool {
        match action {
            ActionMsg::Custom(custom) => {
                serde_json::from_str::<WordFilterAction>(&custom.data).is_ok()
            }
            ActionMsg::TextMsg(_) => true,
            _ => false,
        }
    }

    fn init(&mut self, _action: &mut ProposedAction, _client_data: &mut ClientRef) {}

    fn check(
        &mut self,
        action: &mut ProposedAction,
        client_data: &mut ClientRef,
    ) -> ProposedActionStatus {
        match action.action {
            ActionMsg::Custom(_) => {
                let metadata = action.action.get_metadata();
                let sender = metadata.sender;
                let community_group_id = metadata.community_group_id;
                let rbac = client_data.get_roles(&community_group_id);
                // Check if the sender of the action has a Mod role
                if rbac.user_to_role.get(&sender) == Some(&"Mod".to_string()) {
                    ProposedActionStatus::PASSED
                } else {
                    ProposedActionStatus::FAILED
                }
            }
            ActionMsg::TextMsg(ref text_msg) => {
                let words = text_msg.msg.split_whitespace();
                for word in words {
                    if self.filtered_words.contains_key(word) {
                        return ProposedActionStatus::FAILED;
                    }
                }
                ProposedActionStatus::PASSED
            }
            _ => ProposedActionStatus::FAILED,
        }
    }

    fn pass(&mut self, action: &mut ProposedAction, client_data: &mut ClientRef) {
        match &action.action {
            ActionMsg::Custom(custom) => {
                let change_filter: WordFilterAction = serde_json::from_str(&custom.data).unwrap();
                self.filtered_words = change_filter.new_filtered_words;
            }
            ActionMsg::TextMsg(text_action) => {
                text_action.execute(client_data.deref_mut());
            }
            _ => {}
        }
    }

    fn fail(&mut self, _action: &mut ProposedAction, _client_data: &mut ClientRef) {}

    fn get_policy_obj(&self) -> Box<dyn Policy> {
        Box::new(self.clone())
    }

    fn get_policy_name(&self) -> &str {
        "WordFilterPolicy"
    }
}
