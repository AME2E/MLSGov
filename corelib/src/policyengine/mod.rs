//! The implementation of the policy engine, which evalutes proposed
//! actions that users attempt. This comprises the core of the governance
//! layer, which mediates actions that users attempt.
//!
//! This module is inspired by [policykit](https://github.com/policykit/policykit).

use std::ops::Deref;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use serde::{Deserialize, Serialize};

use crate::client_api::{actions::ActionMsg, client_struct::ClientDataProvider};
use crate::messages::{decode_from_bytes, encode_to_bytes};
use crate::BytesVisitor;

pub mod policies;

#[cfg(test)]
mod policyengine_tests;

/// The `PolicyRef` type is used for handling references to policies within
/// the policy engine. Since we'd like to generate `ProposedAction`
/// objects that contain references to policies, which have mutable state,
/// we require a reference type that allows us to handle trait objects
/// and multiple references, hence our choice of Rc<RefCell<...>>.
type PolicyRef = Rc<RefCell<Box<dyn Policy>>>;
pub type ClientRef = Box<dyn ClientDataProvider>;

/// The `Policy` trait defines the core interface a developer-defined
/// policy must provide.
#[typetag::serde(tag = "policy_type")]
pub trait Policy {
    /// Filters actions that are in scope for this policy
    fn filter(&self, action: &ActionMsg, client_data: &mut ClientRef) -> bool;
    /// Initializes the evaluation of the policy for this proposed action
    /// and notify users of any key information if need to know
    fn init(&mut self, action: &mut ProposedAction, client_data: &mut ClientRef);
    /// Returns the status of the proposed action after it is checked against
    /// this policy
    fn check(
        &mut self,
        action: &mut ProposedAction,
        client_data: &mut ClientRef,
    ) -> ProposedActionStatus;
    /// Specifies what should happen if the proposed action is passed
    fn pass(&mut self, action: &mut ProposedAction, client_data: &mut ClientRef);
    /// Specifies what should happen if the proposed action fails
    fn fail(&mut self, action: &mut ProposedAction, client_data: &mut ClientRef);
    /// Returns a Box containing this policy as a trait object, producing
    /// a copy of the policy
    fn get_policy_obj(&self) -> Box<dyn Policy>;
    /// Returns the name of the policy to aid with debugging
    fn get_policy_name(&self) -> &str;
}

// Drawing on https://github.com/policykit/policykit/blob/6729fa82/policykit/policyengine/engine.py
pub struct PolicyEngine {
    pub policies: Vec<PolicyRef>,
    pub proposed_actions: Vec<ProposedAction>,
}

/// When debugging the PolicyEngine, show the contents of the SerPolicyEngine
impl std::fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ser_engine: SerPolicyEngine = self.into();
        write!(f, "{:?}", ser_engine)
    }
}

/// Use the typetag serialization in order to debug a policy
impl std::fmt::Debug for Box<dyn Policy> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

impl Clone for PolicyEngine {
    fn clone(&self) -> Self {
        let ser_engine: SerPolicyEngine = self.into();
        ser_engine.into()
    }
}

impl PolicyEngine {
    pub fn new(policies: Vec<PolicyRef>) -> Self {
        PolicyEngine {
            policies,
            proposed_actions: Vec::new(),
        }
    }

    /// Called the first time the action is evaluated
    pub fn evaluate_action(&mut self, action: ActionMsg, client_data: &mut ClientRef) {
        let proposed_action_opt = self.create_prefiltered_proposed_actions(action, client_data);
        if let Some(mut proposed_action) = proposed_action_opt {
            Self::evaluate_proposed_action(&mut proposed_action, client_data, true);
            if proposed_action.status == ProposedActionStatus::PROPOSED {
                self.proposed_actions.push(proposed_action);
            }
        }
    }

    /// Evaluates the given action against the list of policies and returns
    /// ProposedActionS for those that pass the filter. This will generate
    /// multiple copies of the same action -- one for each proposal.
    pub fn create_prefiltered_proposed_actions<'a>(
        &self,
        action: ActionMsg,
        client_data: &mut ClientRef,
    ) -> Option<ProposedAction> {
        let mut proposed_actions = None;
        for policy in self.policies.iter() {
            // Check if filter passes, the first policy whose filter
            // passes will be assigned to this action
            if policy.borrow().filter(&action, client_data) {
                proposed_actions = Some(ProposedAction::new(
                    action,
                    policy.clone(),
                    ProposedActionStatus::PROPOSED,
                ));
                break;
            }
        }

        proposed_actions
    }

    /// Called repeatedly until a proposed action reaches a state of
    /// PASSED, FAILED, or BLOCKED. This function will invoke a check.
    /// If the result is PASSED, the code in `pass` runs. If the result
    /// is FAILED or BLOCKED, then the code in `fail` runs. If the result
    /// is PROPOSED, the proposed action is retained.
    /// The argument `first_eval` specifies if this is the first time the
    /// proposed action is being evaluated
    pub fn evaluate_proposed_action(
        proposed_action: &mut ProposedAction,
        client_data: &mut ClientRef,
        first_eval: bool,
    ) {
        let policy_clone = proposed_action.policy.clone();
        let mut policy_ref = policy_clone.borrow_mut();

        if first_eval {
            policy_ref.init(proposed_action, client_data);
        }

        let check_result = policy_ref.check(proposed_action, client_data);
        proposed_action.status = check_result;
        match check_result {
            ProposedActionStatus::PROPOSED => (),
            ProposedActionStatus::PASSED => {
                policy_ref.pass(proposed_action, client_data);
            }
            ProposedActionStatus::FAILED => {
                policy_ref.fail(proposed_action, client_data);
            }
        }
    }

    /// Evaluates all currently proposed actions and retains only those that
    /// are still in a PROPOSED state
    pub fn evaluate_all_proposed_actions(&mut self, client_data: &mut ClientRef) {
        self.proposed_actions
            .iter_mut()
            .for_each(|proposed_action| {
                PolicyEngine::evaluate_proposed_action(proposed_action, client_data, false)
            });
        self.proposed_actions
            .retain(|proposed_action| proposed_action.status == ProposedActionStatus::PROPOSED)
    }
}

/// The status that a proposed action has, according to a given policy.
/// This is also the output type of the `check` function of a policy.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposedActionStatus {
    /// The action's approval is pending
    PROPOSED,
    /// The action has failed to pass
    FAILED,
    /// The action has been approved
    PASSED,
}

/// `ProposedAction` here serves the purpose of a `Proposal` in the PolicyKit
/// codebase. This corresponds to the evaluation of an action on a policy.
/// Data related to the policy is stored in this struct.
pub struct ProposedAction {
    pub action: ActionMsg,
    pub policy: PolicyRef,
    pub status: ProposedActionStatus,
    pub data: String,
}

impl ProposedAction {
    pub fn new(action: ActionMsg, policy: PolicyRef, status: ProposedActionStatus) -> Self {
        ProposedAction {
            action,
            policy,
            status,
            data: "".to_string(),
        }
    }
}

/// A serializable verison of `ProposedAction` that is used in our serialization
/// and deserialization of the `PolicyEngine`
#[derive(Serialize, Deserialize, Debug)]
struct SerProposedAction {
    pub action: ActionMsg,
    pub policy_idx: usize,
    pub status: ProposedActionStatus,
    pub data: String,
}

/// A serializable version of `PolicyEngine` that is used in our serialization
/// and deserialization of the `PolicyEngine`
#[derive(Serialize, Deserialize, Debug)]
struct SerPolicyEngine {
    pub policies: Vec<Box<dyn Policy>>,
    pub proposed_actions: Vec<SerProposedAction>,
}

impl From<SerPolicyEngine> for PolicyEngine {
    fn from(ser_policy_engine: SerPolicyEngine) -> Self {
        let policies: Vec<PolicyRef> = ser_policy_engine
            .policies
            .into_iter()
            .map(|policy| Rc::new(RefCell::new(policy)))
            .collect();
        let proposed_actions: Vec<ProposedAction> = ser_policy_engine
            .proposed_actions
            .into_iter()
            .map(|proposed_action| ProposedAction {
                action: proposed_action.action,
                policy: policies[proposed_action.policy_idx].clone(),
                status: proposed_action.status,
                data: proposed_action.data,
            })
            .collect();
        PolicyEngine {
            policies,
            proposed_actions,
        }
    }
}

impl From<&PolicyEngine> for SerPolicyEngine {
    fn from(engine: &PolicyEngine) -> Self {
        // A vector of serializable policies
        let mut ser_policies: Vec<Box<dyn Policy>> = Vec::new();
        // Mapping of rc pointers to policies (as strings) to their index in
        // `ser_policies`
        let mut pointer_to_idx: BTreeMap<String, usize> = BTreeMap::new();
        // Construct the vector of policies
        for (i, policy) in engine.policies.iter().enumerate() {
            ser_policies.push(policy.borrow().get_policy_obj());
            pointer_to_idx.insert(format!("{:p}", *policy), i);
        }
        // Construct the vector of proposed actions
        let ser_prop_actions: Vec<SerProposedAction> = engine
            .proposed_actions
            .iter()
            .map(|proposed_action| SerProposedAction {
                action: proposed_action.action.clone(),
                policy_idx: *pointer_to_idx
                    .get(&format!("{:p}", proposed_action.policy))
                    .unwrap(),
                status: proposed_action.status,
                data: proposed_action.data.clone(),
            })
            .collect();

        // Construct the SerPolicyEngine
        SerPolicyEngine {
            policies: ser_policies,
            proposed_actions: ser_prop_actions,
        }
    }
}

/// Custom serialization for `PolicyEngine`, to be used with `serde_with`
pub fn policy_eng_serialize<S>(
    engine: &Rc<RefCell<PolicyEngine>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    // Construct the SerPolicyEngine
    let ser_policy_engine: SerPolicyEngine = engine.borrow().deref().into();
    serializer.serialize_bytes(&encode_to_bytes(&ser_policy_engine))
}

/// Custom deserialization for `PolicyEngine`, to be used with `serde_with`
pub fn policy_eng_deserialize<'a, D>(deserializer: D) -> Result<Rc<RefCell<PolicyEngine>>, D::Error>
where
    D: serde::Deserializer<'a>,
{
    let result = deserializer.deserialize_byte_buf(BytesVisitor)?;
    let ser_policy_engine: SerPolicyEngine =
        decode_from_bytes(&result).expect("could not decode policy engine");
    Ok(Rc::new(RefCell::new(ser_policy_engine.into())))
}
