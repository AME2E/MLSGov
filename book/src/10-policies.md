# Policies

Here, we describe how extended governance functionality can be articulated
by developers through our policy interface. Our notion of policies draws
heavily upon those described in the [PolicyKit](https://dl.acm.org/doi/abs/10.1145/3379337.3415858) paper. The core of the
policy execution logic is defined [here](https://github.com/policykit/policykit/blob/f791bc36c747015ad2dd2186ab3d9eb9600a58cf/policykit/policyengine/engine.py).

At a high level, we have a *policy engine*, part of the client code, that
interposes on incoming and outgoing platform actions. Currently, policies
are defined at the creation time of a group and remain active throughout
the lifetime of a community. If an action does not immediately pass,
according to the RBAC primitive, it is evaluated against all policies (in a
developer-defined deterministic order), and if any policy passes the
action, the action is allowed to execute. Actions can also be placed in a
proposed state, in the case of policies that involve some sort of
asynchronous approval process (for instance, voting). Proposed platform
actions are saved by the policy engine, which will periodically attempt to
re-evaluate the proposed action against all policies. This re-evaluation
can also occur in a notification-based manner (e.g., with every incoming
ordered application message). If the action for a user is unauthorized
(according to the RBAC) and no policy matching the action puts the action
in a passed or proposed state, the action is discarded.

## The policy API

The policy engine is implemented in the `corelib/src/policyengine` module. The key components are:

- `Policy` trait: Defines the interface that all policies must implement. Drawing upon the approach to policies in PolicyKit, each of our policies defines each of the following functions:
  - `filter`: Returns true if an action is relevant to this policy.
  - `check`: Evaluates an action and returns its status (Passed, Failed, Proposed).
  - `pass`, `fail`: Executes any side effects of passing or failing an action.
- `PolicyEngine` struct: Manages the list of active policies and the queue of proposed actions. Key methods:
  - `evaluate_action`: Evaluates a new action against all policies. Adds to proposed queue if needed.
  - `evaluate_all_proposed_actions`: Re-evaluates all proposed actions against all policies.
- `ProposedAction` struct: Represents an action in the proposed state, along with the policy that proposed it.

## Policy Engine Integration

The policy engine is integrated into the client in the `ClientData` struct (`corelib/src/client_api/client_struct_impl.rs`):

- The `policy_engine` field stores the engine instance.
- The `set_client_policies` method sets the list of active policies at group creation time.
- The `check_action_msg_and_get_mls` function in `corelib/src/client_api/mod.rs`, which is called to send any action message, passes the action through `policy_engine.evaluate_action`.
- The `parse_incoming_onwire_msgs` function, which processes incoming messages, calls `policy_engine.evaluate_all_proposed_actions` after processing each batch of messages.

## Example policies

Some example policies implemented in `corelib/src/policyengine/policies.rs`:

- `VoteOnNameChangePolicy`: Requires a majority vote to approve a `RenameGroup` action. Uses the proposed action queue to track votes.
- `ReputationNameChangePolicy`: Allows `RenameGroup` only for users with sufficient reputation. Reputation can be modified via a `ReputationChangeAction` custom action.

The policies make use of helper functions on `ClientData` to access and modify group state as needed to implement their logic.