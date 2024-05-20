use std::fs::File;
/// This file contains a macro-behcmark for a voting procedure
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::executor::block_on;
use futures::lock::Mutex;
use log::debug;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use corelib::client_api::actions::{
    ActionMetadata, ActionMsg, ActionType, RenameGroupAction, VoteAction,
};
use corelib::client_api::{add_msg, create_group_msg, pre_add_invite_msg, send_group_state_update};
use corelib::messages::OnWireMessage;
use corelib::policyengine::policies::VoteOnNameChangePolicy;
use corelib::servers_api::as_struct::AuthServiceState;
use corelib::servers_api::ds_structs::DeliveryServiceState;
use corelib::test_helpers::{comm_grp, onwire_msgs_bandwidth, TestClientBundle};
use corelib::{client_api, identity_to_str};

use crate::batch_helper::*;
use crate::record_helper::time_since_epoch;

static RENAME_ACTION_ID: &str = "rename_action_id";
static NEW_GROUP_NAME: &str = "new group name";
static YES_VOTE: &str = "yes";

mod batch_helper;
mod constants;
mod record_helper;

type Bandwidth = usize;

#[derive(Debug, Serialize, Deserialize, Default)]
struct Cost {
    duration_in_nanos: u128,
    bandwidth_in_bytes: Bandwidth,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct BenchmarkOutput {
    last_client_vote: Cost,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct AggregatedBenchmarkOutput {
    group_size: usize,
    outputs: Vec<BenchmarkOutput>,
}

// #[test]
fn test_vote(group_size: usize) -> BenchmarkOutput {
    // Starting with the code from the micro benchmarks
    // Initialize the group
    let ds_state = Arc::new(DeliveryServiceState::new());
    let as_state = Arc::new(AuthServiceState::new());

    let admin_index = 0usize;
    let rename_index = 1usize;
    assert!(group_size > 1);
    let enable_assert = false;

    let mut client_bundles = create_test_bundles(group_size);
    assert_eq!(client_bundles.len(), group_size);

    // Register on AS
    // TimeClientAsRegister
    let section_start_timestamp = Instant::now();
    let as_registers = register_all_as_msgs(&client_bundles);

    let server_timestamp = Instant::now();
    let as_responses = block_on(as_process_all_msgs(as_registers, &as_state));
    let server_time_used = server_timestamp.elapsed();

    let local_msgs = clients_process_all_msgs(as_responses, &mut client_bundles);

    let client_as_reg_time = section_start_timestamp.elapsed() - server_time_used;
    debug!(
        "Time for client to register on AS is {:?}",
        &client_as_reg_time
    );

    maybe_assert_all(local_msgs, enable_assert);

    // Register on DS
    // TimeClientDsRegister
    let section_start_timestamp = Instant::now();
    let ds_registers = register_all_ds_msgs(&mut client_bundles);

    let server_timestamp = Instant::now();
    let ds_responses = block_on(ds_process_all_msgs(ds_registers, &ds_state));
    let server_time_used = server_timestamp.elapsed();

    let local_msgs = clients_process_all_msgs(ds_responses, &mut client_bundles);
    let client_ds_reg_time = section_start_timestamp.elapsed() - server_time_used;
    debug!(
        "Time for client to register on DS is {:?}",
        &client_ds_reg_time
    );

    maybe_assert_all(local_msgs, enable_assert);

    // Ensure Key Synced
    // TimeClientASKeySync
    // Ignoring Time Client generated OnWireMessage::UserSyncCredentials because trivial
    let sync_responses = block_on(get_all_sync_as_msgs(&mut client_bundles, &as_state));
    let section_start_timestamp = Instant::now();
    let local_msgs = clients_process_all_msgs(sync_responses, &mut client_bundles);
    let client_as_sync_time = section_start_timestamp.elapsed();
    debug!("The client AS key sync time is {:?}", &client_as_sync_time);

    maybe_assert_all(local_msgs, enable_assert);

    // Admin creates group
    // TimeAdminCreate
    let section_start_timestamp = Instant::now();
    let admin = client_bundles.get_mut(admin_index).unwrap();

    // Set the voting for rename policy
    admin
        .configs
        .set_client_policies(vec![Box::new(VoteOnNameChangePolicy::new())]);

    let create_msg = create_group_msg(
        &admin.name(),
        &comm_grp(),
        &mut admin.backend,
        admin.configs.deref_mut(),
    );
    let server_timestamp = Instant::now();
    let response = block_on(ds_process_msgs(create_msg, &ds_state));
    let server_time_used = server_timestamp.elapsed();
    let local_msgs = admin.parse_msgs(&response);
    maybe_assert_all(vec![local_msgs], enable_assert);
    let client_create_time = section_start_timestamp.elapsed() - server_time_used;
    debug!("The client create time is {:?}", &client_create_time);

    // Admin pre-invite
    let invitee_key_packages = pre_invite_keypackages(admin_index, &mut client_bundles);

    // TimeAdminPreInvites/TimeAdminAdds/TimeAdminGroupStateUpdate: three timers.
    let mut client_pre_inv_time = Duration::from_micros(0);
    let mut client_add_time = Duration::from_micros(0);
    let mut client_data_update_time = Duration::from_micros(0);
    //debug!("----InviteTimePerNewInvitee csv format----\nInvitee,Invite_ProposeCommit_Time,Invite_Merge_Time,Add_ProposeCommit_Time,Add_Merge_Time,UpdateGroupState_ProposeCommit_Time,UpdateGroupState_Merge_Time");
    for key_package in invitee_key_packages {
        let name = identity_to_str(key_package.credential().identity()).unwrap();
        let admin_bundle = client_bundles.get_mut(admin_index).unwrap();
        if name.clone() != admin_bundle.name() {
            // ------Pre-Invite------
            // Timer0-Start
            let section_start_timestamp = Instant::now();
            let msgs = pre_add_invite_msg(
                &admin_bundle.name(),
                &comm_grp(),
                &mut admin_bundle.backend,
                admin_bundle.configs.deref_mut(),
                vec![key_package],
            );
            client_pre_inv_time += section_start_timestamp.elapsed();
            // print!(
            //     "{}, {:?}",
            //     name,
            //     section_start_timestamp.elapsed().as_micros()
            // );
            // Timer0-Pause
            let response = block_on(ds_process_msgs(msgs, &ds_state));
            // Timer0-Start
            let section_start_timestamp = Instant::now();
            let local_msgs = admin_bundle.parse_msgs(&response);
            client_pre_inv_time += section_start_timestamp.elapsed();
            // print!(", {:?}", section_start_timestamp.elapsed().as_micros());
            // Timer0-Pause
            maybe_assert_all(vec![local_msgs], enable_assert);

            // ------Add------
            // Timer1-Start
            let section_start_timestamp = Instant::now();
            let add = add_msg(
                &comm_grp(),
                &vec![name],
                admin_bundle.configs.deref_mut(),
                &mut admin_bundle.backend,
            );
            client_add_time += section_start_timestamp.elapsed();
            // Timer1-Paused
            // printl!(", {:?}", section_start_timestamp.elapsed().as_micros());
            //            debug!("Add messages for client {}: {:?}", &name, &add);

            let response = block_on(ds_process_msgs(add, &ds_state));
            // Timer1-Start
            let section_start_timestamp = Instant::now();
            let local_msgs = admin_bundle.parse_msgs(&response);
            client_add_time += section_start_timestamp.elapsed();
            // Timer1-Paused
            // print!(", {:?}", section_start_timestamp.elapsed().as_micros());
            maybe_assert_all(vec![local_msgs], enable_assert);

            // ------Group State Update------
            // Timer2-Start
            let section_start_timestamp = Instant::now();
            let state_update = send_group_state_update(
                &admin_bundle.name(),
                &comm_grp(),
                &mut admin_bundle.backend,
                admin_bundle.configs.deref_mut(),
            );
            client_data_update_time += section_start_timestamp.elapsed();
            // Timer2-Paused
            // print!(", {:?}", section_start_timestamp.elapsed().as_micros());
            let response = block_on(ds_process_msgs(state_update, &ds_state));
            // Timer2-Start
            let section_start_timestamp = Instant::now();
            let local_msgs = admin_bundle.parse_msgs(&response);
            client_data_update_time += section_start_timestamp.elapsed();
            // Timer2-Paused
            debug!(", {:?}", section_start_timestamp.elapsed().as_micros());
            maybe_assert_all(vec![local_msgs], enable_assert);

            // Try manual sync
            // let ds_syncs = sync_all_ds_msgs(&mut client_bundles[1..]);
            // let ds_responses = block_on(ds_process_all_msgs(ds_syncs, &ds_state, &ds_param));
        }
    }

    debug!(
        "The client pre-invite message generation time is {:?}",
        &client_pre_inv_time
    );
    debug!("The client add time is {:?}", &client_add_time);
    debug!(
        "The client group state update time is {:?}",
        &client_data_update_time
    );

    let section_start_timestamp = Instant::now();
    let ds_syncs = sync_all_ds_msgs(&mut client_bundles);
    // debug!("Here are the sync requests: {:?}", &ds_syncs);
    let server_timestamp = Instant::now();
    let ds_responses = block_on(ds_process_all_msgs(ds_syncs, &ds_state));
    // debug!("Here are the sync responses: {:?}", &ds_responses);
    let server_duration = server_timestamp.elapsed();
    let local_msgs = clients_process_all_msgs(ds_responses, &mut client_bundles);
    let client_sync_time = section_start_timestamp.elapsed() - server_duration;
    maybe_assert_all(local_msgs, enable_assert);
    debug!("The client sync time is {:?}", &client_sync_time);

    // Invitee accepts group invitation
    // TimeClientAccepts
    let section_start_timestamp = Instant::now();
    let accepts: Vec<Vec<OnWireMessage>> = client_bundles
        .iter_mut()
        .enumerate()
        .map(|(i, invitee)| {
            if i != admin_index {
                client_api::accept_msg(&comm_grp(), &mut invitee.backend, &mut invitee.configs)
            } else {
                vec![]
            }
        })
        .collect();
    let server_timestamp = Instant::now();
    let ds_responses = block_on(ds_process_all_msgs(accepts, &ds_state));
    let server_duration = server_timestamp.elapsed();
    let local_msgs = clients_process_all_msgs(ds_responses, &mut client_bundles);
    let client_accept_time = section_start_timestamp.elapsed() - server_duration;
    debug!("The clients accept time is {:?}", &client_accept_time);

    maybe_assert_all(local_msgs, enable_assert);

    {
        //Block to test if members' state are in sync
        let admin_bundle = client_bundles.get_mut(admin_index).unwrap();
        let admin_to_be_removed_members = admin_bundle
            .configs
            .get_shared_state(&comm_grp())
            .to_be_removed_members
            .to_owned();

        let admin_topic = admin_bundle
            .configs
            .get_shared_state(&comm_grp())
            .topic
            .to_owned();

        let admin_name = admin_bundle
            .configs
            .get_shared_state(&comm_grp())
            .name
            .to_owned();

        let admin_members = admin_bundle.configs.get_group_members(&comm_grp());

        for member in &client_bundles {
            assert_eq!(
                member
                    .configs
                    .get_shared_state(&comm_grp())
                    .to_be_removed_members,
                admin_to_be_removed_members
            );
            assert_eq!(
                member.configs.get_shared_state(&comm_grp()).topic,
                admin_topic
            );
            assert_eq!(
                member.configs.get_shared_state(&comm_grp()).name,
                admin_name
            );
            assert_eq!(member.configs.get_group_members(&comm_grp()), admin_members);
        }
    }

    let section_start_timestamp = Instant::now();
    let ds_syncs = sync_all_ds_msgs(&mut client_bundles);
    let server_timestamp = Instant::now();
    let ds_responses = block_on(ds_process_all_msgs(ds_syncs, &ds_state));
    let server_duration = server_timestamp.elapsed();
    let local_msgs = clients_process_all_msgs(ds_responses, &mut client_bundles);
    let client_sync2_time = section_start_timestamp.elapsed() - server_duration;
    maybe_assert_all(local_msgs, enable_assert);
    debug!(
        "The client sync2 (post-accepts) time is {:?}",
        &client_sync2_time
    );

    // Have a non-admin client attempt to rename the channel, triggering a
    // vote
    let rename_client_bundle = client_bundles.get_mut(rename_index).unwrap();
    let renames = gen_rename_message(rename_client_bundle);
    let ds_responses = block_on(ds_process_msgs(renames, &ds_state));
    // Process the DS response
    let _ = rename_client_bundle.parse_msgs(&ds_responses);

    // Have all clients sync so that they receive the rename message
    sync_all_clients(&mut client_bundles, &ds_state);

    // Initiate a sequence of votes, keeping track of the CPU time of the
    // last client to get their vote in
    let mut last_client_vec = vec![client_bundles.remove(group_size - 1)];

    let mut last_client_duration = Duration::default();
    let mut last_client_bandwidth_out = 0usize;
    let mut last_client_bandwidth_in = 0usize;

    for start_idx in 0..(group_size - 1) {
        // Clients from start_idx to last client cast their votes
        for vote_idx in start_idx..(group_size - 1) {
            let voting_client = client_bundles.get_mut(vote_idx).unwrap();
            client_cast_vote(voting_client, &ds_state);
        }

        // Last client casts their vote
        let (duration, bandwidth_out, bandwidth_in) =
            client_cast_vote(&mut last_client_vec[0], &ds_state);
        last_client_duration += duration;
        last_client_bandwidth_out += bandwidth_out;
        last_client_bandwidth_in += bandwidth_in;

        // Sync all but last client
        sync_all_clients(&mut client_bundles, &ds_state);

        // Sync last client
        let (duration, bandwidth_out, bandwidth_in) =
            sync_all_clients(&mut last_client_vec, &ds_state);
        last_client_duration += duration;
        last_client_bandwidth_out += bandwidth_out;
        last_client_bandwidth_in += bandwidth_in;
    }

    // Last client casts their vote
    let (duration, bandwidth_out, bandwidth_in) =
        client_cast_vote(&mut last_client_vec[0], &ds_state);
    debug!(
        "The bandwidth of a single vote is: {}",
        bandwidth_out + bandwidth_in
    );
    last_client_duration += duration;
    last_client_bandwidth_out += bandwidth_out;
    last_client_bandwidth_in += bandwidth_in;

    // Sync all but last client
    sync_all_clients(&mut client_bundles, &ds_state);

    // Sync last client
    let (duration, bandwidth_out, bandwidth_in) = sync_all_clients(&mut last_client_vec, &ds_state);
    last_client_duration += duration;
    last_client_bandwidth_out += bandwidth_out;
    last_client_bandwidth_in += bandwidth_in;
    debug!(
        "The bandwidth of a single sync is: {}",
        bandwidth_out + bandwidth_in
    );

    // Assert that all clients see the newly updated name
    println!("Asserting that all clients register the new name");
    for client in client_bundles.iter() {
        let group_name = client.configs.get_group_name(&comm_grp());
        assert_eq!(group_name, NEW_GROUP_NAME);
    }

    // Report the overall time the last client spent
    debug!(
        "The computational cost of the last client was {:?}",
        last_client_duration
    );
    // debug!(
    //     "The bandwidth cost for the last client was {} bytes, which is {}",
    //     last_client_bandwidth,
    //     last_client_bandwidth.bytes().to_string()
    // );
    BenchmarkOutput {
        last_client_vote: Cost {
            duration_in_nanos: last_client_duration.as_nanos(),
            bandwidth_in_bytes: last_client_bandwidth_in + last_client_bandwidth_out,
        },
    }
}

/// Casts a vote for the current client and returns a Duration for how much
/// computational time was spent on the client to cast the vote along with
/// the bandwidth incurred.
fn client_cast_vote(
    client_bundle: &mut TestClientBundle,
    ds_state: &Arc<DeliveryServiceState>,
) -> (Duration, usize, usize) {
    let mut _bandwidth: usize = 0;
    let section_start_timestamp = Instant::now();
    let msgs = client_api::check_action_msg_and_get_mls(
        &comm_grp(),
        ActionMsg::Vote(VoteAction {
            vote_value: YES_VOTE.to_string(),
            proposed_action_id: RENAME_ACTION_ID.to_string(),
            proposed_action_type: ActionType::RenameGroup,
            metadata: ActionMetadata {
                sender: client_bundle.name(),
                action_id: Uuid::new_v4().to_string(),

                community_group_id: comm_grp(),
                data: "".to_string(),
            },
        }),
        &mut client_bundle.backend,
        client_bundle.configs.deref_mut(),
    );
    let server_timestamp = Instant::now();
    let outbound_bandwidth = onwire_msgs_bandwidth(&msgs);
    debug!("The outbound bandwidth is {outbound_bandwidth}");
    _bandwidth += outbound_bandwidth;
    let ds_responses = block_on(ds_process_msgs(msgs, ds_state));
    let inbound_bandwidth = onwire_msgs_bandwidth(&ds_responses);
    debug!("The inbound bandwidth is {inbound_bandwidth}");
    _bandwidth += inbound_bandwidth;
    let server_duration = server_timestamp.elapsed();
    let _ = client_bundle.parse_msgs(&ds_responses);
    (
        section_start_timestamp.elapsed() - server_duration,
        outbound_bandwidth,
        inbound_bandwidth,
    )
}

/// Handles synchrnoization for all clients specified in `client_bundles`
/// Returns the duration of client-side request generation and response
/// processing along with the bandwidth incurred
fn sync_all_clients(
    client_bundles: &mut Vec<TestClientBundle>,
    ds_state: &Arc<DeliveryServiceState>,
) -> (Duration, usize, usize) {
    let section_start_timestamp = Instant::now();
    let ds_syncs = sync_all_ds_msgs(client_bundles);
    let server_timestamp = Instant::now();
    let _bandwidth: usize = 0;
    let bandwidth_out = ds_syncs.iter().map(onwire_msgs_bandwidth).sum::<usize>();
    let ds_responses = block_on(ds_process_all_msgs(ds_syncs, ds_state));
    let bandwidth_in = ds_responses
        .iter()
        .map(onwire_msgs_bandwidth)
        .sum::<usize>();
    let server_duration = server_timestamp.elapsed();
    let _ = clients_process_all_msgs(ds_responses, client_bundles);

    (
        section_start_timestamp.elapsed() - server_duration,
        bandwidth_out,
        bandwidth_in,
    )
}

/// Generate the rename message
fn gen_rename_message(client_bundle: &mut TestClientBundle) -> Vec<OnWireMessage> {
    client_api::check_action_msg_and_get_mls(
        &comm_grp(),
        ActionMsg::RenameGroup(RenameGroupAction {
            new_name: NEW_GROUP_NAME.to_owned(),
            metadata: ActionMetadata {
                sender: client_bundle.name(),
                action_id: RENAME_ACTION_ID.to_string(),

                data: "".to_string(),
                community_group_id: comm_grp(),
            },
        }),
        &mut client_bundle.backend,
        client_bundle.configs.deref_mut(),
    )
}

fn main() {
    println!("Starting voting benchmark");

    let mut final_output = vec![];
    for group_size in constants::GROUP_SIZES_TO_BENCHMARK {
        let mut outputs = vec![];
        println!("Running with group size of {}", group_size);
        for _i in 0..constants::REPEAT_PER_GROUP_SIZE {
            outputs.push(test_vote(group_size));
        }
        final_output.push(AggregatedBenchmarkOutput {
            group_size,
            outputs,
        });
    }
    serde_json::to_writer(
        &File::create(format!(
            "Test1_vote_groupsizes_{:?}_t{}.json",
            constants::GROUP_SIZES_TO_BENCHMARK,
            time_since_epoch(),
        ))
        .unwrap(),
        &final_output,
    )
    .expect("failed to write output to file");
}
