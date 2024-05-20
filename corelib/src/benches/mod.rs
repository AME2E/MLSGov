use std::fs::File;

use futures::lock::Mutex;
use log::debug;
use serde::{Deserialize, Serialize};

use test1::BenchmarkOutput;

use crate::record_helper::time_since_epoch;
use crate::test1::benchmark;
use crate::test1::Test1TimerConfig::*;

pub(crate) mod batch_helper;
pub(crate) mod constants;
pub(crate) mod record_helper;

pub(crate) type Bandwidth = usize;

#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct Cost {
    duration_in_nanos: u128,
    bandwidth_in_bytes: Bandwidth,
}

#[cfg(test)]
mod test1 {
    use std::ops::DerefMut;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use futures::executor::block_on;
    use futures::lock::Mutex;
    use rand::distributions::{Alphanumeric, DistString};
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    use corelib::client_api::actions::{ActionMetadata, ActionMsg, RenameGroupAction};
    use corelib::client_api::{
        add_msg, create_group_msg, pre_add_invite_msg, send_group_state_update,
    };
    use corelib::messages::OnWireMessage;
    use corelib::servers_api::as_struct::AuthServiceState;
    use corelib::servers_api::ds_structs::DeliveryServiceState;
    use corelib::test_helpers::*;
    use corelib::{client_api, identity_to_str};

    use crate::{batch_helper::*, Cost};

    #[derive(Debug, PartialEq, Eq, PartialOrd, Clone, Copy)]
    pub(crate) enum Test1TimerConfig {
        TimeClientsInit,
        TimeClientsAsRegister,
        TimeClientsDsRegister,
        TimeClientsASKeySync,
        TimeAdminCreate,
        TimeAdminPreInvites,
        TimeAdminAdds,
        TimeClientPostAddSync,
        TimeAdminGroupStateUpdate,
        TimeClientsAccept,
        TimeClientPostAcceptSync,
        TimeAdminSendsMessage,
        TimeClientReceivesMessageSync,
        TimeAdminRenameGroup,
        TimeClientsPostRenameSync,
        All,
    }

    #[derive(Debug, Serialize, Deserialize, Default)]
    pub(crate) struct BenchmarkOutput {
        admin_pre_invite_last_member: Cost,
        admin_add_last_member: Cost,
        admin_group_state_update_after_last_member: Cost,
        admin_send_message: Cost,
        admin_rename_group: Cost,
    }

    pub(crate) fn benchmark(_section: Test1TimerConfig, group_size: usize) -> BenchmarkOutput {
        let mut output = BenchmarkOutput::default();

        // Initialize AS and DS.
        let ds_state = Arc::new(DeliveryServiceState::new());

        let as_state = Arc::new(AuthServiceState::new());

        let text = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
        let admin_index = 0usize;
        let enable_assert = false;

        // let section_start_timestamp = Instant::now();
        let mut client_bundles = create_test_bundles(group_size);

        // let client_init_time = section_start_timestamp.elapsed();
        // debug!("The client init time is {:?}", &client_init_time);
        // if section == TimeClientsInit {
        //     return vec![client_init_time];
        // }
        // times.push(client_init_time);

        // Register on AS
        // TimeClientAsRegister
        // let section_start_timestamp = Instant::now();
        let as_registers = register_all_as_msgs(&client_bundles);

        // let server_timestamp = Instant::now();
        let as_responses = block_on(as_process_all_msgs(as_registers, &as_state));
        // let server_time_used = server_timestamp.elapsed();

        let local_msgs = clients_process_all_msgs(as_responses, &mut client_bundles);

        // let client_as_reg_time = section_start_timestamp.elapsed() - server_time_used;
        // debug!(
        //     "Time for client to register on AS is {:?}",
        //     &client_as_reg_time
        // );
        // if section == TimeClientsAsRegister {
        //     return vec![client_as_reg_time];
        // }
        // times.push(client_as_reg_time);
        maybe_assert_all(local_msgs, enable_assert);

        // Register on DS
        // TimeClientDsRegister
        // let section_start_timestamp = Instant::now();
        let ds_registers = register_all_ds_msgs(&mut client_bundles);

        // let server_timestamp = Instant::now();
        let ds_responses = block_on(ds_process_all_msgs(ds_registers, &ds_state));
        // let server_time_used = server_timestamp.elapsed();

        let local_msgs = clients_process_all_msgs(ds_responses, &mut client_bundles);
        // let client_ds_reg_time = section_start_timestamp.elapsed() - server_time_used;
        // debug!(
        //     "Time for client to register on DS is {:?}",
        //     &client_ds_reg_time
        // );
        // if section == TimeClientsDsRegister {
        //     return vec![client_ds_reg_time];
        // }
        // times.push(client_ds_reg_time);
        maybe_assert_all(local_msgs, enable_assert);

        // Ensure Key Synced
        // TimeClientASKeySync
        // Ignoring Time Client generated OnWireMessage::UserSyncCredentials because trivial
        let sync_responses = block_on(get_all_sync_as_msgs(&mut client_bundles, &as_state));
        // let section_start_timestamp = Instant::now();
        let local_msgs = clients_process_all_msgs(sync_responses, &mut client_bundles);
        // let client_as_sync_time = section_start_timestamp.elapsed();
        // debug!("The client AS key sync time is {:?}", &client_as_sync_time);
        // if section == TimeClientsASKeySync {
        //     return vec![client_as_sync_time];
        // }
        // times.push(client_as_sync_time);
        maybe_assert_all(local_msgs, enable_assert);

        // Admin creates group
        // TimeAdminCreate
        // let section_start_timestamp = Instant::now();
        let admin = client_bundles.get_mut(admin_index).unwrap();
        let create_msg = create_group_msg(
            &admin.name(),
            &comm_grp(),
            &mut admin.backend,
            admin.configs.deref_mut(),
        );
        // let server_timestamp = Instant::now();
        let response = block_on(ds_process_msgs(create_msg, &ds_state));
        // let server_time_used = server_timestamp.elapsed();
        let local_msgs = admin.parse_msgs(&response);
        maybe_assert_all(vec![local_msgs], enable_assert);
        // let client_create_time = section_start_timestamp.elapsed() - server_time_used;
        // debug!("The client create time is {:?}", &client_create_time);
        // if section == TimeAdminCreate {
        //     return vec![client_create_time];
        // }
        // times.push(client_create_time);
        let mut admin_pre_inv_time = Duration::from_micros(0);
        let mut admin_pre_inv_bandwidth = 0usize;
        let mut admin_add_time = Duration::from_micros(0);
        let mut admin_add_bandwidth = 0usize;
        let mut admin_state_update_time = Duration::from_micros(0);
        let mut admin_state_update_bandwidth = 0usize;

        // Admin pre-invite
        let invitee_key_packages = pre_invite_keypackages(admin_index, &mut client_bundles);

        // TimeAdminPreInvites/TimeAdminAdds/TimeAdminGroupStateUpdate: three timers.
        let admin_bundle = client_bundles.get_mut(admin_index).unwrap();
        //debug!("----InviteTimePerNewInvitee csv format----\nInvitee,Invite_ProposeCommit_Time,Invite_Merge_Time,Add_ProposeCommit_Time,Add_Merge_Time,UpdateGroupState_ProposeCommit_Time,UpdateGroupState_Merge_Time");
        // let mut invite_times = vec![];
        for key_package in invitee_key_packages {
            admin_pre_inv_time = Duration::from_micros(0);
            admin_add_time = Duration::from_micros(0);
            admin_state_update_time = Duration::from_micros(0);

            let name = identity_to_str(key_package.credential().identity()).unwrap();
            // let mut invite_time = vec![];
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
                admin_pre_inv_time += section_start_timestamp.elapsed();
                // invite_time.push(section_start_timestamp.elapsed().as_micros());
                // Timer0-Pause
                admin_pre_inv_bandwidth = onwire_msgs_bandwidth(&msgs);
                let response = block_on(ds_process_msgs(msgs, &ds_state));
                // Timer0-Start
                let section_start_timestamp = Instant::now();
                let local_msgs = admin_bundle.parse_msgs(&response);
                admin_pre_inv_time += section_start_timestamp.elapsed();
                admin_pre_inv_bandwidth += onwire_msgs_bandwidth(&response);

                // invite_time.push(section_start_timestamp.elapsed().as_micros());
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
                admin_add_time += section_start_timestamp.elapsed();
                admin_add_bandwidth = onwire_msgs_bandwidth(&add);
                // Timer1-Paused
                // invite_time.push(section_start_timestamp.elapsed().as_micros());
                let response = block_on(ds_process_msgs(add, &ds_state));
                // Timer1-Start
                let section_start_timestamp = Instant::now();
                let local_msgs = admin_bundle.parse_msgs(&response);
                admin_add_time += section_start_timestamp.elapsed();
                admin_add_bandwidth += onwire_msgs_bandwidth(&response);

                // Timer1-Paused
                // invite_time.push(section_start_timestamp.elapsed().as_micros());
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
                admin_state_update_time = section_start_timestamp.elapsed();
                // Timer2-Paused
                // invite_time.push(section_start_timestamp.elapsed().as_micros());
                admin_state_update_bandwidth = onwire_msgs_bandwidth(&state_update);
                let response = block_on(ds_process_msgs(state_update, &ds_state));
                // Timer2-Start
                let section_start_timestamp = Instant::now();
                let local_msgs = admin_bundle.parse_msgs(&response);
                admin_state_update_time += section_start_timestamp.elapsed();
                admin_state_update_bandwidth += onwire_msgs_bandwidth(&response);

                // Timer2-Paused
                // invite_time.push(section_start_timestamp.elapsed().as_micros());
                // invite_times.push(invite_time);
                maybe_assert_all(vec![local_msgs], enable_assert);
            }
        }

        output.admin_pre_invite_last_member = Cost {
            duration_in_nanos: admin_pre_inv_time.as_nanos(),
            bandwidth_in_bytes: admin_pre_inv_bandwidth,
        };
        output.admin_add_last_member = Cost {
            duration_in_nanos: admin_add_time.as_nanos(),
            bandwidth_in_bytes: admin_add_bandwidth,
        };
        output.admin_group_state_update_after_last_member = Cost {
            duration_in_nanos: admin_state_update_time.as_nanos(),
            bandwidth_in_bytes: admin_state_update_bandwidth,
        };

        // write_u128s_list(
        //     format!(
        //         "Test1_Invite_results_{}mem_t{:?}.csvl",
        //         group_size,
        //         time_since_epoch()
        //     ),
        //     invite_times,
        // )
        // .expect("Cannnot save invite");
        // debug!(
        //     "The client pre-invite message generation time is {:?}",
        //     &client_pre_inv_time
        // );
        // debug!("The client add time is {:?}", &client_add_time);
        // debug!(
        //     "The client group state update time is {:?}",
        //     &client_data_update_time
        // );
        // if section == TimeAdminPreInvites {
        //     return vec![client_pre_inv_time];
        // }
        // times.push(client_pre_inv_time);
        // if section == TimeAdminGroupStateUpdate {
        //     return vec![client_data_update_time];
        // }
        // times.push(client_data_update_time);
        // if section == TimeAdminAdds {
        //     return vec![client_add_time];
        // }
        // times.push(client_add_time);

        let section_start_timestamp = Instant::now();
        let ds_syncs = sync_all_ds_msgs(&mut client_bundles);
        let server_timestamp = Instant::now();
        let ds_responses = block_on(ds_process_all_msgs(ds_syncs, &ds_state));
        let server_duration = server_timestamp.elapsed();
        let local_msgs = clients_process_all_msgs(ds_responses, &mut client_bundles);
        let _client_sync_time = section_start_timestamp.elapsed() - server_duration;
        maybe_assert_all(local_msgs, enable_assert);
        // debug!("The client sync time is {:?}", &client_sync_time);
        // if section == TimeClientPostAddSync {
        //     return vec![client_sync_time];
        // }
        // times.push(client_sync_time);

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
        let _local_msgs = clients_process_all_msgs(ds_responses, &mut client_bundles);
        let _client_accept_time = section_start_timestamp.elapsed() - server_duration;

        let section_start_timestamp = Instant::now();
        let ds_syncs = sync_all_ds_msgs(&mut client_bundles);
        let server_timestamp = Instant::now();
        let ds_responses = block_on(ds_process_all_msgs(ds_syncs, &ds_state));
        let server_duration = server_timestamp.elapsed();
        let local_msgs = clients_process_all_msgs(ds_responses, &mut client_bundles);
        let _client_sync2_time = section_start_timestamp.elapsed() - server_duration;
        maybe_assert_all(local_msgs, enable_assert);

        // Admin sends a group message
        //TimeClientSendsMessage
        let admin_bundle = client_bundles.get_mut(admin_index).unwrap();
        let section_start_timestamp = Instant::now();
        let client_for_ds_msgs2 = client_api::send_text_msg_mls(
            &admin_bundle.name(),
            &comm_grp(),
            text,
            &mut admin_bundle.backend,
            admin_bundle.configs.deref_mut(),
        );
        let outbound_bandwidth = onwire_msgs_bandwidth(&client_for_ds_msgs2);
        let server_timestamp = Instant::now();
        let ds_responses = block_on(ds_process_msgs(client_for_ds_msgs2, &ds_state));
        let server_duration = server_timestamp.elapsed();
        let _local_msgs = admin_bundle.parse_msgs(&ds_responses);
        let admin_send_msg_time = section_start_timestamp.elapsed() - server_duration;
        let inbound_bandwidth = onwire_msgs_bandwidth(&ds_responses);
        output.admin_send_message = Cost {
            duration_in_nanos: admin_send_msg_time.as_nanos(),
            bandwidth_in_bytes: outbound_bandwidth + inbound_bandwidth,
        };

        // Invitee receives all messages
        //     TimeClientReceivesMessageSync
        let ds_syncs = sync_all_ds_msgs(&mut client_bundles);
        let ds_responses = block_on(ds_process_all_msgs(ds_syncs, &ds_state));
        let local_msgs = clients_process_all_msgs(ds_responses, &mut client_bundles);
        maybe_assert_all(local_msgs, enable_assert);

        // Admin sends a rename message
        //TimeAdminRenameGroup
        let admin_bundle = client_bundles.get_mut(admin_index).unwrap();
        let section_start_timestamp = Instant::now();
        let renames = client_api::check_action_msg_and_get_mls(
            &comm_grp(),
            ActionMsg::RenameGroup(RenameGroupAction {
                new_name: "new_group_name".to_owned(),
                metadata: ActionMetadata {
                    sender: admin_bundle.name(),
                    action_id: Uuid::new_v4().to_string(),
                    community_group_id: comm_grp(),
                    data: "".to_string(),
                },
            }),
            &mut admin_bundle.backend,
            admin_bundle.configs.deref_mut(),
        );
        let server_timestamp = Instant::now();
        let outbound_bandwidth = onwire_msgs_bandwidth(&renames);
        let ds_responses = block_on(ds_process_msgs(renames, &ds_state));
        let server_duration = server_timestamp.elapsed();
        let _local_msgs = admin_bundle.parse_msgs(&ds_responses);
        let admin_rename_time = section_start_timestamp.elapsed() - server_duration;
        let inbound_bandwidth = onwire_msgs_bandwidth(&ds_responses);
        output.admin_rename_group = Cost {
            duration_in_nanos: admin_rename_time.as_nanos(),
            bandwidth_in_bytes: outbound_bandwidth + inbound_bandwidth,
        };
        // debug!("The admin rename sending time is {:?}", &admin_rename_time);
        // if section == TimeAdminRenameGroup {
        //     return vec![admin_rename_time];
        // }
        // times.push(admin_rename_time);

        // Invitee sync Renames
        //     TimeClientReceivesMessageSync
        // let section_start_timestamp = Instant::now();
        let ds_syncs = sync_all_ds_msgs(&mut client_bundles);
        // let server_timestamp = Instant::now();
        let ds_responses = block_on(ds_process_all_msgs(ds_syncs, &ds_state));
        // let server_duration = server_timestamp.elapsed();
        let local_msgs = clients_process_all_msgs(ds_responses, &mut client_bundles);
        // let client_sync4_time = section_start_timestamp.elapsed() - server_duration;
        maybe_assert_all(local_msgs, enable_assert);
        // debug!(
        //     "The client sync4 (post-admin-rename) time is {:?}",
        //     &client_sync4_time
        // );
        // if section == TimeClientsPostRenameSync {
        //     return vec![client_sync4_time];
        // }
        // times.push(client_sync4_time);
        // times

        output
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct AggregatedBenchmarkOutput {
    group_size: usize,
    outputs: Vec<BenchmarkOutput>,
}

fn main() {
    debug!("Running with `cargo bench` main() (which means optimized)");

    let mut final_output = vec![];
    for group_size in constants::GROUP_SIZES_TO_BENCHMARK {
        let mut outputs = vec![];
        println!("Running with group size of {}", group_size);
        for _i in 0..constants::REPEAT_PER_GROUP_SIZE {
            outputs.push(benchmark(All, group_size));
        }
        final_output.push(AggregatedBenchmarkOutput {
            group_size,
            outputs,
        });
    }

    serde_json::to_writer(
        &File::create(format!(
            "Test1_microbench_groupsizes_{:?}_t{}.json",
            constants::GROUP_SIZES_TO_BENCHMARK,
            time_since_epoch(),
        ))
        .unwrap(),
        &final_output,
    )
    .expect("failed to write output to file");
}

// criterion_group! {name = benches; config = Criterion::default()/*.measurement_time(Duration::from_secs(10)).sample_size(10)*/;targets = criterion_benchmark}
// criterion_main!(benches);
