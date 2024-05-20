#[cfg(all(test, features = "gov"))]
mod integrated_test {
    use std::ops::DerefMut;
    use std::sync::Arc;

    use rand::distributions::{Alphanumeric, DistString};

    use crate::client_api::actions::{ActionMetadata, ActionMsg, RenameGroupAction};
    use crate::client_api::{self, check_action_msg_and_get_mls, parse_incoming_onwire_msgs};
    use crate::servers_api::as_struct::AuthServiceState;
    use crate::servers_api::ds_structs::DeliveryServiceState;
    use crate::servers_api::{self};
    use crate::test_helpers::*;

    #[actix_rt::test]
    /// Simulate
    /// an admin registers,
    ///         creates a group,
    ///         invites a newly registered member,
    ///         send a message
    /// test that they both receive the message.
    /// Then the invitee can leave the group successfully
    ///
    /// Does assume that in sync, the first message returned from the server
    /// is the [DSUserMsg] (if any) rather than a [DSResult]
    async fn test_client_and_server_api1() {
        let ds_state = Arc::new(DeliveryServiceState::new());

        let as_state = Arc::new(AuthServiceState::new());
        let mut admin = TestClientBundle::new("GroupAdmin");
        let mut invitee = TestClientBundle::new("Invitee");

        let text = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);

        // Register on AS
        let admin_for_as_msgs = client_api::register_msg_as(
            admin.credential().to_owned(),
            admin.configs.get_keypair().public_key(),
        );
        let invitee_for_as_msg = client_api::register_msg_as(
            invitee.credential().to_owned(),
            invitee.configs.get_keypair().public_key(),
        );
        for admin_msg in admin_for_as_msgs {
            let msgs = servers_api::handle_onwire_msg_as_local(admin_msg, &as_state).await;
            assert_all_feedback_ok(&parse_incoming_onwire_msgs(
                msgs,
                &mut admin.configs,
                &mut admin.backend,
            ));
        }
        for msg in invitee_for_as_msg {
            let msgs = servers_api::handle_onwire_msg_as_local(msg, &as_state).await;
            assert_all_feedback_ok(&parse_incoming_onwire_msgs(
                msgs,
                &mut invitee.configs,
                &mut invitee.backend,
            ));
        }

        // Register on DS
        let clients_for_ds_msgs0 = flatten(vec![
            client_api::register_msg_ds(admin.new_kps(5)),
            client_api::register_msg_ds(invitee.new_kps(5)),
        ]);

        for client_msg in clients_for_ds_msgs0 {
            let _ = servers_api::handle_onwire_msg_ds_local(client_msg, &ds_state).await;
        }

        // Ensure Key Synced
        admin.sync_as_assert_ok(&as_state).await;
        invitee.sync_as_assert_ok(&as_state).await;

        // Admin creates group and pre-invite
        let admin_for_ds_msgs1 = flatten(vec![
            client_api::create_group_msg(
                &admin.name(),
                &comm_grp(),
                &mut admin.backend,
                admin.configs.deref_mut(),
            ),
            client_api::pre_add_invite_msg(
                &admin.name(),
                &comm_grp(),
                &mut admin.backend,
                admin.configs.deref_mut(),
                invitee.new_key_package(),
            ),
        ]);
        admin
            .send_all_assert_ok(admin_for_ds_msgs1, &ds_state)
            .await;

        // Admin adds invitee
        let admin_for_ds_msgs2 = flatten(vec![client_api::add_msg(
            &comm_grp(),
            &invitee.name(),
            admin.configs.deref_mut(),
            &mut admin.backend,
        )]);
        admin
            .send_all_assert_ok(admin_for_ds_msgs2, &ds_state)
            .await;

        // Admin shares group state
        let admin_for_ds_msgs3 = flatten(vec![client_api::send_group_state_update(
            &admin.name(),
            &comm_grp(),
            &mut admin.backend,
            admin.configs.deref_mut(),
        )]);
        admin
            .send_all_assert_ok(admin_for_ds_msgs3, &ds_state)
            .await;

        invitee.sync_ds_assert_ok(&ds_state).await;

        // Invitee accepts group invitation
        let invitee_for_ds_msgs2 = flatten(vec![client_api::accept_msg(
            &comm_grp(),
            &mut invitee.backend,
            &mut invitee.configs,
        )]);
        invitee
            .send_all_assert_ok(invitee_for_ds_msgs2, &ds_state)
            .await;

        admin.sync_ds_assert_ok(&ds_state).await;

        // Admin sends a group message
        let client_for_ds_msgs2 = flatten(vec![client_api::send_text_msg_mls(
            &admin.name(),
            &comm_grp(),
            text.to_owned(),
            &mut admin.backend,
            admin.configs.deref_mut(),
        )]);
        admin
            .send_all_assert_ok(client_for_ds_msgs2, &ds_state)
            .await;

        //Test if the message appear in synced message of invitee's client
        let invitee_sync_response = parse_incoming_onwire_msgs(
            servers_api::handle_onwire_msg_ds_local(
                sync_msg(invitee.name(), vec![])[0].to_owned(),
                &ds_state,
            )
            .await,
            &mut invitee.configs,
            &mut invitee.backend,
        );
        assert!(concat_string_in_decrypted_msgs(invitee_sync_response).contains(&text));

        invitee.sync_ds_assert_ok(&ds_state).await;

        // Now invitee should be able to leave the group
        let invitee_for_ds_msgs2 = client_api::pre_leave_msg(
            &comm_grp(),
            &mut invitee.backend,
            invitee.configs.deref_mut(),
        );

        invitee
            .send_all_assert_ok(invitee_for_ds_msgs2, &ds_state)
            .await;

        let invitee_for_ds_msgs3 = client_api::remove_other_or_self_msg(
            &comm_grp(),
            &invitee.name(),
            &mut invitee.backend,
            invitee.configs.deref_mut(),
        );
        invitee
            .send_all_assert_ok(invitee_for_ds_msgs3, &ds_state)
            .await;

        let admin_for_ds_msgs4 = flatten(vec![
            sync_msg(admin.name(), admin.new_kps(5)),
            client_api::send_text_msg_mls(
                &admin.name(),
                &comm_grp(),
                text.to_owned(),
                &mut admin.backend,
                admin.configs.deref_mut(),
            ),
        ]);

        admin
            .send_all_assert_ok(admin_for_ds_msgs4, &ds_state)
            .await;
    }

    #[actix_rt::test]
    /// Simulate (same as test_client_and_server_api1 except admin and client2 try to kick each other)
    /// an admin registers,
    ///         creates a group,
    ///         invites a newly registered member,
    ///         send a message
    /// test that they both receive the message.
    /// (not happening)Then the invitee cannot kick admin from the group
    /// Then the invitee can be kicked from the group successfully by admin
    ///
    /// Does assume that in sync, the first message returned from the server
    /// is the [DSUserMsg] (if any) rather than a [DSResult]
    async fn test_client_and_server_api2() {
        let ds_state = Arc::new(DeliveryServiceState::new());

        let as_state = Arc::new(AuthServiceState::new());
        let mut admin = TestClientBundle::new("GroupAdmin");
        let mut invitee = TestClientBundle::new("Invitee");

        let text = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
        let text2 = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);

        // First user and invitee register, create a group, and send a message
        // Register on AS
        let admin_for_as_msgs = client_api::register_msg_as(
            admin.credential().to_owned(),
            admin.configs.get_keypair().public_key(),
        );
        let invitee_for_as_msg = client_api::register_msg_as(
            invitee.credential().to_owned(),
            invitee.configs.get_keypair().public_key(),
        );
        for admin_msg in admin_for_as_msgs {
            let msgs = servers_api::handle_onwire_msg_as_local(admin_msg, &as_state).await;
            assert_all_feedback_ok(&parse_incoming_onwire_msgs(
                msgs,
                &mut admin.configs,
                &mut admin.backend,
            ));
        }
        for msg in invitee_for_as_msg {
            let msgs = servers_api::handle_onwire_msg_as_local(msg, &as_state).await;
            assert_all_feedback_ok(&parse_incoming_onwire_msgs(
                msgs,
                &mut invitee.configs,
                &mut invitee.backend,
            ));
        }

        let clients_for_ds_msgs0 = flatten(vec![
            client_api::register_msg_ds(admin.new_kps(5)),
            client_api::register_msg_ds(invitee.new_kps(5)),
        ]);

        let admin_for_ds_msgs1 = flatten(vec![
            client_api::create_group_msg(
                &admin.name(),
                &comm_grp(),
                &mut admin.backend,
                admin.configs.deref_mut(),
            ),
            client_api::pre_add_invite_msg(
                &admin.name(),
                &comm_grp(),
                &mut admin.backend,
                admin.configs.deref_mut(),
                invitee.new_key_package(),
            ),
            sync_msg(admin.name(), admin.new_kps(5)),
        ]);

        // AS registration

        // DS registration
        for client_msg in clients_for_ds_msgs0 {
            let _ = servers_api::handle_onwire_msg_ds_local(client_msg, &ds_state).await;
        }

        admin
            .send_all_assert_ok(admin_for_ds_msgs1, &ds_state)
            .await;

        admin.sync_as_assert_ok(&as_state).await;
        invitee.sync_as_assert_ok(&as_state).await;

        let admin_for_ds_msgs2 = flatten(vec![client_api::add_msg(
            &comm_grp(),
            &invitee.name(),
            admin.configs.deref_mut(),
            &mut admin.backend,
        )]);
        admin
            .send_all_assert_ok(admin_for_ds_msgs2, &ds_state)
            .await;
        let admin_for_ds_msgs2 = flatten(vec![client_api::send_group_state_update(
            &admin.name(),
            &comm_grp(),
            &mut admin.backend,
            admin.configs.deref_mut(),
        )]);
        admin
            .send_all_assert_ok(admin_for_ds_msgs2, &ds_state)
            .await;

        let invitee_for_ds_msgs1 = flatten(vec![sync_msg(invitee.name(), invitee.new_kps(1))]);

        invitee
            .send_all_assert_ok(invitee_for_ds_msgs1, &ds_state)
            .await;

        let invitee_for_ds_msgs2 = flatten(vec![client_api::accept_msg(
            &comm_grp(),
            &mut invitee.backend,
            &mut invitee.configs,
        )]);

        invitee
            .send_all_assert_ok(invitee_for_ds_msgs2, &ds_state)
            .await;

        admin.sync_ds_assert_ok(&ds_state).await;

        let client_for_ds_msgs2 = client_api::send_text_msg_mls(
            &admin.name(),
            &comm_grp(),
            text.to_owned(),
            &mut admin.backend,
            admin.configs.deref_mut(),
        );

        admin
            .send_all_assert_ok(client_for_ds_msgs2, &ds_state)
            .await;

        //Test if the message appear in synced message of [invitee.name]
        let invitee_sync_response = parse_incoming_onwire_msgs(
            servers_api::handle_onwire_msg_ds_local(
                sync_msg(invitee.name(), vec![])[0].to_owned(),
                &ds_state,
            )
            .await,
            &mut invitee.configs,
            &mut invitee.backend,
        );

        assert!(concat_string_in_decrypted_msgs(invitee_sync_response).contains(&text));

        invitee.sync_ds_assert_ok(&ds_state).await;

        admin.sync_ds_assert_ok(&ds_state).await;

        // Now invitee should not be able to kick admin from the group
        // TODO not sure how to do this
        // let r = servers_api::handle_app_msg_delivery_local(
        //     client_api::pre_kick_msg(
        //         &c(),
        //         &g(),
        //         &admin.name(),
        //         &mut invitee.backend,
        //         &mut invitee.configs,
        //     )[0]
        //     .clone(),
        //     &ds_state,
        //     &ds_param,
        // )
        // .await;
        //
        // assert!(matches!(
        //     r[0],
        //     OnWireMessage::DSResult {
        //         request_valid: false,
        //         ..
        //     }
        // ));

        // Now admin should be able to kick invitee from the group

        let admin_for_ds_msgs3 = client_api::pre_kick_msg(
            &comm_grp(),
            &invitee.name(),
            &mut admin.backend,
            admin.configs.deref_mut(),
        );
        admin
            .send_all_assert_ok(admin_for_ds_msgs3, &ds_state)
            .await;

        let admin_for_ds_msgs4 = client_api::remove_other_or_self_msg(
            &comm_grp(),
            &invitee.name(),
            &mut admin.backend,
            admin.configs.deref_mut(),
        );
        admin
            .send_all_assert_ok(admin_for_ds_msgs4, &ds_state)
            .await;

        // Assert the invitee's name is removed in admin's member list.
        assert!(!admin
            .configs
            .get_group_members(&comm_grp())
            .contains(&invitee.name));

        let admin_for_ds_msgs5 = client_api::send_text_msg_mls(
            &admin.name(),
            &comm_grp(),
            text2.to_owned(),
            &mut admin.backend,
            admin.configs.deref_mut(),
        );
        admin
            .send_all_assert_ok(admin_for_ds_msgs5, &ds_state)
            .await;

        //Test if the message appear in synced message of [invitee.name] (it shouldn't)
        let invitee_sync_response2 = parse_incoming_onwire_msgs(
            servers_api::handle_onwire_msg_ds_local(
                sync_msg(invitee.name(), vec![])[0].to_owned(),
                &ds_state,
            )
            .await,
            &mut invitee.configs,
            &mut invitee.backend,
        );
        assert!(!concat_string_in_decrypted_msgs(invitee_sync_response2).contains(&text2));
    }

    #[actix_rt::test]
    /// Simulate
    /// an admin registers,
    ///         creates a group,
    ///         invites a newly registered member,
    ///         send a message
    /// test that they both receive the message.
    /// Then the invitee can leave the group successfully
    ///
    /// Does assume that in sync, the first message returned from the server
    /// is the [DSUserMsg] (if any) rather than a [DSResult]
    async fn test_client_conflict_resolution_invites() {
        let ds_state = Arc::new(DeliveryServiceState::new());

        let as_state = Arc::new(AuthServiceState::new());
        let mut admin = TestClientBundle::new("GroupAdmin");
        let mut invitee = TestClientBundle::new("Invitee");
        let mut invitee2 = TestClientBundle::new("Invitee2");

        // ----------
        // All users register, and admin creates new group
        // Messages
        let admin_for_as_msgs = flatten(vec![client_api::register_msg_as(
            admin.credential().to_owned(),
            admin.configs.get_keypair().public_key(),
        )]);
        let invitee_for_as_msgs = client_api::register_msg_as(
            invitee.credential().to_owned(),
            invitee.configs.get_keypair().public_key(),
        );
        let invitee2_for_as_msgs = client_api::register_msg_as(
            invitee2.credential().to_owned(),
            invitee2.configs.get_keypair().public_key(),
        );
        for admin_msg in admin_for_as_msgs {
            let msgs = servers_api::handle_onwire_msg_as_local(admin_msg, &as_state).await;
            assert_all_feedback_ok(&parse_incoming_onwire_msgs(
                msgs,
                &mut admin.configs,
                &mut admin.backend,
            ));
        }
        for msg in invitee_for_as_msgs {
            let msgs = servers_api::handle_onwire_msg_as_local(msg, &as_state).await;
            assert_all_feedback_ok(&parse_incoming_onwire_msgs(
                msgs,
                &mut invitee.configs,
                &mut invitee.backend,
            ));
        }
        for msg in invitee2_for_as_msgs {
            let msgs = servers_api::handle_onwire_msg_as_local(msg, &as_state).await;
            assert_all_feedback_ok(&parse_incoming_onwire_msgs(
                msgs,
                &mut invitee2.configs,
                &mut invitee2.backend,
            ));
        }

        let clients_for_ds_msgs0 = flatten(vec![
            client_api::register_msg_ds(admin.new_kps(5)),
            client_api::register_msg_ds(invitee.new_kps(5)),
            client_api::register_msg_ds(invitee2.new_kps(5)),
        ]);

        let admin_for_ds_msgs1 = flatten(vec![
            client_api::create_group_msg(
                &admin.name(),
                &comm_grp(),
                &mut admin.backend,
                admin.configs.deref_mut(),
            ),
            client_api::pre_add_invite_msg(
                &admin.name(),
                &comm_grp(),
                &mut admin.backend,
                admin.configs.deref_mut(),
                invitee.new_key_package(),
            ),
            sync_msg(admin.name(), admin.new_kps(1)),
        ]);

        // Send to DS
        for client_msg in clients_for_ds_msgs0 {
            let _ = servers_api::handle_onwire_msg_ds_local(client_msg, &ds_state).await;
        }

        admin
            .send_all_assert_ok(admin_for_ds_msgs1, &ds_state)
            .await;

        admin.sync_as_assert_ok(&as_state).await;
        invitee.sync_as_assert_ok(&as_state).await;
        invitee2.sync_as_assert_ok(&as_state).await;

        let admin_for_ds_msgs2 = flatten(vec![client_api::add_msg(
            &comm_grp(),
            &invitee.name(),
            admin.configs.deref_mut(),
            &mut admin.backend,
        )]);
        admin
            .send_all_assert_ok(admin_for_ds_msgs2, &ds_state)
            .await;

        let admin_for_ds_msgs3 = flatten(vec![client_api::send_group_state_update(
            &admin.name(),
            &comm_grp(),
            &mut admin.backend,
            admin.configs.deref_mut(),
        )]);
        admin
            .send_all_assert_ok(admin_for_ds_msgs3, &ds_state)
            .await;

        invitee.sync_ds_assert_ok(&ds_state).await;

        // ---------
        // Now [invitee] accepts the invite, and both [admin] and [invitee] race to invite [invitee2]

        let invitees_accept_admin_invite_msgs = flatten(vec![client_api::accept_msg(
            &comm_grp(),
            &mut invitee.backend,
            &mut invitee.configs,
        )]);
        invitee
            .send_all_assert_ok(invitees_accept_admin_invite_msgs, &ds_state)
            .await;

        let admin_invites_invitee2_msgs = flatten(vec![client_api::pre_add_invite_msg(
            &admin.name(),
            &comm_grp(),
            &mut admin.backend,
            admin.configs.deref_mut(),
            invitee2.new_key_package(),
        )]);
        admin
            .send_all_assert_ok(admin_invites_invitee2_msgs, &ds_state)
            .await;

        let invitee_invites_invitee2_msgs = flatten(vec![client_api::pre_add_invite_msg(
            &invitee.name(),
            &comm_grp(),
            &mut invitee.backend,
            invitee.configs.deref_mut(),
            invitee2.new_key_package(),
        )]);
        // Would not pass because conflict. Assert will panic
        for msg in invitee_invites_invitee2_msgs {
            invitee.send_and_parse(msg, &ds_state).await;
        }

        admin.sync_ds_assert_ok(&ds_state).await;
        invitee.sync_ds_assert_ok(&ds_state).await;

        let admin_for_ds_msgs2 = flatten(vec![client_api::add_msg(
            &comm_grp(),
            &invitee2.name(),
            admin.configs.deref_mut(),
            &mut admin.backend,
        )]);
        admin
            .send_all_assert_ok(admin_for_ds_msgs2, &ds_state)
            .await;
        // Admin shares group state
        let admin_for_ds_msgs3 = flatten(vec![client_api::send_group_state_update(
            &admin.name(),
            &comm_grp(),
            &mut admin.backend,
            admin.configs.deref_mut(),
        )]);
        admin
            .send_all_assert_ok(admin_for_ds_msgs3, &ds_state)
            .await;

        //Test if the both clients handle things successfully
        admin.sync_ds_assert_ok(&ds_state).await;

        invitee.sync_ds_assert_ok(&ds_state).await;

        assert_credential_exist_in_config(
            invitee.configs.deref_mut(),
            &comm_grp(),
            invitee2.credential(),
        );

        assert_credential_exist_in_config(
            admin.configs.deref_mut(),
            &comm_grp(),
            invitee2.credential(),
        );
    }

    #[actix_rt::test]
    async fn test_client_conflict_resolution_name_changes() {
        let ds_state = Arc::new(DeliveryServiceState::new());

        let as_state = Arc::new(AuthServiceState::new());
        let mut admin = TestClientBundle::new("GroupAdmin");
        let mut invitee = TestClientBundle::new("Invitee");

        let _text = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);

        // ----------
        // All users register, and admin creates new group
        // Messages
        let clients_register_as_msgs = flatten(vec![
            client_api::register_msg_as(
                admin.credential().to_owned(),
                admin.configs.get_keypair().public_key(),
            ),
            client_api::register_msg_as(
                invitee.credential().to_owned(),
                invitee.configs.get_keypair().public_key(),
            ),
        ]);

        for msg in clients_register_as_msgs {
            let msgs = servers_api::handle_onwire_msg_as_local(msg, &as_state).await;
            assert_all_feedback_ok(&parse_incoming_onwire_msgs(
                msgs,
                &mut admin.configs,
                &mut admin.backend,
            ));
        }

        let clients_register_ds_msgs = flatten(vec![
            client_api::register_msg_ds(admin.new_kps(5)),
            client_api::register_msg_ds(invitee.new_kps(5)),
        ]);

        for client_msg in clients_register_ds_msgs {
            let _ = servers_api::handle_onwire_msg_ds_local(client_msg, &ds_state).await;
        }

        admin.sync_as_assert_ok(&as_state).await;
        invitee.sync_as_assert_ok(&as_state).await;

        let admin_creates_and_invites_msgs = flatten(vec![
            client_api::create_group_msg(
                &admin.name(),
                &comm_grp(),
                &mut admin.backend,
                admin.configs.deref_mut(),
            ),
            client_api::pre_add_invite_msg(
                &admin.name(),
                &comm_grp(),
                &mut admin.backend,
                admin.configs.deref_mut(),
                invitee.new_key_package(),
            ),
            sync_msg(admin.name(), admin.new_kps(1)),
        ]);

        admin
            .send_all_assert_ok(admin_creates_and_invites_msgs, &ds_state)
            .await;

        let admin_for_ds_msgs2 = flatten(vec![client_api::add_msg(
            &comm_grp(),
            &invitee.name(),
            admin.configs.deref_mut(),
            &mut admin.backend,
        )]);

        admin
            .send_all_assert_ok(admin_for_ds_msgs2, &ds_state)
            .await;

        let admin_for_ds_msgs3 = flatten(vec![client_api::send_group_state_update(
            &admin.name(),
            &comm_grp(),
            &mut admin.backend,
            admin.configs.deref_mut(),
        )]);
        admin
            .send_all_assert_ok(admin_for_ds_msgs3, &ds_state)
            .await;

        invitee.sync_ds_assert_ok(&ds_state).await;

        admin.sync_ds_assert_ok(&ds_state).await;

        let invitees_accept_admin_invite_msgs = flatten(vec![client_api::accept_msg(
            &comm_grp(),
            &mut invitee.backend,
            &mut invitee.configs,
        )]);
        invitee
            .send_all_assert_ok(invitees_accept_admin_invite_msgs, &ds_state)
            .await;
        admin.sync_ds_assert_ok(&ds_state).await;

        let promote_msgs = client_api::set_role_msg(
            &comm_grp(),
            &invitee.name(),
            "Mod".parse().unwrap(),
            &mut admin.backend,
            admin.configs.deref_mut(),
        );
        admin.send_all_assert_ok(promote_msgs, &ds_state).await;
        println!("----Invitee accepted Admin Invite, now syncing----");

        admin.sync_ds_assert_ok(&ds_state).await;
        invitee.sync_ds_assert_ok(&ds_state).await;

        println!("----Both clients synced, sending Rename----");

        let invitee_rename_msgs = flatten(vec![check_action_msg_and_get_mls(
            &comm_grp(),
            ActionMsg::RenameGroup(RenameGroupAction {
                new_name: "invitee_changed".to_string(),
                metadata: ActionMetadata::new(invitee.name(), "".to_string(), comm_grp()),
            }),
            &mut invitee.backend,
            invitee.configs.deref_mut(),
        )]);
        invitee
            .send_all_assert_ok(invitee_rename_msgs, &ds_state)
            .await;

        assert_eq!(
            invitee.configs.get_group_name(&comm_grp()),
            "invitee_changed"
        );

        let admin_rename_msgs = flatten(vec![check_action_msg_and_get_mls(
            &comm_grp(),
            ActionMsg::RenameGroup(RenameGroupAction {
                new_name: "admin_changed".to_string(),
                metadata: ActionMetadata::new(admin.name(), "".to_string(), comm_grp()),
            }),
            &mut admin.backend,
            admin.configs.deref_mut(),
        )]);
        // Would not pass because conflict. Assert will panic
        for msg in admin_rename_msgs {
            admin.send_and_parse(msg, &ds_state).await;
        }

        println!("----Invitee then admin both submitted rename actions, now syncing----");

        //Test if the both clients handle things successfully
        admin.sync_ds_assert_ok(&ds_state).await;
        invitee.sync_ds_assert_ok(&ds_state).await;

        assert_eq!(admin.configs.get_group_name(&comm_grp()), "invitee_changed");
        assert_eq!(
            invitee.configs.get_group_name(&comm_grp()),
            "invitee_changed"
        );
    }
}
