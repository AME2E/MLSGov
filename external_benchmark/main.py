# Assumption:
# 1. working directory is repo, or alternatively pass it as the first argument when running this script.
# 2. AS and DS is running FRESH by default, unless env variable exists: `DO_NOT_RUN_DS_AS=1`
#
# See [`config.py`] to set configs

from helper import *

if __name__ == '__main__':

    print("Start Time", datetime.datetime.now())
    if args.avoid_overwrite_result and os.path.exists(meta_output_json_path):
        print(f"Early return: {meta_output_json_path} exist")
        exit(0)
    else:
        print(f"Results saving to {meta_output_json2_path} and {meta_output_json_path} ")

    meta_measurements = {}

    if not remote:
        # Automatic rebuild to guarantee code up-to-date.
        # Will be quick if release build up-to-date
        subprocess.run(["cargo", "build", "--release"])
        assert os.path.exists(local_release_folder)
        assert os.path.exists(local_client_path)
    else:
        if args.aws_relogin:
            subprocess.run(["aws", "logout"])
            subprocess.run(["aws", "login"])


    setup_client_dirs_and_configs()

    # statr AS and DS if requested
    if args.run_services:
        run_ds_as()

    title("Registers")
    meta_measurements['register'] = run_command_on_clients(client_names,
                                                           ["register", CommandMagicWord.ClientSelfName],
                                                           allow_unordered=True)
    title("Create")
    meta_measurements['create'] = run_command_on_admin(["create", community_name, group_name])

    title("Invite, Add, Update")
    meta_measurements['invite_add_update'] = run_command_on_admin(
        [CommandMagicWord.InviteAddUpdateGroupState, community_name, group_name,
         CommandMagicWord.OtherClientNamesInPlace])

    title("Sync1")
    meta_measurements['sync1'] = run_command_on_clients(client_names, ["sync"], allow_unordered=True)

    title("Accept")
    no_admin_clients = client_names[:]
    no_admin_clients.remove(admin)
    meta_measurements['accept'] = run_command_on_clients(no_admin_clients,
                                                         ["accept", community_name, group_name], allow_unordered=True)

    title("Admin sends text message")
    meta_measurements['sendtext'] = run_command_on_admin(["send", community_name, group_name, "a-message"])

    title("Sync after text sending")
    meta_measurements['sync2'] = run_command_on_clients(client_names, ["sync"], allow_unordered=True)

    title("Admin sends rename action")
    meta_measurements['rename'] = run_command_on_admin(
        ["rename-group", community_name, group_name, "admin-s-new-name"])

    title("Sync after admin sent rename action")
    meta_measurements['sync3'] = run_command_on_clients(client_names, ["sync"], allow_unordered=True)

    title("Rename propose by non-admin")
    propose_out = []
    meta_measurements['rename_propose'] = \
        run_command_on_clients(no_admin_clients[:1],
                               ["rename-group", community_name, group_name, "voted-new-name"], out=propose_out,
                               allow_unordered=True)
    uuid = get_uuid_from_str(propose_out[0][0])

    title("Sync after rename propose by non-admin")
    meta_measurements['sync4'] = run_command_on_clients(client_names, ["sync"], allow_unordered=True)

    print("Finish non-voting Time", datetime.datetime.now())

    print("Rename UUID for voting:", uuid)
    if uuid is not None:
        title("Vote")
        processes = []
        estimated_send_request_sec = estimated_send_request_sec_per_client * num_clients + 2
        estimated_start_time = datetime.datetime.now() + datetime.timedelta(0, estimated_send_request_sec)
        if remote:
            for i, client_name in enumerate(client_names):
                output_path = os.path.join(meta_output_save_data_dir,
                                           client_name + "_vote" + ".json") if not remote else remote_vote_output_path

                if ordered_vote:
                    envs = {"uuid": uuid, "community_name": community_name, 'group_name': group_name,
                            'num_clients': str(num_clients),
                            "output_path": output_path,
                            "client_path": remote_client_path if remote else local_client_path,
                            "timer_print_prefix": timer_print_prefix,
                            "bandwidth_print_prefix": bandwidth_print_prefix,
                            "start_time": estimated_start_time.timestamp() + (
                                vote_start_delays[i] if len(vote_start_delays) == num_clients else 0),
                            "max_delay": str(backoff_max_delay),
                            "window_size": str(backoff_windowsize),
                            "RUST_BACKTRACE": "1"
                            }
                else:
                    envs = {"uuid": uuid, "community_name": community_name, 'group_name': group_name,
                            'num_clients': str(num_clients),
                            "output_path": output_path,
                            "client_path": remote_client_path if remote else local_client_path,
                            "timer_print_prefix": timer_print_prefix,
                            "bandwidth_print_prefix": bandwidth_print_prefix,
                            "start_time": estimated_start_time.timestamp() + (
                                vote_start_delays[i] if len(vote_start_delays) == num_clients else 0),
                            "RUST_BACKTRACE": "1"
                            }

                p = client_execute(client_name, ["python3", remote_vote_script_path], wait=False, env=envs)
                processes.append(p)
            print("Voting starting in (i.e. time buffer):", estimated_start_time - datetime.datetime.now())
            for index, p in tqdm(enumerate(processes), desc="Awaiting voting", total=len(processes)):
                result = p.wait()

            vote_measurement = run_command_on_clients(client_names, ["cat", remote_vote_output_path, ">&2"],
                                                      add_client_prefix=False,
                                                      allow_unordered=True)
            if not ordered_vote:
                meta_measurements['sync5'] = run_command_on_admin(["sync"])
                meta_measurements['admin_batch'] = run_command_on_admin(
                    ["commit-pending-votes", community_name, group_name])

            with open(meta_output_json2_path, "w+") as f:
                # Saving to prevent vote failure
                json.dump(vote_measurement, f)
        else:
            # Local
            if ordered_vote:
                vote_measurement = run_command_on_clients(client_names,
                                                          ["--window-size", str(backoff_windowsize), "--max-delay",
                                                           str(backoff_max_delay), "vote", community_name, group_name,
                                                           "yes",
                                                           uuid, "rename-group"], allow_unordered=True)
            else:
                vote_measurement = run_command_on_clients(client_names,
                                                          ["propose-vote", community_name, group_name, "yes",
                                                           uuid, "rename-group"], allow_unordered=True)
                meta_measurements['sync_admin_batch'] = run_command_on_clients(client_names, ["sync"],
                                                                               allow_unordered=True)
                meta_measurements['admin_batch'] = run_command_on_admin(
                    ["commit-pending-votes", community_name, group_name])

        print("Saving vote results")
        with open(meta_output_json2_path, "w+") as f:
            json.dump(vote_measurement, f)

        meta_measurements['sync5'] = run_command_on_clients(client_names, ["sync"], allow_unordered=True)
        outs = []

        run_command_on_clients(clients=client_names, command=['show-group-state', community_name, group_name], out=outs,
                               allow_unordered=True)
        for out in outs:
            assert 'SharedGroupState { name: "voted-new-name"' in out[0], \
                out[0][out[0].index("SharedGroupState"):out[0].index(" topic:")]

        print("Name changed verified, saving last results...")
    else:
        print("No UUID, no voting")

    with open(meta_output_json_path, "w+") as f:
        json.dump(meta_measurements, f)

    print("Result saved.")

    run_command_on_clients(clients=client_names, command=['rm -rf ./*'], add_client_prefix=False, force_bash=True,
                           allow_unordered=True, parse_output=False)

    if os.name == "posix":
        os.system("""
                      osascript -e 'display notification "{}" with title "{}"'
                      """.format("Distributed benchmarking has finished running", "Finished Running"))

    if not args.keep_temp:
        shutdown()
