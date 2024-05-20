# Assumption:
# 1. working directory is repo, or alternatively pass it as the first argument when running this script.
# 2. AS and DS is running FRESH, or alternatively set env variable `RUN_DS_AS=1`
#
# See [`config.py`] to set configs
import sys
from pathlib import Path

from helper import *

num_send_per_client_list = [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
repeats = 5
MAX_TIME = 300
group_sizes = [64, 256]
unordered_ten_percent_list = [0, 5, 9, 10]

file_path = Path("./result.jsonl").resolve()
if not file_path.exists():
    with open(file_path, 'w') as file:
        pass

if __name__ == '__main__':
    print("Start Time", datetime.datetime.now())

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
        if args.terraform_init:
            os.chdir(local_cloud_folder)
            subprocess.run(["terraform", "init"])

    for group_size in group_sizes:
        num_groups = num_clients // group_size
        print(f"\ngroup_size = {group_size}", file=sys.stderr)
        print(f"num_groups = {num_groups}\n", file=sys.stderr)
        setup_client_dirs_and_configs(dump_vote_file=False)

        # statr AS and DS if requested
        if args.run_services:
            run_ds_as()

        # Group will have disjoint users, with the caveat that they might be on the same instances
        group_idx_to_clients = defaultdict(list)
        group_idx_to_comm_group = dict()
        client_name_to_comm_group = dict()

        for group_index in range(num_groups):
            for ii in range(group_size):
                client_index = ii * num_groups + group_index
                if client_index < num_clients:
                    client = client_names[client_index]
                    group_idx_to_clients[group_index].append(client)
                    if group_index not in group_idx_to_comm_group:
                        group_idx_to_comm_group[group_index] = (f"community{group_index}", f"group{group_index}")
                    client_name_to_comm_group[client] = group_idx_to_comm_group[group_index]
                else:
                    print(f"malformed client_index:{client_index}")

        client_name_to_comm_groups = {k: [v] for k, v in client_name_to_comm_group.items()}

        # Registers
        run_command_on_clients(client_names,
                               ["--fresh-start", "register", CommandMagicWord.ClientSelfName],
                               allow_unordered=True, parse_output=False)

        admins = []
        # Create
        for group_index in group_idx_to_clients:
            admin = group_idx_to_clients[group_index][0]
            admins.append(admin)
            community_name, group_name = group_idx_to_comm_group[group_index]
            run_command_on_clients([admin],
                                   ["create", CommandMagicWord.MappedCommunities,
                                    CommandMagicWord.MappedGroups],
                                   client_name_to_comm_groups=client_name_to_comm_groups, parse_output=False)

            # Invite+Add+Update
            run_command_on_clients([admin],
                                   [CommandMagicWord.InviteAddUpdateGroupState,
                                    CommandMagicWord.MappedCommunities,
                                    CommandMagicWord.MappedGroups,
                                    CommandMagicWord.OtherClientNamesInPlace],
                                   client_names_override=group_idx_to_clients[group_index],
                                   client_name_to_comm_groups=client_name_to_comm_groups, parse_output=False)

        # Sync
        run_command_on_clients(client_names, ["sync"], allow_unordered=True, parse_output=False)

        # Accept
        non_admins = [*set(client_names).difference(admins)]
        run_command_on_clients(non_admins,
                               ["accept", CommandMagicWord.MappedCommunities,
                                CommandMagicWord.MappedGroups],
                               allow_unordered=True, client_name_to_comm_groups=client_name_to_comm_groups,
                               parse_output=False)
        # Promote
        for group_index in group_idx_to_clients:
            run_command_on_clients([group_idx_to_clients[group_index][0]],
                                   ["set-role", CommandMagicWord.MappedCommunities,
                                    CommandMagicWord.MappedGroups, CommandMagicWord.OtherClientNames, "Mod"],
                                   allow_unordered=True, client_name_to_comm_groups=client_name_to_comm_groups,
                                   client_names_override=group_idx_to_clients[group_index],
                                   parse_output=False)
        run_command_on_clients(client_names, ["--skip-history-msg-update", "sync"], allow_unordered=True,
                               parse_output=False)

        prefix_str = " ".join(client_command_prefix)
        prefix_str = prefix_str.replace("Mobile Documents", r"Mobile\ Documents")

        try_more_send_per_client = True
        for num_send_per_client in sorted(num_send_per_client_list):
            try_more_ordered_msgs_mix = try_more_send_per_client
            for unordered_ten_percent in sorted(unordered_ten_percent_list, reverse=True):
                for trial in range(repeats):
                    if not try_more_ordered_msgs_mix:
                        continue

                    command = ["rm -rf ./temp/ || true; mkdir temp; cp -r ./*.yaml ./temp/;"]
                    run_command_on_clients(client_names,
                                           command,
                                           allow_unordered=True,
                                           parse_output=False, add_client_prefix=False, no_space=True,
                                           client_name_to_comm_groups=client_name_to_comm_groups, force_bash=True)

                    start = datetime.datetime.now()
                    command = [
                        f"cd ./temp/; unordered_ten_percent={unordered_ten_percent} x={num_send_per_client} name=",
                        CommandMagicWord.ClientSelfName,
                        f"; for ((n=0; n < $x; n++)); do (( (n + name) % 10 < unordered_ten_percent)) && {prefix_str} --skip-history-msg-update send",
                        " ",
                        CommandMagicWord.MappedCommunities, " ",
                        CommandMagicWord.MappedGroups, " ",
                        f"helloworldhellsoworld || {prefix_str} --skip-history-msg-update rename-group",
                        " ",
                        CommandMagicWord.MappedCommunities, " ",
                        CommandMagicWord.MappedGroups, " ", "new_name_", CommandMagicWord.ClientSelfName,
                        "; done"]
                    run_command_on_clients(client_names,
                                           command,
                                           allow_unordered=True,
                                           parse_output=False, add_client_prefix=False, no_space=True,
                                           client_name_to_comm_groups=client_name_to_comm_groups, force_bash=True)

                    send_duration = datetime.datetime.now() - start

                    run_command_on_clients(client_names,
                                           ["cd ./temp/;", client_command_prefix[0], "--skip-store", "sync"],
                                           allow_unordered=True,
                                           parse_output=False, add_client_prefix=False, force_bash=True)
                    sendsync_duration = (datetime.datetime.now() - start)
                    print(f"\n<Config> num_clients={len(client_names)}")
                    print(f"<Config> num_send_per_client={num_send_per_client}", "out of ", num_send_per_client_list)
                    print(f"<Config> num_groups={num_groups}")
                    print(f"<Config> group_size={group_size}")
                    print(f"<Config> trial={trial}")
                    print("<Result> Sending duration ", send_duration)
                    print("<Result> Sending+sync duration ", sendsync_duration)
                    print("Number of messages", num_send_per_client * (len(client_names)))
                    result_entry = {
                        "num_clients": len(client_names),
                        "group_size": group_size,
                        "num_groups": num_groups,
                        "num_send_per_client": num_send_per_client,
                        "unordered_msg_%": unordered_ten_percent * 10,
                        "trial": trial,
                        "Sending_duration_sec": send_duration.total_seconds(),
                        "Sending_sync_duration_sec": sendsync_duration.total_seconds(),
                        "Number_of_messages": num_send_per_client * len(client_names),
                        "server_region": server_region if remote else "local",
                        "client_region": client_region if remote else "local",
                    }
                    with open(file_path, 'a+') as f:
                        json.dump(result_entry, f)
                        f.write('\n')

                    if trial == 0 and sendsync_duration.total_seconds() > MAX_TIME:
                        print(
                            "Time out on first trial. Will not try this or more ordered messages in the same send size")
                        try_more_ordered_msgs_mix = False
                        # If all clients are sending unordered but still time out, skip bigger num_send_per_client
                        if max(unordered_ten_percent_list) == unordered_ten_percent:
                            print(
                                "Time out on fewest ordered msgs mixture. Give up on more send sizes of any ordered/unordered combination")
                            try_more_send_per_client = False

    shutdown()
