from __future__ import annotations

import re
import shutil
import socket
import stat
import subprocess
import time
import warnings
from collections import defaultdict
from enum import Enum
from math import ceil

import paramiko
import selectors2 as selectors
from tqdm import tqdm

from config import *

# client name to their local directory
client_name_to_dir = {}
# client name or "server" to their ids
name_to_instance_ids = {}
# client name or "server" to ssh
name_to_ssh = {}


class WaitableProcess:
    """
    Abstract base class representing a process whose execution can be waited upon.
    """

    def wait(self):
        """
        Waits for the process to complete. This method should be implemented by subclasses.
        """
        pass


class SubprocessWaitableProcess(WaitableProcess):
    """
    A waitable process for subprocesses. Collects stderr from each subprocess.
    """

    def __init__(self, process):
        self.processes = [process]

    def __len__(self):
        return len(self.processes)

    def add(self, process):
        self.processes.append(process)

    def wait(self):
        """
        Waits for all subprocesses to complete and collects their stderr outputs.

        :return: A string concatenating all collected stderr outputs.
        """
        all_stderr = ""
        for process in self.processes:
            _stdout, stderr = process.communicate()
            if isinstance(stderr, bytes):
                stderr = stderr.decode()
            assert stderr is not None
            all_stderr = all_stderr + "\n" + stderr
        return all_stderr


class ParamikoWaitableProcess(WaitableProcess):
    """
    A waitable process for Paramiko SSH channels.
    """

    def __init__(self, channel):
        self.channel = channel

    def wait(self):
        """
        Waits for data on the channel's stderr stream, collecting it until the channel is closed.

        :return: A string of all data read from the stderr stream.
        """
        sel = selectors.DefaultSelector()
        sel.register(self.channel, selectors.EVENT_READ)
        result = b""
        while True:
            events = sel.select(timeout=0.01)
            if events:
                for key, mask in events:
                    while self.channel.recv_stderr_ready():
                        result += self.channel.recv_stderr(9999)
                    if self.channel.recv_ready():
                        self.channel.recv(9999)
            if self.channel.exit_status_ready():
                break
        try:
            result += self.channel.recv_stderr(9999)
        except:
            pass
        sel.unregister(self.channel)
        return result.decode()


class CommandMagicWord(Enum):
    """
    Enumeration for magic words used in creating dynamic commands for a mustache interface.
    (A mustache as in (mustache.github.io))

    The enums are placeholders to be replaced in the command parsing process with appropriate
    values or lists of values, often involving client names or groups.

    - ClientSelfName: Replaces with the name representing the client itself.
    - OtherClientNames: Replaces with the names of other clients.
    - AllClientNames: Replaces with the names of all clients.
    - InviteAddUpdateGroupState: Creates a sequence of invite, add, and update group state commands.
    - OtherClientNamesInPlace: Replaces with all other client names in a single string separated by commas.
    - MappedCommunities: Replaces with names of communities based on a mapping from client names to community groups.
    - MappedGroups: Replaces with names of groups based on a mapping from client names to group identifiers.
    """
    # [..., ClientSelfName] -> [[... , "SelfName"]]
    ClientSelfName = 0
    # [..., OtherClientNames] -> [[... , "Other1"], [... , "Other2"], ...]
    OtherClientNames = 1
    # [..., AllClientNames] -> [[... , "User1"], [... , "User2"], ...]
    AllClientNames = 2
    # [InviteAddUpdateGroupState, ...] -> [["Invite", ...], ["Add", ...], ["UpdateGroupState", ...]]
    InviteAddUpdateGroupState = 3
    # [..., OtherClientNamesInPlace] -> [[... , "User1,User2,..."]]
    OtherClientNamesInPlace = 4
    # [..., MappedCommunity] -> [[... , "CommunityBasedOn`client_name_to_comm_group 1`"], [... , "CommunityBasedOn`client_name_to_comm_group 2`"],...]
    MappedCommunities = 5
    # [..., MappedGroup] -> [[... , "GroupBasedOn`client_name_to_comm_group1`"], [... , "GroupBasedOn`client_name_to_comm_group2`"],...]
    MappedGroups = 6


def parse_client_command(client_name: str, client_commands: list[str | CommandMagicWord],
                         client_prefix: list[str] | None = None, client_names_override: list[str] = None,
                         client_name_to_comm_groups: dict[str, list[(str, str)]] | None = None) -> \
        list[list[str]]:
    """
    Parse a command.
    Tip: Better to see the printed output to understand this function
    :param client_prefix: Whether to add client_command_prefix
    :param client_name: the name of the client to generate command for
    :param client_commands: commands be parsed
    :param client_names_override: if not None, override client_names used for `AllClientNames` or `OtherClientNames`
    :param client_name_to_comm_group: if not None, parse `MappedCommunity`/`MappedGroup` base on username
    :return: A list of command, each being a list of str
    """
    parsed_commands = [client_prefix[:]] if client_prefix is not None else [[]]
    remove_invitee_on_update_group_state = False
    client_names_internal = client_names[:] if client_names_override is None else client_names_override[:]
    for command_token in client_commands:

        if isinstance(command_token, str) or isinstance(command_token,
                                                        float) or command_token == CommandMagicWord.ClientSelfName:
            # command token that will keep the number of commands:
            to_add_token = command_token if isinstance(command_token, str) else client_name
            parsed_commands = [command + [to_add_token] for command in parsed_commands]
        else:
            # command token that will increase the number of commands by generating same commands except this token:
            if command_token == CommandMagicWord.AllClientNames:
                to_add_tokens = client_names_internal
            elif command_token == CommandMagicWord.OtherClientNames:
                clients_copy = client_names_internal[:]
                clients_copy.remove(client_name)
                to_add_tokens = clients_copy
            elif command_token == CommandMagicWord.InviteAddUpdateGroupState:
                remove_invitee_on_update_group_state = True
                to_add_tokens = invite_add_update_commands
            elif command_token == CommandMagicWord.OtherClientNamesInPlace:
                clients_copy = client_names_internal[:]
                clients_copy.remove(client_name)
                to_add_tokens = [",".join(clients_copy)]
            elif command_token == CommandMagicWord.MappedCommunities:
                to_add_tokens = [comm_grp[0] for comm_grp in client_name_to_comm_groups[client_name]]
            elif command_token == CommandMagicWord.MappedGroups:
                to_add_tokens = [comm_grp[1] for comm_grp in client_name_to_comm_groups[client_name]]
            else:
                raise NotImplementedError
            org_num_commands = len(parsed_commands)
            # [["a"],["b"]] + ["name1","name2"] = [["a","name1"], ["b","name1"], ["a","name2"], ["b","name2"]]
            parsed_commands = [command + [to_add_tokens[i // org_num_commands]] for i, command in
                               enumerate(parsed_commands * len(to_add_tokens))]
    # Post process
    if client_prefix is not None:
        for i, command in enumerate(parsed_commands):
            # Remove "no sync" flag for commands of sync
            if "sync" in command[len(client_command_prefix):]:
                if "-n" in command:
                    parsed_commands[i].remove("-n")
                if "--no-sync" in command:
                    parsed_commands[i].remove("--no-sync")
            # Remove last token (invitee's name) on update_group_state command
            # because above code does not take care of this
            if remove_invitee_on_update_group_state \
                    and (invite_add_update_commands[-1] in command[len(client_command_prefix):]):
                parsed_commands[i] = parsed_commands[i][:-1]
    # tqdm.write("Command:", parsed_commands)
    return parsed_commands


def get_echo_commands(s, path) -> list[str]:
    """
    Generate a line of command to echo a string to a file
    """
    result = []
    for i, line in enumerate(s.split("\n")):
        if line:
            pipe_sign = ">" if i == 0 else ">>"
            result.append(f"echo {repr(line)} {pipe_sign} {path}")
    return [" && ".join(result)]


def get_export_commands(envs: dict, command_str) -> str:
    """
    Generate a line of command to echo a string to a file
    """
    result = []
    for k, v in envs.items():
        result.append(f"export {k}={v}")
    result.append(command_str)
    return " && ".join(result)


def preprocess_stderr(stderr_output: str):
    """
    Preprocesses the standard error output by decoding escaped characters and splitting into lines.

    :param stderr_output: The stderr output as a string.
    :return: A list of strings, each representing a line from the stderr output.
    """
    if "\\\"" in stderr_output:
        stderr_output = stderr_output.encode('utf-8').decode('unicode_escape')
    return stderr_output.splitlines()


def get_time_measurements(stderr_output: str) -> list[dict]:
    """
    Process the entire output of a process, and extract all time_measurements
    :param stderr_output: entire stderr of a process, which is used by the rust env logger
    :return: a list of time measurements found
    """
    lines = preprocess_stderr(stderr_output)
    time_measurements = []
    for line in lines:
        if timer_print_prefix in line:
            index = line.index(timer_print_prefix)
            assert "}" in line, "Error } not in line after prefix" + line
            time_json_str = line[index + len(timer_print_prefix):line.rindex("}") + 1]
            time_json = json.loads(time_json_str)
            time_measurements.append(time_json)
    return time_measurements


def get_bandwidth_measurements(stderr_output: str) -> list[dict]:
    """
    Process the entire output of a process, and extract all time_measurements
    :param stderr_output: entire stderr of a process, which is used by the rust env logger
    :return: a list of time measurements found
    """
    lines = preprocess_stderr(stderr_output)
    bandwidth_measurements = []
    for line in lines:
        if bandwidth_print_prefix in line:
            index = line.index(bandwidth_print_prefix)
            bandwidth_json_str = line[index + len(bandwidth_print_prefix):]
            bandwidth_json = json.loads(bandwidth_json_str)
            bandwidth_measurements.append(bandwidth_json)
    return bandwidth_measurements


def remove_client_dirs():
    """
    [Local Only] Removes the temporary work directory for benchmarks.
    """
    if not remote:
        if os.path.exists(benchmark_temp_work_dir):
            shutil.rmtree(benchmark_temp_work_dir)


def get_next_file_index():
    """
    [Local Only] Increments and returns the next global file index.

    :return: The next incremented value of global_index.
    """
    global global_index
    global_index += 1
    return global_index


def edit_distance_at_least(s1, s2, x, ignore_numbers):
    """
    Check if edit distance between s1 and s2 is at least x, with option to ignore numbers.

    :param s1: First string.
    :param s2: Second string.
    :param x: Edit distance threshold.
    :param ignore_numbers: Flag to ignore digits in comparison.
    :return: True if edit distance is at least x, False otherwise.
    """
    if s1 == s2:
        return False
    if ignore_numbers:
        s1 = re.sub(r'\d', '', s1)
        s2 = re.sub(r'\d', '', s2)
    if s1 == s2:
        return False
    len1, len2 = len(s1), len(s2)
    if abs(len1 - len2) > x:
        return True
    dp = [i for i in range(len2 + 1)]
    for i in range(1, len1 + 1):
        new_dp = [i]
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            new_dp.append(min(new_dp[j - 1] + 1, dp[j] + 1, dp[j - 1] + cost))
        dp = new_dp
        if min(dp) > x:
            return True
    return False


def client_execute(client: str, commands: list[list[str]] | list[str], wait: bool = True, env=None, no_space=False,
                   force_bash=False) \
        -> str | WaitableProcess:
    result = ""  # must have len 0
    if not isinstance(commands[0], list):
        commands = [commands]
    if env is None:
        env = {}
    if not remote:
        os.chdir(client_name_to_dir[client])

        if wait:
            for c in commands:
                p = subprocess.run(c, capture_output=True)
                assert "panic" not in str(p.stderr.lower()), str(p.stderr)
                assert "no such file" not in str(p.stderr.lower()), str(p.stderr)
                assert "command not found" not in str(p.stderr.lower()), str(p.stderr)
                assert "error:" not in str(p.stderr.lower()), str(p.stderr)
                result = result + p.stderr.decode()
        else:
            if len(commands) == 1 and not force_bash:
                new_process = subprocess.Popen(commands[0], env=env, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE)
            else:
                file_index = get_next_file_index()
                file_name = f"file_{file_index}.sh"
                with open(file_name, 'w') as file:
                    file.write("#!/bin/bash\n")
                    file.write(f" \necho {batch_process_sep} \n".join(
                        [("" if no_space else " ").join(
                            [command_token.replace('Mobile Documents', r'Mobile\ Documents') for command_token in
                             command]) for command in
                            commands]) + ';\nrm "$0"')
                st = os.stat(file_name)
                os.chmod(file_name, st.st_mode | stat.S_IEXEC)
                new_process = subprocess.Popen([os.path.abspath(file_name)], env=env, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE)
            result = SubprocessWaitableProcess(new_process)
        return result
    else:
        ssh, dir = name_to_ssh[client]
        command_token_joiner = "" if no_space else " "
        if not env:
            commands = f" && echo {batch_process_sep} && ".join(
                [command_token_joiner.join(command) for command in commands])
        else:
            commands = f" && echo {batch_process_sep} && ".join(
                [get_export_commands(envs=env, command_str=command_token_joiner.join(command)) for command in commands])

        if dir:
            commands = f"cd {dir};" + commands

        global client_execute_previous_command
        if 'client_execute_previous_command' in globals():
            if edit_distance_at_least(client_execute_previous_command, str(commands), 2, True):
                tqdm.write("Sending remote commands | " + str(commands))
        client_execute_previous_command = str(commands)

        transport = ssh.get_transport()
        channel = transport.open_session()
        channel.exec_command(commands)

        if wait:
            return ParamikoWaitableProcess(channel).wait()
        else:
            return ParamikoWaitableProcess(channel)


def setup_client_dirs_and_configs(dump_vote_file=True):
    """
    Create client directories and pop up their config files, based on configurations
    Delete the temporary client directories if exists
    pop up `client_name_to_dir` in doing so
    """

    if not remote:
        # Clear benchmark working folder
        if os.path.exists(benchmark_temp_work_dir):
            shutil.rmtree(benchmark_temp_work_dir)
        os.makedirs(benchmark_temp_work_dir)
        for (client_name) in client_names:
            config_str = client_config_string.format("localhost", "3000", "localhost", "2000")
            directory = os.path.abspath(os.path.join(benchmark_temp_work_dir, client_name))
            os.makedirs(directory)
            client_name_to_dir[client_name] = directory
            # Init Cli Config
            with open(os.path.join(directory, config_file_name), "w+") as f:
                f.write(config_str)
    else:
        n_instances = ceil(num_clients / client_per_instance)

        # Define the AWS regions and instance details
        print("creating server instances using EC2/boto3")
        server_instance_to_wait = []
        if len(server_instance_ids) == 0:
            response = ec2_servers.run_instances(
                ImageId=ami_server,
                InstanceType=instance_type_server,
                KeyName=key_name,
                SecurityGroupIds=[vpc_security_group_id],
                MinCount=1,
                MaxCount=1,
            )
            server_instance_ids.extend([instance["InstanceId"] for instance in response["Instances"]])
            server_instance_to_wait.extend([instance["InstanceId"] for instance in response["Instances"]])

        print("creating client instances using EC2/boto3")
        remaining_clients = n_instances - len(client_instance_ids)
        client_instances_to_wait = []
        while remaining_clients > 0:
            batch = min(remaining_clients, max_batch)
            # Launch client instances
            response = ec2_clients.run_instances(
                ImageId=ami_client,
                InstanceType=instance_type_client,
                KeyName=key_name,
                MinCount=batch,
                MaxCount=batch,
            )
            client_instance_ids.extend([instance["InstanceId"] for instance in response["Instances"]])
            client_instances_to_wait.append(client_instance_ids[-1])
            remaining_clients -= batch

        print("client_instance_ids =", client_instance_ids)
        print("server_instance_ids =", server_instance_ids)
        print(f"Waiting for selected {len(client_instances_to_wait)} client instance(s) to run",
              client_instances_to_wait)
        if client_instances_to_wait:
            waiter_clients = ec2_clients.get_waiter('instance_running')
            waiter_clients.wait(InstanceIds=client_instances_to_wait)
        # Wait for all instances to run
        print("Waiting for server instance(s) to run")
        if server_instance_to_wait:
            waiter_servers = ec2_servers.get_waiter('instance_running')
            waiter_servers.wait(InstanceIds=server_instance_to_wait)

        print("Getting metadata of instances using boto3")
        # Get public DNS and instance IDs of client instances
        response = ec2_clients.describe_instances(InstanceIds=client_instance_ids)
        client_info = []
        for res in response["Reservations"]:
            client_info = res["Instances"] + client_info
        client_public_dns = [instance["PublicDnsName"] for instance in client_info]

        # Get public DNS and instance IDs of the server instance
        server_instance = {}
        while "PublicIpAddress" not in server_instance:
            response = ec2_servers.describe_instances(InstanceIds=server_instance_ids)
            server_instance = response["Reservations"][0]["Instances"][0]

        server_public_dns.extend([server_instance["PublicDnsName"]])
        server_public_ips.extend([server_instance["PublicIpAddress"]])
        server_private_ips.extend([server_instance["PrivateIpAddress"]])

        assert len(server_instance_ids) == 1, "not expecting more than one server"

        # Cancel previous commands to avoid multiple ds/as running on same machines
        running_commands = ssm_client.list_commands()
        filtered_commands = [command['CommandId'] for command in running_commands['Commands'] if
                             ("Progress" in command['Status'] or "Pending" in command['Status'])
                             # and "animated-adventure" in " ".join(command['Parameters']['commands'])
                             ]
        if len(filtered_commands) > 0:
            print("Cancelling", len(filtered_commands), "previously running commands")
        for command_id in filtered_commands:
            ssm_client.cancel_command(CommandId=command_id)

        time.sleep(5)
        print("Setting up SSH Connection")
        # Update `name_to_instance_ids`
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            client_infos = [*zip(client_instance_ids, client_public_dns)]

            for idx, (instance_id, url) in tqdm(enumerate(client_infos), total=len(client_infos)):
                trial = 0
                ssh = paramiko.SSHClient()
                while trial <= MAX_SSH_RETRY_SEC:
                    try:
                        ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
                        ssh.connect(url, username="ec2-user", key_filename=local_aws_key_file)
                        trial = float('inf')
                    except paramiko.ssh_exception.NoValidConnectionsError as _:
                        trial += 1
                        time.sleep(1)
                        print(f"NoValidConnectionsError Error caught. Trial {trial} Retrying {url}")

                for ii in range(client_per_instance):
                    client_index = ii * len(client_infos) + idx
                    if client_index >= len(client_names):
                        continue
                    client_name = client_names[client_index]
                    name_to_instance_ids[client_name] = instance_id
                    name_to_ssh[client_name] = (ssh, f"~/{client_name}/")
                    client_index += 1
            # directories must be created

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
            ssh.connect(server_public_dns[0], username="ec2-user", key_filename=local_aws_key_file, )
            name_to_ssh["server"] = (ssh, "~")

        run_command_on_clients(client_names, ['rm -r ~/', CommandMagicWord.ClientSelfName, '/; ', 'mkdir ~/',
                                              CommandMagicWord.ClientSelfName, '/'], add_client_prefix=False,
                               allow_unordered=True,
                               parse_output=False, no_space=True)

        config_str = client_config_string.format(server_public_dns[0], "3000", server_public_dns[0], "2000")
        commands = get_echo_commands(config_str, f"./{client_config_name}")
        run_command_on_clients(client_names, commands, add_client_prefix=False, allow_unordered=True,
                               parse_output=False)
        if dump_vote_file:
            vote_file = open(local_vote_script_path).read()
            commands = get_echo_commands(vote_file, f"{remote_vote_script_path}")
            run_command_on_clients(client_names, commands, add_client_prefix=False, allow_unordered=True,
                                   parse_output=False)
        pass


def run_command_on_clients(clients: list[str], command: list[str | CommandMagicWord],
                           add_client_prefix=True, out: None | list = None, allow_unordered=False, parse_output=True,
                           no_space=False, client_names_override: list[str] = None,
                           client_name_to_comm_groups: dict[str, list[(str, str)]] | None = None, force_bash=False) \
        -> None | list[list[dict[str, list[dict[str, str | int]]]]]:
    """
    Run the same command on a list of clients, and return measurements
    :param parse_output: If `False`, only ensure execution but do not parse the outputs for measurements
    :param clients: whose client to run the commands
    :param command: command to run
                    (the input command could have MagicWords that can spin one command into many, e.g. inviting many).
    :param add_client_prefix: Whether to add `client_command_prefix` before command.
    :param out: If a list is passed in, `stderrs` will be appended to it as a side effect, one sublist per client
                not working when `parse_output` is `False`
    :param allow_unordered: Allow the executions on clients in any order. (return is still in order).
                    Command for each user is still guaranteed to execute in order. Might be ignored for larger group
    :param no_space: Whether to add space between comamand tokens when executing
    :param client_names_override: if not None, override client_names used for `AllClientNames` or `OtherClientNames`
    :param client_name_to_comm_groups: if not None, parse `MappedCommunity`/`MappedGroup` base on username
    :return: [per-user list] of [per-parsed-command list] of Time and Bandwidth measurements,
            each being a [list of measurement JSONs] illustrated below
            not working when `parse_output` is `False`
    [
       [ (Client 0)
           { (Parsed Command 0)
                "Time":
                    [
                        {'description':.. ,'nanoseconds': .. },
                        {'description':.. ,'nanoseconds': .. },
                        ...
                    ],
               "Bandwidth":
                    [
                        {'description':.. ,'num_bytes': .. },
                        {'description':.. ,'num_bytes': .. },
                        ...
                    ],
           },
        ...
       ]
       ...
    ]
    """
    assert isinstance(clients, list)
    result = []
    prefix = client_command_prefix if add_client_prefix else None
    client_commands = dict()
    waitables = defaultdict(list)
    outputs = defaultdict(list)

    for i, client in tqdm(enumerate(clients),
                          desc="Sending request" + ("" if allow_unordered else " and blocking"), total=len(clients)):
        client_commands[client] = parse_client_command(client, command, prefix, client_names_override,
                                                       client_name_to_comm_groups)
        if i == 0:
            tqdm.write(f"\nAs an example, {client} is sending {client_commands[client]}")
        parsed_commands = client_commands[client]
        waitables[client].append(
            client_execute(client, parsed_commands, wait=False, no_space=no_space, force_bash=force_bash))
        if not allow_unordered:
            outputs[client].append(waitables[client].pop().wait())
    for client in tqdm(clients, leave=allow_unordered, desc="Awaiting + retrieving command outputs",
                       total=len(clients)):
        while waitables[client]:
            outputs[client].append(waitables[client].pop().wait())

    for client in clients:
        if out is not None:
            out.append([])
        inner_out = out[-1] if out else out
        measurements = []

        client_outputs = outputs[client]
        assert "panic" not in str(client_outputs).lower(), client + " -- " + str(client_outputs)
        if len(client_outputs) == 1 and batch_process_sep in client_outputs[0]:
            client_outputs = client_outputs[0].split(batch_process_sep)

        for output in client_outputs:
            if parse_output:
                measurement = {"Time": get_time_measurements(str(output))}
                assert len(measurement['Time']) > 0, "Forgot to use parse_output=False?" + output
                measurement["Bandwidth"] = get_bandwidth_measurements(str(output))
                measurements.append(measurement)
            if inner_out is not None:
                inner_out.append(output)
        result.append(measurements)
    if parse_output:
        return result


def run_command_on_admin(command: list[str | CommandMagicWord]) -> \
        list[list[dict[str, list[dict[str, str | int]]]]]:
    """
    :param: command: the command to be run by the admin
    :return: same as `run_command_on_clients` for consistent data struct
    """
    return run_command_on_clients([admin], command)


def run_ds_as():
    if not remote:
        assert os.path.exists(local_ds_path)
        assert os.path.exists(local_as_path)
        subprocess.run(["pkill", "delivery_service"])
        subprocess.run(["pkill", "authentication_service"])

        subprocess.Popen([local_as_path, '-f', "--non-persistent"], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)  # no print, fresh start
        subprocess.Popen([local_ds_path, '-f', "--non-persistent"], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)  # no print, fresh start
        time.sleep(3)
    else:
        client_execute("server", ["pkill -9 -f delivery_service"], wait=True)
        client_execute("server", ["pkill -9 -f authentication_service"], wait=True)

        client_execute("server", [*get_echo_commands(as_config_str, f"./{auth_config_name}"), ";", remote_as_path, "-f",
                                  "--non-persistent"], wait=False)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = 1
        server_ip = server_public_ips[0] if remote else args.server_ip
        while result != 0:
            print("Waiting for AS to run")
            time.sleep(1)
            result = sock.connect_ex((server_ip, 2000))

        client_execute("server", [*get_echo_commands(ds_config_str, f"./{ds_config_name}"), ";", remote_ds_path, "-f",
                                  "--non-persistent"], wait=False)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = 1
        while result != 0:
            print("Waiting for DS to run")
            time.sleep(1)
            result = sock.connect_ex((server_ip, 3000))
        sock.close()


def get_uuid_from_str(output_str: str):
    """
    Extract UUID from str, basing on
    :param output_str: outputs of program
    :return:
    """
    lines = output_str.split("\n")
    for line in lines:
        if action_UUID_prefix in line:
            uuid = line[line.index(action_UUID_prefix) + len(action_UUID_prefix):].strip()
            return uuid


def title(s):
    print(f"\n\n\n{c.HEADER}{s}{c.ENDC}")


def shutdown():
    if remote:
        print("Killing all instances")
        ec2_servers.terminate_instances(InstanceIds=server_instance_ids)
        ec2_clients.terminate_instances(InstanceIds=client_instance_ids)
        print("Killed all instances")

    remove_client_dirs()
