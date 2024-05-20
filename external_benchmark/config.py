import datetime
import json
import os

import yaml
from argparse_prompt import PromptParser


# Colors prefix to print statements
class c:
    HEADER = '\033[95m'  # Header
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False


##################################################
#              CONFIGURATION                    #
##################################################


parser = PromptParser()
parser.add_argument('--num_clients', '-n', default=64, type=int,
                    help='Number of clients to spin up, i.e. Total group size')
parser.add_argument('--remote', '-r', default=True, type=str2bool,
                    help='Whether to spin clients (and/or) on AWS. (True)=AWS, (False)=Local', )
parser.add_argument('--run_services', default=True, type=str2bool, prompt=False,
                    help='Run AS and DS. Local: Run locally. Remote: Spawn a new server instance')
parser.add_argument('--repo_dir', '-d', default=None, prompt=False,
                    help='Repo directory. i.e. The folder above the folder containing this `config.py`')
parser.add_argument('--key_path', '-kp', default=None, prompt=False,
                    help='[Remote-Only] Path to AWS key (.pem), which is used to SSH into AWS instances as ec2-user')
parser.add_argument('--key_name', '-kn', default=None, prompt=False,
                    help='[Remote-Only] AWS key-pair name, which is used to SSH into AWS instances as ec2-user')
parser.add_argument('--aws_relogin', default=True, type=str2bool, prompt=False,
                    help='[Remote-Only] Keep local AWS-CLI valid by `aws logout` and `aws login`', )
parser.add_argument('--client_aws_region', default="us-east-2", prompt=False,
                    help='[Remote-Only] AWS region to spin up client instances')
parser.add_argument('--server_aws_region', default="us-west-2", prompt=False,
                    help='[Remote-Only] AWS region to  spin up the server instance')
parser.add_argument('--keep_temp', default=False, type=str2bool, prompt=False,
                    help='Keep temporary files or spinned up instances at the end')
parser.add_argument('--server_ip', default="localhost", prompt=False,
                    help='[Local-Only] Server ip, if not localhost')
parser.add_argument('--sub_folder', '-s', default=None, prompt=False,
                    help='Subfolder name in ./saved_result to put results')
parser.add_argument('--backoff_parameters', '-b', default=[0, 0], type=float, nargs=2, prompt=False,
                    help='backoff parameters: (max_delay) (window_size)')
parser.add_argument('--ordered_vote', '-ov', default=False, type=str2bool, prompt=False,
                    help='Whether to use ordered messages for voting')
parser.add_argument('--client_per_instance', '-ci', default=8, type=int, prompt=True,
                    help='[Remote-Only] How many clients on each instances')
parser.add_argument('--instance_type_server', '-its', default="m7g.medium", type=str, prompt=False,
                    help='[Remote-Only] Which instance type to run for server')
parser.add_argument('--instance_type_client', '-itc', default="t4g.small", type=str, prompt=False,
                    help='[Remote-Only] Which instance type to run for client-bearing instances')
parser.add_argument('--ami_client', '-ac', default=None, type=str, prompt=False,
                    help='[Remote-Only] Override AMI for client instances')
parser.add_argument('--ami_server', '-as', default=None, type=str, prompt=False,
                    help='[Remote-Only] Override AMI for server instances')
parser.add_argument('--reuse_instances', '-ri', default=True, type=str2bool, prompt=False,
                    help='[Remote-Only] Reuse existing running instances, if any')
parser.add_argument('--avoid_overwrite_result', '-aor', default=True, type=str2bool, prompt=False,
                    help='[Remote-Only] Skip running if result file exists')
parser.add_argument('--region_to_ami_map', '-rta', default="./external_benchmark/aws/region_to_AMI.json", type=str,
                    prompt=False,
                    help='[Remote-Only] JSON file mapping AWS Region (lowercase) to AMI ID (ami-*******)')
parser.add_argument('--region_to_vpc_map', '-rtv', default="./external_benchmark/aws/region_to_VPC.json", type=str,
                    prompt=False,
                    help='[Remote-Only] JSON file mapping AWS Region (lowercase) to VPC (sg-*******)')
parser.add_argument('--max_ssh_init_wait', '-mssh', default=8, type=int,
                    prompt=False,
                    help='[Remote-Only] Max time in seconds to try to reconnect to a SSH instance')
args = parser.parse_args()

# Args validations
local_aws_key_file, key_name = args.key_path, args.key_name
if args.remote and (local_aws_key_file is None):
    local_aws_key_file = input("Must specify key_path if remote (preferably in args):")
if args.remote and (key_name is None):
    key_name = input("Must specify key_name if remote (preferably in args):")

backoff_max_delay = args.backoff_parameters[0]
backoff_windowsize = args.backoff_parameters[1]
ordered_vote = args.ordered_vote
client_per_instance = args.client_per_instance

if not args.run_services:
    print("This script is not spawning AS/DS and you are in charge of make sure you restarted AS/DS.")
    if args.server_ip == "localhost":
        print(f"{c.WARNING}You did not specify server ip. Assuming local")

if args.repo_dir is not None:
    os.chdir(args.repo_dir)
delay_desc = ""
if backoff_max_delay:
    delay_desc += f"_max_delay{backoff_max_delay}"
if backoff_windowsize:
    delay_desc += f"_window{backoff_windowsize}"
if client_per_instance > 1:
    delay_desc += f"_multiclient{client_per_instance}"

vote_start_delays = []

remote = args.remote
sub_folder = args.sub_folder
repo_dir = os.getcwd()

# Number and names of clients and admin
num_clients = args.num_clients
client_names = [f"{str(i)}" for i in range(num_clients)]
admin = client_names[0]

# Paths
release_folder = os.path.abspath("./target/release/")
client_path = os.path.abspath(os.path.join(release_folder, "client"))
ds_path = os.path.abspath(os.path.join(release_folder, "delivery_service"))
as_path = os.path.abspath(os.path.join(release_folder, "authentication_service"))

local_release_folder = os.path.abspath("./target/release/")
local_client_path = os.path.abspath(os.path.join(local_release_folder, "client"))
local_ds_path = os.path.abspath(os.path.join(local_release_folder, "delivery_service"))
local_as_path = os.path.abspath(os.path.join(local_release_folder, "authentication_service"))
local_cloud_folder = os.path.abspath(os.path.join("./", "cloud"))
local_vote_script_path = os.path.abspath(
    "./external_benchmark/vote_until_success_ordered.py") if ordered_vote else os.path.abspath(
    "./external_benchmark/vote_until_success_unordered.py")
remote_vote_script_path = "./vote_until_success.py"
auth_config_name = "AuthServiceConfig.yaml"
ds_config_name = "DeliveryServiceConfig.yaml"
client_config_name = "CliClientConfig.yaml"
if not remote:
    # temporary working directory for saving client states
    benchmark_temp_work_dir = os.path.abspath("./external_benchmark/temp")
else:
    from aws.aws_refreshable_session import RefreshableBotoSession

    MAX_SSH_RETRY_SEC = args.max_ssh_init_wait

    amis = json.load(open(args.region_to_ami_map))
    vpc = json.load(open(args.region_to_vpc_map))

    client_region = args.client_aws_region
    server_region = args.server_aws_region
    last_session_refresh_time = datetime.datetime.now().timestamp()
    client_region_session = RefreshableBotoSession(client_region).refreshable_session()
    ec2_clients = client_region_session.client('ec2')
    ssm_client = client_region_session.client('ssm')

    server_region_session = RefreshableBotoSession(server_region).refreshable_session()
    ec2_servers = server_region_session.client('ec2')

    server_public_dns = []
    server_public_ips = []
    server_private_ips = []

    instance_type_server = args.instance_type_server
    instance_type_client = args.instance_type_client

    ami_server = amis[server_region] if args.ami_server is None else args.ami_server
    ami_client = amis[client_region] if args.ami_client is None else args.ami_client
    vpc_security_group_id = vpc[server_region]

    # Reuse client instance ids with the correct AMI and is running
    response = ec2_clients.describe_instances(Filters=[
        {'Name': 'instance-state-name', 'Values': ['running']},
        {'Name': 'instance-type', 'Values': [instance_type_client]},
        {'Name': 'image-id', 'Values': [ami_client]}
    ])
    client_instance_ids = []

    if args.reuse_instances:
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                client_instance_ids.append(instance['InstanceId'])

    # Reuse client instance ids with the correct AMI and is running
    response = ec2_servers.describe_instances(Filters=[
        {'Name': 'instance-state-name', 'Values': ['running']},
        {'Name': 'instance-type', 'Values': [instance_type_server]},
        {'Name': 'image-id', 'Values': [ami_server]}
    ])
    server_instance_ids = []
    if args.reuse_instances:
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                server_instance_ids.append(instance['InstanceId'])

    client_public_dns = []

    remote_client_path = "/home/ec2-user/animated-adventure/target/release/client"
    remote_as_path = "/home/ec2-user/animated-adventure/target/release/authentication_service"
    remote_ds_path = "/home/ec2-user/animated-adventure/target/release/delivery_service"
    remote_vote_output_path = f"./vote_result_group_size{num_clients}.json"

meta_output_save_data_dir = os.path.abspath(os.path.join("./external_benchmark/saved_result", sub_folder)
                                            if sub_folder else "./external_benchmark/saved_result")
if not os.path.exists(meta_output_save_data_dir):
    os.makedirs(meta_output_save_data_dir)
meta_output_json_path = os.path.join(meta_output_save_data_dir, "group_size_{}.json".format(str(num_clients)))
meta_output_json2_path = os.path.join(meta_output_save_data_dir,
                                      "group_size_{}_vote{}.json".format(str(num_clients), delay_desc))

# Keywords
if not remote:
    client_command_prefix = [local_client_path, "--verbose", "--no-sync",
                             "--auto-retry"]  # Command line to use for client to output timer
else:
    client_command_prefix = [remote_client_path, "--verbose", "--no-sync", "--auto-retry"]
    max_batch = 30

batch_process_sep = "---process_separator---"
timer_print_prefix = "[Timer-JSON]"  # The prefix to look for in stderr when trying to find time JSONs
bandwidth_print_prefix = "[Bandwidth-JSON]"  # The prefix to look for in stderr when trying to find traffic JSONs
config_file_name = "CliClientConfig.yaml"  # name of the config file
action_UUID_prefix = "Voting is happening for action ID:"

# Client config
client_config_string = """---
ds_url_str: "ws://{}:{}/"
as_url_str: "ws://{}:{}/"
new_key_packages_per_sync: 5
data_path: "./ClientData.yaml"
keystore_path: "./ClientKeyStore.yaml" 
"""

as_config_str = yaml.dump({"data_path": f"./{auth_config_name}", "ip_address": "0.0.0.0", "port": 2000})
ds_config_str = yaml.dump({"data_path": f"./{ds_config_name}", "ip_address": "0.0.0.0", "port": 3000})

community_name, group_name = "community", "group"
invite_add_update_commands = ["invite", "add", "update-group-state"]
uuid = None
global_index = 0
# estimated_send_request_sec_per_client = 0.4  # More than enough: empirically 0.09 ~ 0.13 with good internet. A value of 0.4 left 0.28 seconds of buffer per client
estimated_send_request_sec_per_client = 0.15  # for SSH: More than enough: empirically 0.05 with good internet. A value of 0.4 left 0.28 seconds of buffer per client
