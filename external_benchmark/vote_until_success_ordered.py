import datetime
import json
import os
import subprocess
import time

uuid = os.getenv("uuid")
community_name = os.getenv("community_name")
group_name = os.getenv("group_name")
client_path = os.getenv("client_path")
num_clients = int(os.getenv("num_clients"))
output_path = os.getenv("output_path")
start_time = float(os.getenv("start_time"))
timer_print_prefix = os.getenv("timer_print_prefix")
max_delay = float(eval(os.getenv("max_delay")))
window_size = float(eval(os.getenv("window_size")))

if __name__ == '__main__':
    backoff_sleeps = []
    wait_sec = start_time - datetime.datetime.now().timestamp()
    if wait_sec > 0:
        time.sleep(wait_sec)
    else:
        print("panic/error: start time too early")
    p = subprocess.run(
        [client_path, "--verbose", "--no-sync", "--auto-retry", "--max-delay", str(max_delay), "--window-size",
         str(window_size), "vote", community_name, group_name, "yes", uuid, "rename-group"],
        capture_output=True)

    total_time = {"description": "TotalVotingStartToEndTime",
                  "nanoseconds": int((datetime.datetime.now().timestamp() - start_time) * 1000000000)}
    json.dump([p.stderr.decode()], open(output_path, "w+"))
