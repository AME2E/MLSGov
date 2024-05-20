# Benchmarking

We have both external and internal benchmarking.
Our internal one (written as a module in `corelib`) calls respective
functions directly, skipping all network components,
while our external benchmarking, written in python, provides an end to end benchmarking, by
collecting our client's debug output, which contain time and traffic data.

## Internal Benchmarking

The internal benchmarking code is in the `corelib/src/benches` module. It includes:

- `vote_bench.rs`: A benchmark for a voting procedure in a group. It measures the time and bandwidth consumption for each client to cast a vote and sync the updated group state.
- `mod.rs`: The main benchmarking function `benchmark` which sets up test groups of different sizes and runs a series of actions (create group, invite members, send message, rename group). It measures the time and bandwidth for each action.

## External Benchmarking

The external benchmarking code is in the `external_benchmark` directory. The key components are:

- `main.py`: The main driver script. It spawns multiple client processes, makes them join a group, and execute a series of actions. It collects the timing and bandwidth data printed by each client. The tested routine is:
  1. Setup client directories and configuration files
  2. Start the AS and DS services
  3. Register all clients with the AS
  4. Admin client creates a group
  5. Admin invites all other clients, adds them to the group, updates group state
  6. All clients sync
  7. Non-admin clients accept the invite
  8. Admin sends a text message
  9. All clients sync
  10. Admin sends a rename group action
  11. All clients sync
  12. A non-admin proposes another rename
  13. All clients sync
  14. All clients vote on the proposed rename
  15. All clients sync and verify the new group name
  16. Timing and bandwidth data for each step is collected and saved to a JSON file
- `config.py`: Contains all the configuration parameters for the benchmarks, including number of clients, AWS regions, instance types, paths to binaries and scripts etc. Uses the `argparse_prompt` library to interactively prompt for missing required parameters.
- `helper.py`: Contains utility functions used by the main script, including:
  - Setting up client directories and config files
  - Parsing client commands with macro substitutions
  - Running commands on clients and collecting output
  - Extracting timing and bandwidth data from client output
  - Setting up and tearing down AWS instances
- `stress_sending.py`: A script to benchmark message sending under load. It:
  1. Sets up multiple groups with disjoint members
  2. Has each client send a configured number of text messages and rename actions
  3. Syncs all clients
  4. Measures the total send and sync duration
  5. Repeats for different combinations of number of messages per client, % of ordered vs unordered messages, group sizes
  6. Saves the results to a JSONL file
- `vote_until_success_ordered.py` and `vote_until_success_unordered.py`: Scripts to benchmark the voting procedure with ordered and unordered messages respectively. They:
  1. Wait until the designated start time (to synchronize clients)
  2. Send a vote message
  3. Measure the total time from start to finish
  4. Save the stderr output (which contains the timing data) to a file
- `aws` directory: Contains scripts for managing AWS resources
  - `shutdown_all_aws_ins.py`: Terminates all running instances across specified regions
  - `aws_refreshable_session.py`: A helper class to create boto3 sessions with auto-refreshing credentials

### Output Format

The output of our external benchmarking is a JSON of the below annotated format.

```json
{
  "register": 
  [
    [ #(User1)
      {
        "Time": [
          {
            "description": "EstablishWebsockets",
            "nanoseconds": 4583850
          },
          ... #(other time measurements)
        ],
        "Bandwidth": [
          {
            "description": "OutgoingMsg",
            "num_bytes": 561
          },
          ... #(other bandwidth measurements)
        ]
      },
      ... #(measurement of other user requests (if any) sent in the part `register`)
    ]
    ... #(other users)
  ],
  # (other parts, like "sync", "rename", etc. )
}
```

For a comparison view of what could be in the descriptions, see `client/src/main`'s `TimerType` and `MsgSizeType`, which
is also where we define the individual measurement JSON.

Some key measurements:

- End-to-end latency for each type of action at different group sizes
- Bandwidth consumption for each type of action
- Time breakdown of client-side and server-side processing for each action
- Effect of simultaneous actions (e.g. sends) on latency and success rate
