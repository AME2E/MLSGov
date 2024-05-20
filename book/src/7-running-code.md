# Building and Running the Code

In this section, we provide a brief overview of how one can manually test
and run our E2EE communities system. We focus on running and testing code
in a rapid-development setting.

First, start the authentication service and the delivery service as shown
below

```
cargo run --bin authentication_service
cargo run --bin delivery_service
```

Ensure that the ports on which these applications run do not conflict with
any other applications you have running. For instance, if you have this
book being served on `localhost:2000` and you have the authentication
service running on `localhost:2000`, you're going to run into some issues.

Now open up two separate terminals (in different directories) to start
two clients. (TODO: in the future we will allow the command line options to
specify directories for storing client state, and we will have a script
that can orchestrate setting up the appropriate services.)

For each client, register the client as follows:

```
cargo run --bin client register alice
```

Then, from one of the clients issue the following command to create a
community named "Test" with a single channel named "General"

```
cargo run --bin client create Test General
```

Then, invite the other client to this community and channel as follows

```
cargo run --bin client invite Test General bob
```

Synchronize bob's client state and then have bob accept the invite

```
cargo run sync
cargo run accept Test General
```

Send a message to bob as follows

```
cargo run --bin client send Test General "hello bob”
```

Bob reads the message by syncing first and then issuing a read command

```
cargo run sync
cargo run read Test General
```

We note that, instead of repeatedly running `cargo run`, one can create
and run binaries by issuing the following commands

```
cargo build --release
./target/release/auth_service
```

You can see a full list of commands by running `./client help` and for
each command, you can get more information by typing the name of the command
and then using the `--help` flag. An example for the `read` command is
provided below.

```
./client read --help
client-read 0.1.0
read a message from a group

USAGE:
    client read <COMMUNITY_NAME> <GROUP_NAME> [SUBCOMMAND]

ARGS:
    <COMMUNITY_NAME>    
    <GROUP_NAME>        

OPTIONS:
    -h, --help       Print help information
    -V, --version    Print version information

SUBCOMMANDS:
    all       
    help      Print this message or the help of the given subcommand(s)
    last      
    unread    
```

You can see the JSON output of a command as follows

```
cargo r --bin client -- --json read Test General all
 {
  "message": {
    "content": {
      "Text": {
        "text_content": "Hallo world"
      }
    },
    "sender_timestamp": {
      "secs_since_epoch": 1666627442,
      "nanos_since_epoch": 287998000
    }
  },
  "sender": "b",
  "received_timestamp": {
    "secs_since_epoch": 1666627454,
    "nanos_since_epoch": 982841000
  }
}
```
