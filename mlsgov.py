#!/usr/bin/env python
import argparse
from itertools import chain
import pathlib
import sys
import subprocess, shlex, shutil

AUTH_SERVICE_CMD = "cargo run --bin authentication_service"
DELIVERY_SERVICE_CMD = "cargo run --bin delivery_service"
CLIENT_CMD_PREFIX = "cargo run --quiet --bin client"
ALICE_DIR = "alice"
BOB_DIR = "bob"


def clean_configs():
    """
    Reset client, AS, and DS state
    """
    to_delete = chain(
        pathlib.Path(ALICE_DIR).glob("Client*.yaml"),
        pathlib.Path(BOB_DIR).glob("Client*.yaml"),
        [
            pathlib.Path("DeliveryServiceState.yaml"),
            pathlib.Path("AuthenticationServiceState.yaml"),
        ],
    )
    for path in to_delete:
        if path.exists():
            path.unlink()


def run_client_cmd(cmd, client_name):
    """
    Run the command `cmd` on the client `client_name`
    """
    dir = ALICE_DIR if client_name == "alice" else BOB_DIR
    full_cmd = f"{CLIENT_CMD_PREFIX} {cmd}"
    status = subprocess.Popen(shlex.split(full_cmd), cwd=dir).wait()
    print(f"{full_cmd} produced status {status}")


def run_servers():
    auth = subprocess.Popen(shlex.split(AUTH_SERVICE_CMD))
    delivery = subprocess.Popen(shlex.split(DELIVERY_SERVICE_CMD))
    try:
        auth.wait()
        delivery.wait()
    except KeyboardInterrupt:
        auth.kill()
        delivery.kill()
        sys.exit(0)


def setup_alice_bob(gov=True):
    """
    Initialize a group containing alice and bob with alice as the moderator.
    """
    alice_path = pathlib.Path(ALICE_DIR)
    bob_path = pathlib.Path(BOB_DIR)
    if not alice_path.exists():
        alice_path.mkdir()
        shutil.copy("CliClientConfig.yaml", alice_path)

    if not bob_path.exists():
        bob_path.mkdir()
        shutil.copy("CliClientConfig.yaml", bob_path)

    run_client_cmd("register alice", "alice")
    run_client_cmd("register bob", "bob")
    run_client_cmd("create Test General", "alice")
    if gov:
        run_client_cmd("invite Test General bob", "alice")
        run_client_cmd("add Test General bob", "alice")
        run_client_cmd("update-group-state Test General", "alice")
    else:
        run_client_cmd("invite Test General bob", "alice")
        run_client_cmd("add Test General bob", "alice")

    run_client_cmd("accept Test General", "bob")


def build_baseline():
    """
    Build the baseline system with no governance
    """
    p = pathlib.Path("corelib/Cargo.toml")
    # Modify corelib/Cargo.toml
    p.write_text(p.read_text().replace('["gov"]', '["baseline"]'))
    # Build
    build()
    # Undo modification
    p.write_text(p.read_text().replace('["baseline"]', '["gov"]'))


def build():
    subprocess.Popen(shlex.split("cargo build")).wait()


def client_repl(client_name):
    """
    Run a repl for commands from the specified client
    """
    print(f"Starting client REPL for {client_name}")
    print()
    while True:
        try:
            command = input()
            if command in ("quit", "q"):
                break
            run_client_cmd(command, client_name)
            print()
        except KeyboardInterrupt:
            print("Shutting down REPL")
            break


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--run_servers", action="store_true")
    parser.add_argument("--setup_clients", action="store_true")
    parser.add_argument("--baseline", action="store_true", default=False)
    parser.add_argument("--build_baseline", action="store_true", default=False)
    parser.add_argument("--build", action="store_true")
    parser.add_argument(
        "--run",
        nargs=2,
        help="first argument is client name, second is command arguments",
    )
    parser.add_argument("--repl", help="specify the client name for the repl")

    args = parser.parse_args()

    if args.run:
        client_name, cmd = args.run
        run_client_cmd(cmd, client_name)

    if args.build_baseline:
        build_baseline()

    if args.build:
        build()

    if args.clean:
        clean_configs()

    if args.run_servers:
        run_servers()

    if args.setup_clients:
        setup_alice_bob(not args.baseline)

    if args.repl:
        client_repl(args.repl)


if __name__ == "__main__":
    main()
