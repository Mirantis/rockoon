#!/usr/bin/env python3
import os
import subprocess
import sys
import threading
from typing import List
import argparse
import logging
import logging.config
import kr8s
import time
from datetime import datetime
import re
import json

# Configuration variables (would typically come from environment or config file)
CLUSTER_SIZE = int(os.getenv("CLUSTER_SIZE"))
PEER_PREFIX_NAME = "openvswitch-ovn-db"
SERVICE_NAME = "ovn-discovery"
NAMESPACE = os.getenv("NAMESPACE")
INTERNAL_DOMAIN = "cluster.local"
DB_TYPE = os.getenv("DB_TYPE")
DB_PORT = os.getenv("DB_PORT")
RAFT_PORT = os.getenv("RAFT_PORT")
RAFT_ELECTION_TIMER = os.getenv("RAFT_ELECTION_TIMER")
HOSTNAME = os.getenv("HOSTNAME", "")
WAIT_ALL_ALIVE_TIMEOUT = int(os.getenv("WAIT_ALL_ALIVE_TIMEOUT", "300"))

DB_NAME = "OVN_Northbound"
DB_DIRECTORY = "/var/lib/ovn/"

STATE_CONFIGMAP = "openvswitch-ovn-db-state"
STATE_REFRESH_INTERVAL = 15


# Set DB_NAME based on DB_TYPE
if DB_TYPE == "sb":
    DB_NAME = "OVN_Southbound"


def get_logger(name):
    """Return logger object according to its configuration

    :param name: The name of this module
    :returns: python logger object.
    """
    conf = {
        "disable_existing_loggers": False,
        "formatters": {"standard": {"format": "%(asctime)s [%(levelname)s] %(name)s %(threadName)s: %(message)s"}},
        "handlers": {
            "default": {"class": "logging.StreamHandler", "formatter": "standard", "stream": "ext://sys.stdout"}
        },
        "loggers": {
            "kr8s": {"level": "INFO"},
            "httpx": {"level": "WARNING"},
        },
        "root": {"handlers": ["default"], "level": "INFO"},
        "version": 1,
    }

    logging.config.dictConfig(conf)
    logger = logging.getLogger(name)
    return logger


LOG = get_logger(__name__)


def get_remotes() -> str:
    """Generate comma-separated list of remote addresses."""
    remotes = [f"{PEER_PREFIX_NAME}-{i}.{SERVICE_NAME}.{NAMESPACE}.svc.{INTERNAL_DOMAIN}" for i in range(CLUSTER_SIZE)]
    return ",".join(remotes)


def run_ovn_ctl(cmd: List[str]) -> None:
    """Run ovn-ctl command in a separate thread.

    :param cmd: List of strings that form command to execute
    :returns: result of subprocess command
    """

    LOG.info(f"Running cmd: {cmd}")
    try:
        return subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        LOG.error(f"Error running ovn-ctl: {e}")
        sys.exit(1)


def is_db_present(db_type):
    """Check if OVN DB with specified type is present

    :param db_type: OVN DB type
    :retruns: Boolean flag
    """
    return os.path.exists(f"{DB_DIRECTORY}/ovn{db_type}_db.db")


class State:
    # States
    # When cluster was initialized
    INITIALIZED = "initialized"
    # When cluster is not formed yet local db is empty
    EMPTY = "empty"
    # When we don't know cluster state yet.
    UNKNOWN = "unknwon"

    def __init__(self, host, size):
        self.cm_name = STATE_CONFIGMAP
        self.cm_namespace = NAMESPACE
        self.host = host
        self.host_prefix = "-".join(self.host.split("-")[:-1])
        self.size = size
        self.cm = self.initialize()

    def initialize(self):
        configmap = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": self.cm_name, "namespace": self.cm_namespace},
        }
        cm = kr8s.objects.ConfigMap(configmap)
        if not cm.exists():
            cm.create()
        return cm

    @property
    def host_state(self):
        return self.get_host_state(self.host)

    @host_state.setter
    def host_state(self, state):
        return self.set_host_state(self.host, state)

    def get_host_state(self, host):
        self.cm.refresh()
        obj = self.cm.to_dict()
        return obj.get("data", {}).get(f"{host}_state", self.UNKNOWN)

    def set_host_state(self, host, state):
        self.cm.patch({"data": {f"{host}_state": state}})

    def tick(self):
        ts = datetime.utcnow().isoformat()
        self.cm.patch({"data": {f"{self.host}_updated_at": ts}})

    def get_host_tick(self, host):
        self.cm.refresh()
        obj = self.cm.to_dict()
        res = obj.get("data", {}).get(f"{host}_updated_at")
        if not res:
            return None
        return datetime.fromisoformat(res)

    def all_alive_after(self, date):
        for num in range(self.size):
            host = f"{self.host_prefix}-{num}"
            host_tick = self.get_host_tick(host)
            if not host_tick:
                LOG.info(f"Member {host} did not report its state yet.")
                return False
            if host_tick < date:
                LOG.info(f"Member {host} last update was before {date}")
                return False
            if (datetime.utcnow() - host_tick).seconds > 3 * STATE_REFRESH_INTERVAL:
                LOG.info(f"Member {host} last update is too old.")
                return False
        return True

    @property
    def all_empty(self):
        states = []
        for num in range(self.size):
            host = f"{self.host_prefix}-{num}"
            host_state = self.get_host_state(host)
            if host_state != self.EMPTY:
                return False
        return True

    def wait_all_alive(self, timeout=WAIT_ALL_ALIVE_TIMEOUT):
        LOG.info("Waiting all members are alive")
        start = time.time()
        now = datetime.utcnow()
        while time.time() - start < 300:
            if self.all_alive_after(now):
                return True
            time.sleep(STATE_REFRESH_INTERVAL)
        LOG.info("All members reporting its states withing timeout.")
        raise TimeoutError(f"Failed waiting all replicas reporting.")

    def wait_initialized(self, host):
        LOG.info(f"Waiting {host} to initialize")
        while True:
            host_state = self.get_host_state(host)
            LOG.info(f"{host} state is {host_state}")
            if host_state == self.INITIALIZED:
                break
            time.sleep(STATE_REFRESH_INTERVAL)
        LOG.info(f"{host} is initialized")

heal_needed = threading.Event()


def state_reporting():
    # Initialize state
    st = State(HOSTNAME, CLUSTER_SIZE)
    while True:
        LOG.info("Running state tick.")
        try:
            if is_db_present(DB_TYPE):
                st.host_state = st.INITIALIZED
            else:
                st.host_state = st.EMPTY
            st.tick()
        except Exception as e:
            LOG.error(f"Error in state tick: {e}")
        time.sleep(STATE_REFRESH_INTERVAL)


def get_cluster_status(db_type, db_name):
    result = subprocess.run(
        ["ovs-appctl", "-t", f"/var/run/ovn/ovn{db_type}_db.ctl", "cluster/status", db_name],
        check=True,
        capture_output=True,
        text=True,
    )
    output = result.stdout

    # Initialize the main dictionary to store parsed data
    result = {
        "Name": "",
        "Cluster": {"ID": "", "UUID": ""},
        "Server": {"ID": "", "UUID": "", "Address": "", "Status": "", "Role": "", "Term": 0, "Leader": "", "Vote": ""},
        "ElectionTimer": 0,
        "Log": {"Start": 0, "End": 0},
        "Entries": {"NotYetCommitted": 0, "NotYetApplied": 0},
        "Connections": [],
        "Disconnections": 0,
        "Servers": [],
    }

    # Regular expressions for parsing
    patterns = {
        "name": r"Name: (.*)",
        "cluster_id": r"Cluster ID: (\S+) \(([\w-]+)\)",
        "server_id": r"Server ID: (\S+) \(([\w-]+)\)",
        "address": r"Address: (.*)",
        "status": r"Status: (.*)",
        "role": r"Role: (.*)",
        "term": r"Term: (\d+)",
        "leader": r"Leader: (\S+)",
        "vote": r"Vote: (\S+)",
        "election_timer": r"Election timer: (\d+)",
        "log": r"Log: \[(\d+), (\d+)\]",
        "entries_not_committed": r"Entries not yet committed: (\d+)",
        "entries_not_applied": r"Entries not yet applied: (\d+)",
        "connections": r"Connections: (.*)",
        "disconnections": r"Disconnections: (\d+)",
        "server": r"^\s*(\S+) \((\S+) at ([^)]+)\)(?: \((self)\))?(?: last msg (\d+) ms ago)?",
    }

    # Parse line by line
    lines = output.strip().split("\n")
    for line in lines:
        line = line.strip()

        # Match each pattern
        for key, pattern in patterns.items():
            match = re.match(pattern, line)
            if match:
                if key == "name":
                    result["Name"] = match.group(1)
                elif key == "cluster_id":
                    result["Cluster"]["ID"] = match.group(1)
                    result["Cluster"]["UUID"] = match.group(2)
                elif key == "server_id":
                    result["Server"]["ID"] = match.group(1)
                    result["Server"]["UUID"] = match.group(2)
                elif key == "address":
                    result["Server"]["Address"] = match.group(1)
                elif key == "status":
                    result["Server"]["Status"] = match.group(1)
                elif key == "role":
                    result["Server"]["Role"] = match.group(1)
                elif key == "term":
                    result["Server"]["Term"] = int(match.group(1))
                elif key == "leader":
                    result["Server"]["Leader"] = match.group(1)
                elif key == "vote":
                    result["Server"]["Vote"] = match.group(1)
                elif key == "election_timer":
                    result["ElectionTimer"] = int(match.group(1))
                elif key == "log":
                    result["Log"]["Start"] = int(match.group(1))
                    result["Log"]["End"] = int(match.group(2))
                elif key == "entries_not_committed":
                    result["Entries"]["NotYetCommitted"] = int(match.group(1))
                elif key == "entries_not_applied":
                    result["Entries"]["NotYetApplied"] = int(match.group(1))
                elif key == "connections":
                    # Split connections into list, removing empty strings
                    connections = [conn for conn in match.group(1).split() if conn]
                    result["Connections"] = connections
                elif key == "disconnections":
                    result["Disconnections"] = int(match.group(1))
                elif key == "server":
                    server = {
                        "ID": match.group(1),
                        "ServerID": match.group(2),
                        "Address": match.group(3),
                        "IsSelf": match.group(4) == "self" if match.group(4) else False,
                        "LastMsgMsAgo": int(match.group(5)) if match.group(5) else None,
                    }
                    result["Servers"].append(server)
    return result


def extract_cluster_local_servers(cluster_status):
    res = []
    host = HOSTNAME
    for server in cluster_status["Servers"]:
        if host in server["Address"]:
            res.append(server)
    return res


def remove_ovndb_server(server):
    id = server["ID"]
    LOG.info(f"Removing stale server {id}")
    result = subprocess.run(
        ["ovs-appctl", "-t", f"/var/run/ovn/ovn{DB_TYPE}_db.ctl", "cluster/kick", DB_NAME, id],
        check=True,
        capture_output=True,
        text=True,
    )
    return result


def heal_cluster():
    LOG.info("Starting cluster healing")
    # TODO(vsaienko): add waiter here to check current node started
    # before proceed with healing
    time.sleep(30)
    # Check for duplicate local member, remove stale when found.
    for i in range(3):
        cluster_status = get_cluster_status(DB_TYPE, DB_NAME)
        servers = extract_cluster_local_servers(cluster_status)
        if len(servers) > 1:
            LOG.warning(f"Found duplicate server {servers}")
            stale_servers = [x for x in servers if x["IsSelf"] is False]
            LOG.info(f"Removing stale servers {stale_servers}")
            for server in stale_servers:
                remove_ovndb_server(server)
    LOG.info(f"Current cluster status is {cluster_status}")


def heal_cluster_thread():
    LOG.info("Starting heal cluster thread.")
    while True:
        try:
            if heal_needed.is_set():
                heal_cluster()
                heal_needed.clear()
        except Exception:
            LOG.exception("Failed to heal cluster, retrying.")
        time.sleep(STATE_REFRESH_INTERVAL)


def start():
    """Start the OVSDB server with appropriate configuration in a separate thread."""

    # Start state reporting
    LOG.info("Starting state reporting thread")
    state_thread = threading.Thread(target=state_reporting, args=())
    state_thread.start()

    # Start healing thread
    LOG.info("Starting healing thread")
    heal_thread = threading.Thread(target=heal_cluster_thread, args=())
    heal_thread.start()

    # Initialize state
    bootstrap = False
    st = State(HOSTNAME, CLUSTER_SIZE)
    if not is_db_present(DB_TYPE):
        st.wait_all_alive()
        if st.all_empty:
            LOG.info("All members are empty, this is initial bootstrap.")
            bootstrap = True
            if HOSTNAME != "openvswitch-ovn-db-0":
                st.wait_initialized("openvswitch-ovn-db-0")

    UPGRADE_ARGS = []

    # Upgrade logic
    version_file = f"{DB_DIRECTORY}/ovsdb_server_version"
    if not os.path.exists(version_file):
        version_output = subprocess.check_output(["ovsdb-server", "--version"]).decode()
        with open(version_file, "w") as f:
            f.write(version_output)

    with open(version_file, "r") as f:
        old_version = f.read().strip()
    new_version = subprocess.check_output(["ovsdb-server", "--version"]).decode().strip()

    if old_version != new_version:
        LOG.info(f"OVS DB version changed {old_version} to {new_version}")
        # Needed during cluster upgrade from 3.1 and earlier to 3.2 and later
        UPGRADE_ARGS = ["--disable-file-no-data-conversion"]

    cluster_opts = []
    if CLUSTER_SIZE > 1:
        cluster_opts = [
            f"--db-{DB_TYPE}-election-timer={RAFT_ELECTION_TIMER}",
            f"--db-{DB_TYPE}-cluster-local-proto=tcp",
            f"--db-{DB_TYPE}-cluster-local-addr={HOSTNAME}.{SERVICE_NAME}.{NAMESPACE}.svc.{INTERNAL_DOMAIN}",
            f"--db-{DB_TYPE}-cluster-local-port={RAFT_PORT}",
        ]

    opts = []
    if not bootstrap or HOSTNAME != "openvswitch-ovn-db-0":
        LOG.info(f"Joining node {HOSTNAME} to the cluster.")
        opts = [
            f"--db-{DB_TYPE}-cluster-remote-proto=tcp",
            f"--db-{DB_TYPE}-cluster-remote-addr=ovn-db.{NAMESPACE}.svc.{INTERNAL_DOMAIN}",
            f"--db-{DB_TYPE}-cluster-remote-port={RAFT_PORT}",
        ]
        heal_needed.set()

    # Update version file
    with open(version_file, "w") as f:
        f.write(new_version)

    # Construct ovn-ctl command
    cmd = [
        "/usr/share/ovn/scripts/ovn-ctl",
        f"run_{DB_TYPE}_ovsdb",
        *cluster_opts,
        f"--ovn-northd-sb-db=tcp:{get_remotes()}",
        *opts,
        f"--ovn-{DB_TYPE}-log=-vconsole:info -vfile:off",
        "--",
        "--remote",
        f"ptcp:{DB_PORT}",
        *UPGRADE_ARGS,
    ]

    # Start ovn-ctl in a separate thread
    LOG.info("Starting ovsdb server")
    thread = threading.Thread(target=run_ovn_ctl, args=(cmd,))
    thread.start()
    LOG.info("Started ovn-ctl in a separate thread")
    thread.join()


def stop():
    """Stop the OVSDB server."""
    try:
        subprocess.run(["/usr/share/ovn/scripts/ovn-ctl", f"stop_{DB_TYPE}_ovsdb"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error stopping ovn-ctl: {e}")
        sys.exit(1)


def main():
    """Parse command-line arguments and execute the specified command."""
    parser = argparse.ArgumentParser(description="OVN Database Management Script")
    parser.add_argument("command", choices=["start", "stop"], help="Command to execute: 'start' or 'stop'")
    args = parser.parse_args()

    if args.command == "start":
        start()
    elif args.command == "stop":
        stop()


if __name__ == "__main__":
    main()
