#!/usr/bin/env python

{{/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/}}

"""
Health probe script for OpenStack agents that uses RPC/unix domain socket for
communication. Sends message to agent through rpc call method and expects a
reply. It is expected to receive a failure from the agent's RPC server as the
method does not exist.

Script returns failure to Kubernetes only when
  a. agent is not reachable or
  b. agent times out sending a reply.
  c. l3 agent is not synced

The logs are written to events in case of probe failure according to
log severity.

Usage example for Neutron L3 agent:
# python health-probe.py --config-file /etc/neutron/neutron.conf \
#  --config-file /etc/neutron/l3_agent.ini --rabbitmtq-queue-name l3_agent

Usage example for Neutron metadata agent:
# python health-probe.py --config-file /etc/neutron/neutron.conf \
#  --config-file /etc/neutron/metadata_agent.ini
"""

import httplib2
from six.moves import http_client as httplib
import argparse
import configparser
import os
import json
import psutil
import signal
import socket
import sys
import uuid
import logging
from pyroute2 import netns
from six.moves.urllib import parse as urlparse

import oslo_messaging
from oslo_messaging._drivers import common as rpc_common
from kombu import Connection, Exchange, Producer, Queue, Consumer

# TODO(vsaienko): drop when queens with python2 support is dropped
try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError

tcp_established = "ESTABLISHED"
tcp_syn = "SYN_SENT"

logging.basicConfig(stream = sys.stdout, level=logging.INFO)
LOG = logging.getLogger(__file__)


def read_json_file(file_name):
    try:
        with open(file_name, "r") as _f:
            return json.load(_f)
    except FileNotFoundError:
        LOG.warning("File %s doesn't exist", file_name)
    except json.decoder.JSONDecodeError:
        LOG.warning("Invalid JSON file %s", file_name)
    return {}



def _get_hostname():
    if opts.use_fqdn:
        return socket.getfqdn()
    return socket.gethostname()


def is_sriov_ready():
    """Checks the sriov configuration on the sriov nic's"""
    cfg_file = [x for x in opts.config_file if "sriov_agent.ini" in x]
    if not cfg_file:
        return True
    with open(cfg_file[0]) as nic:
        for phy in nic:
            if "physical_device_mappings" in phy:
                phy_dev = phy.split("=", 1)[1]
                phy_dev1 = phy_dev.rstrip().split(",")
                if not phy_dev1:
                    LOG.error("No Physical devices" " configured as SRIOV NICs")
                    return False
                for intf in phy_dev1:
                    phy, dev = intf.split(":")
                    try:
                        with open("/sys/class/net/%s/device/sriov_numvfs" % dev) as f:
                            for line in f:
                                numvfs = line.rstrip("\n")
                                if numvfs:
                                    return True
                    except IOError:
                        LOG.error("IOError:No sriov_numvfs config file")
    return False

def is_connected_to(process_name, sockets):
    ports = [s[1] for s in sockets]
    socket_open = False
    for sock in sockets:
       s = None
       try:
           s = socket.create_connection((sock[0], sock[1]), timeout=opts.rabbitmq_connect_timeout)
           socket_open = True
           break
       except Exception as e:
           LOG.warning("Can not connect to  %s:%d. Exception is %s" % (sock[0], sock[1], e))
       finally:
           if s:
               s.close()

    if not socket_open:
        LOG.warning("Skip connect check, server is down.")
        return True

    for pr in psutil.pids():
        try:
            p = psutil.Process(pr)
            if any(process_name in cmd for cmd in p.cmdline()):
                pcon = p.connections()
                for con in pcon:
                    try:
                        port = con.raddr[1]
                        status = con.status
                    except IndexError:
                        continue
                    if port in ports and status in [tcp_established, tcp_syn]:
                        return True
        except psutil.NoSuchProcess:
            continue


def get_rabbitmq_ports():
    "Get RabbitMQ ports"
    transport_url = cfg.get("DEFAULT", "transport_url")
    sockets = set()
    for url in transport_url.split(','):
        parse = urlparse.urlparse(url)
        hostname = parse.hostname
        port = parse.port
        if hostname and port:
            sockets.add((hostname, port))
    return sockets

def is_connected_to_rabbitmq(process_name):
    sockets = get_rabbitmq_ports()
    return is_connected_to(process_name, sockets)


class UnixDomainHTTPConnection(httplib.HTTPConnection):
    """Connection class for HTTP over UNIX domain socket."""

    def __init__(self, host, port=None, strict=None, timeout=None, proxy_info=None):
        httplib.HTTPConnection.__init__(self, host, port, strict)
        self.timeout = timeout
        self.socket_path = cfg.get(
            "DEFAULT",
            "metadata_proxy_socket",
            fallback="/var/lib/neutron/openstack-helm/metadata_proxy",
        )

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout:
            self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def is_metadata_alive():
    """Test if agent can respond to message over the socket"""

    headers = {
        "X-Forwarded-For": "169.254.169.254",
        "X-Neutron-Router-ID": "pod-health-probe-check-ignore-errors",
    }

    h = httplib2.Http(timeout=30)

    try:
        resp, content = h.request(
            "http://169.254.169.254",
            method="GET",
            headers=headers,
            connection_type=UnixDomainHTTPConnection,
        )
    except socket.error as se:
        msg = "Socket error: Health probe failed to connect to " "Neutron Metadata agent: "
        if se.strerror:
            LOG.error(msg, se.strerror)
        elif getattr(se, "message", False):
            LOG.error(msg, se.message)
        return False
    except Exception as ex:
        message = getattr(ex, "message", str(ex))
        LOG.info("Health probe caught exception sending message to " "Neutron Metadata agent: %s" % message)
        return True

    if resp.status >= 500:  # Probe expects HTTP error code 404
        msg = "Health probe failed: Neutron Metadata agent failed to process request: "
        LOG.error(msg, resp.__dict__)
        return False
    return True


def does_respond_to_rpc():
    """Verify agent status. Return success if agent consumes message"""
    rabbit_url = cfg.get("DEFAULT", "transport_url").replace("rabbit://", "amqp://")
    host = _get_hostname()
    agent_type = opts.rabbitmq_queue_name
    exchange_name = opts.rabbitmq_exchange
    queue_name = "health_probe.{0}.{1}".format(agent_type, host)

    msg = {"method": "oslo_rpc_server_ping"}
    msg.update({"_msg_id": uuid.uuid4().hex})
    msg.update({"_reply_q": queue_name})
    msg.update({"_timeout": None})
    msg = rpc_common.serialize_msg(msg)

    def _process_message(body, message):
        message.ack()
        data = rpc_common.deserialize_msg(message.payload)
        if data.get("result") == "pong":
            return
        # For case when pong not supported.
        if "failure" not in data:
            LOG.error("Expect failure, but didn't get it.")
            raise Exception("Expect failure, but didn't get it.")
        raise rpc_common.deserialize_remote_exception(data["failure"], allowed_remote_exmods=[])

    try:
        conn = Connection(rabbit_url, connect_timeout=opts.rabbitmq_connect_timeout)
        try:
            channel = conn.channel()
            exchange = Exchange(exchange_name, type="topic", durable=False)
            producer = Producer(exchange=exchange, channel=channel, routing_key="")
            queue = Queue(name=queue_name, exchange=exchange, routing_key="")
            queue.maybe_bind(conn)
            queue.declare()
            producer.publish(msg, routing_key="{0}.{1}".format(agent_type, host))
        except Exception as e:
            LOG.debug("Failed to send ping, not failing.")
            return True

        with Consumer(conn, queues=queue, callbacks=[_process_message]):
            timeout = opts.rabbitmq_rpc_timeout
            try:
                conn.drain_events(timeout=timeout)
            except oslo_messaging.rpc.client.RemoteError as re:
                LOG.debug("Got reply from peer.")
                return True
            except socket.timeout:
                LOG.error("Didn't get reply in {0}".format(timeout))
                return False
            except Exception as e:
                LOG.error("Go unknown exception. {0}".format(e))
                return False
            return True
    except Exception as e:
        LOG.debug("Failed to send ping, not failing.")
        return True
    finally:
        conn.release()

def is_keepalived_running(router_id):
    """Test checks for router keepalived process

    :param router_id: The uuid of the router
    :returns True: in case keepalived process found
    :returns False: in case namespace or keepalived is not found.
    """

    ns_name = "qrouter-%s" % router_id
    if ns_name not in netns.listnetns():
        LOG.debug("Can't find namespace for router: %s", router_id)
        return False

    pids = psutil.pids()
    router_ka_conf = "%s/keepalived.conf" % router_id
    for pid in pids:
        process = psutil.Process(pid)
        if "keepalived" == process.name():
            if router_ka_conf in " ".join(process.cmdline()):
                return True

    LOG.debug("Not found keepalived process for router %s", router_id)
    return False


def is_l3_agent_synced():
    """Check that l3 agent was initialized

    Checks that keepalived process is running in all HA router
    namespaces. The list of routers is taken from sync_ha_routers_info
    which is prepared by neutron-l3-agent.
    In case sync_ha_routers_info no found skipping check.

    :returns True: * In case sync_ha_routers_info no found
                   * In case were moved initialized state earlier,
                     useful only for readiness probe as they are periodic.
                   * all routers were synced.
    """
    sync_ha_routers_path = os.path.join(
        cfg.get("DEFAULT", "state_path", fallback="/var/lib/neutron"),
        "sync_ha_routers_info",
    )

    if not os.path.exists(sync_ha_routers_path):
        LOG.info(
            "The %s doesn't exists. Do not wait for initial state.",
            sync_ha_routers_path,
        )
        return True
    with open(sync_ha_routers_path, "r") as f:
        for router_id in f.readlines():
            router_id = router_id.strip()
            if router_id == "synced":
                return True
            elif router_id == "started":
                LOG.info("Waiting unless sync info is populated.")
                return False

            if not is_keepalived_running(router_id):
                LOG.error("The router: %s is not initialized.", router_id)
                return False

    with open(sync_ha_routers_path, "w") as f:
        f.write("synced")

    LOG.info("All routers were initialized.")
    return True


def is_ovs_agent_synced():
    """Check that ovs agent was initialized

    Checks whether sync_state file has been created and has ready state.

    :returns True: * In case sync_state is in state ready (ovs agent has configured
                     flows in ovs)
                   * In case support_sync_ovs_info is not configured
    """
    sync_ovs_path = os.path.join(cfg.get("DEFAULT", "state_path", fallback="/var/lib/neutron"), "ovs/sync_state")

    if not cfg.getboolean("DEFAULT", "support_sync_ovs_info", fallback=True):
        LOG.info("Checking ovs sync is skipped")
        return True

    if not os.path.exists(sync_ovs_path):
        LOG.info("The %s doesn't exists, waiting for ovs sync to be ready", sync_ovs_path)
        return False
    with open(sync_ovs_path, "r") as f:
        state = f.readlines()[0].strip()
        if state == "ready":
            LOG.info("OVS agent has been synced")
            return True
        else:
            LOG.info(
                "Ovs agent sync state is %s. Waiting unless ovs sync state is ready",
                state,
            )
            return False


def is_portprober_agent_synced():
    """Check that portprober agent was initialized

    Checks whether sync_state file has been created and has ready state.

    :returns True: * In case sync_state is in state ready (portprober agent has configured
                     probes for its ports.)
    """
    sync_path = os.path.join(cfg.get("DEFAULT", "state_path", fallback="/var/lib/neutron"), "portprober/sync_state")

    if not os.path.exists(sync_path):
        LOG.info("The %s doesn't exists, waiting for portprober sync finished", sync_path)
        return False
    with open(sync_path, "r") as f:
        state = f.readlines()[0].strip()
        if state == "finished":
            LOG.info("The portprober agent has been synced.")
            return True
        else:
            LOG.info(
                "The portprober agent sync state is %s. Waiting unless ovs sync state finished.",
                state,
            )
            return False


if __name__ == "__main__":
    cfg = configparser.ConfigParser()
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-file", action="append")
    parser.add_argument("--probe-type", required=True, choices=["liveness", "readiness"])
    parser.add_argument("--use-fqdn", required=False)
    parser.add_argument("--rabbitmq-queue-name", required=True)
    parser.add_argument("--rabbitmq-exchange", default="neutron")
    parser.add_argument("--process-name", required=True)
    parser.add_argument("--rabbitmq-rpc-timeout", type=int, required=True)
    parser.add_argument("--rabbitmq-connect-timeout", type=int, default=15)
    opts = parser.parse_args()

    cfg.read(opts.config_file)

    # There are 3 types of probes
    # * liveness - will trigger pod restart
    # * readiness - will allow to send traffic to service
    #               for non API services is usefull only
    #               during rolling updates
    # * startup - added in 1.15, executed once during startup

    pidfile = "/tmp/%s.pid" % opts.probe_type  # nosec
    data = read_json_file(pidfile)
    if data:
        if psutil.pid_exists(int(data["pid"])):
            if data["exit_count"] > 1:
                # Third time in, kill the previous process
                os.kill(int(data["pid"]), signal.SIGTERM)
            else:
                data["exit_count"] += 1
                with open(pidfile, "w") as f:
                    json.dump(data, f)
                sys.exit(0)
    data["pid"] = os.getpid()
    data["exit_count"] = 0
    with open(pidfile, "w") as f:
        json.dump(data, f)

    if opts.probe_type == "readiness":
        # Check connection to rabbitmq is established, when rabbitmq server is down
        # mark pods as not ready, but do not fail as this is a readiness probe.
        if not is_connected_to_rabbitmq(opts.process_name):
            LOG.error("Connection to rabbitmq is not established.")
            sys.exit(1)

        if "openvswitch_agent.ini" in ",".join(sys.argv):
            if not is_ovs_agent_synced():
                LOG.error("The ovs agent is not synced yet.")
                sys.exit(1)

        if "portprober_agent.ini" in ",".join(sys.argv):
            if not is_portprober_agent_synced():
                LOG.error("The portprober agent is not synced yet.")
                sys.exit(1)

        if opts.rabbitmq_queue_name == "l3_agent":
            if not is_l3_agent_synced():
                LOG.error("L3 agent is not synced yet.")
                sys.exit(1)

        if "sriov_agent.ini" in ",".join(opts.config_file):
            if not is_sriov_ready():
                LOG.error("The sriov readiness failed.")
                sys.exit(1)

    if opts.probe_type == "liveness":
        # NOTE(vsaienko): the metadata agent doesn't respond to RPC
        # it only polling neutron server.
        if opts.rabbitmq_queue_name == "metadata_agent":
            if not is_metadata_alive():
                LOG.error("Connection to metadata service failed")
                sys.exit(1)
        else:
            if not does_respond_to_rpc():
                # NOTE(vsaienko): when not respond to rpc, check if agent is connected
                # to rmq, maybe agent is busy.
                # TODO(vsaienko): do not fail for specific attempts.
                if not is_connected_to_rabbitmq(opts.process_name):
                    LOG.error("The agent doesn't respond to RPC, and connection to rabbit not established")
                    sys.exit(1)
                LOG.warning("The agent doesn't respond to RPC.")
    sys.exit(0)  # return success
