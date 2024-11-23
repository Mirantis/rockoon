#!/usr/bin/env python

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Health probe script for OpenStack service that uses RPC/unix domain socket for
communication. Check's the RPC tcp socket status on the process and send
message to service through rpc call method and expects a reply.
Use nova's ping method that is designed just for such simple purpose.

Script returns failure to Kubernetes only when
  a. TCP socket for the RPC communication are not established.
  b. service is not reachable or
  c. service times out sending a reply.

sys.stderr.write() writes to pod's events on failures.

Usage example for Nova Compute:
# python health-probe.py --config-file /etc/nova/nova.conf \
#  --rabbitmq-queue-name compute --process-name nova-compute

"""

import json
import os
import argparse
import configparser
import psutil
import signal
import socket
import sys
import uuid
import logging

import oslo_messaging
from oslo_messaging._drivers import common as rpc_common
from six.moves.urllib import parse as urlparse
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

def get_database_ports():
    "Get Database ports"
    sockets = []
    connection = cfg.get("database", "connection", fallback=None)
    if not connection:
        return sockets
    connection = urlparse.urlparse(connection)
    return [(connection.hostname, connection.port)]

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

def is_connected_to_database(process_name):
    sockets = get_database_ports()
    return is_connected_to(process_name, sockets)

def _get_hostname():
    if opts.use_fqdn:
        return socket.getfqdn()
    return socket.gethostname()

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

def check_process_is_our(proc):
    cmdline = proc.cmdline()
    for arg in sys.argv:
        if arg not in cmdline:
            return False
    return True

if __name__ == "__main__":
    # Mask permissions to files 416 dirs 0750
    os.umask(0o027)
    cfg = configparser.ConfigParser()
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-file", action="append")
    parser.add_argument("--probe-type", required=True, choices=["liveness", "readiness"])
    parser.add_argument("--rabbitmq-queue-name", required=False)
    parser.add_argument("--rabbitmq-exchange", default="nova")
    parser.add_argument("--rabbitmq-rpc-timeout", type=int, required=True)
    parser.add_argument("--rabbitmq-connect-timeout", type=int, default=15)
    parser.add_argument("--process-name", required=True)
    parser.add_argument("--use-fqdn", required=False)
    opts = parser.parse_args()

    cfg.read(opts.config_file)

    pidfile = "/tmp/%s.pid" % opts.probe_type  # nosec
    data = read_json_file(pidfile)
    if data:
        try:
            proc = psutil.Process(int(data["pid"]))
            if data["exit_count"] > 1 and check_process_is_our(proc):
                # Third time in, kill the previous process
                try:
                    os.kill(int(data["pid"]), signal.SIGTERM)
                except PermissionError:
                    pass
            else:
                data["exit_count"] += 1
                with open(pidfile, "w") as f:
                    json.dump(data, f)
                sys.exit(0)
        except psutil.NoSuchProcess:
            pass
    data["pid"] = os.getpid()
    data["exit_count"] = 0
    with open(pidfile, "w") as f:
        json.dump(data, f)

    if opts.probe_type == "readiness":
        if not is_connected_to_rabbitmq(opts.process_name):
            LOG.error("Process: {0} not connected to rabbitmq.".format(opts.process_name))
            sys.exit(1)
        if opts.process_name != 'nova-compute':
            if not is_connected_to_database(opts.process_name):
                LOG.error("Process: {0} not connected to rabbitmq.".format(opts.process_name))
                sys.exit(1)

    elif opts.probe_type == "liveness":
        if opts.rabbitmq_queue_name and not does_respond_to_rpc():
            # NOTE(vsaienko): when not respond to rpc, check if agent is connected
            # to rmq, maybe agent is busy.
            # TODO(vsaienko): do not fail for specific attempts.
            if not is_connected_to_rabbitmq(opts.process_name):
                LOG.error("The agent doesn't respond to RPC, and connection to rabbit not established")
                sys.exit(1)
            LOG.warning("The agent doesn't respond to RPC.")
