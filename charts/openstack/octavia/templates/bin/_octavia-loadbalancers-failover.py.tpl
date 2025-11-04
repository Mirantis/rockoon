#!/usr/bin/env python3

{{/*
Copyright 2025 Mirantis Inc.

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

import sys
import os
import yaml
import logging
import time
import ssl
import configparser
import socket
import struct
from enum import Enum, auto

from concurrent.futures import ThreadPoolExecutor, ALL_COMPLETED, wait
from keystoneauth1 import exceptions as ksa_exceptions
import openstack
from openstack.exceptions import (
    ResourceTimeout,
    ResourceNotFound,
    SDKException,
)
from retry import retry
import urllib3
from urllib3.exceptions import (
    SSLError,
    ConnectionError,
    ConnectTimeoutError,
)


def strtobool(v):
    """Convert a string representation of truth to boolean.

    :param v: string to convert
    :returns: True if string represents true, False otherwise
    """
    return str(v).lower() in ("yes", "true", "t", "1")


LB_FAILOVER_LOG_LEVEL = os.environ.get("LB_FAILOVER_LOG_LEVEL", "DEBUG").upper()
LB_FAILOVER_MAX_WORKERS = int(os.environ.get("LB_FAILOVER_MAX_WORKERS", 5))
LB_FAILOVER_AMPHORA_AGENT_PORT = int(os.environ.get("LB_FAILOVER_AMPHORA_AGENT_PORT", 9443))

LB_FAILOVER_RETRY_DELAY = int(os.environ.get("LB_FAILOVER_RETRY_DELAY", 5))
LB_FAILOVER_RETRY_ATTEMPTS = int(os.environ.get("LB_FAILOVER_RETRY_ATTEMPTS", 7))
LB_FAILOVER_RETRY_BACKOFF = int(os.environ.get("LB_FAILOVER_RETRY_BACKOFF", 10))


class SUPPORTED_FAILOVER_LB_CASES(Enum):

    # When certificate is expired on amphora
    AMPHORA_CERT_EXPIRED = auto()

    # When amphora is missing due to some reason
    AMPHORA_MISSING = auto()

    # When amphora is unreachable
    AMPHORA_UNREACHABLE = auto()

    # When LB provisioning status is error
    PROVISIONING_STATUS_ERROR = auto()


FAILOVER_LB_CASES = os.environ.get(
    "FAILOVER_LB_CASES",
    "AMPHORA_CERT_EXPIRED,PROVISIONING_STATUS_ERROR,AMPHORA_UNREACHABLE",
).split(",")

CA_CERT_PATH = "/etc/octavia/certs/ca_01.pem"
CLIENT_CERT_PATH = "/etc/octavia/certs/client.pem"
LB_OPERATION_INTERVAL = 30
LB_OPERATION_TIMEOUT = 300
AMPHORA_CONNECTION_TIMEOUT = 10
AMPHORA_LB_PROVIDERS = ["amphora", "amphorav2"]

LOG = logging.getLogger(__name__)
logging.basicConfig(
    stream=sys.stdout,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOG.setLevel(LB_FAILOVER_LOG_LEVEL)

OCTAVIA_SETTINGS_CONF_PATH = "/etc/octavia/settings.conf"
def get_health_manager_ips():
    """Parse Octavia settings.conf to get health manager IP addresses.

    :returns: list of IP addresses of Octavia health managers
    """
    ips = []
    cfg = configparser.ConfigParser(strict=False)
    cfg.read(OCTAVIA_SETTINGS_CONF_PATH)
    ip_ports = cfg.get("health_manager", "controller_ip_port_list", fallback="")
    for ip_port in ip_ports.split(","):
        ip = ip_port.split(":")[0]
        if ip:
            ips.append(ip)
    return ips

OCTAVIA_HEALTH_MANAGER_IPS = get_health_manager_ips()


class AmphoraLivenessStatus(Enum):
    ALIVE = auto()
    UNREACHABLE = auto()
    CERT_EXPIRED = auto()


class LBFailoverStatus(Enum):
    SUCCESS = auto()  # When failover succeded
    FAILED = auto()  # When failover failed
    SKIPPED = auto()  # When we skip failover
    CANCELLED = auto()  # When lb dissapear during failover


def handle_retry_exception(e):
    if isinstance(e, ResourceNotFound):
        raise e


@retry(
    (SDKException, ksa_exceptions.base.ClientException),
    delay=1,
    tries=7,
    backoff=2,
    logger=LOG,
)
def get_loadbalancers(oc):
    return list(oc.load_balancer.load_balancers())


@retry(
    (SDKException, ksa_exceptions.base.ClientException),
    delay=1,
    tries=7,
    backoff=2,
    logger=LOG,
    on_exception=handle_retry_exception,
)
def get_loadbalancer(lb_id, oc):
    return oc.load_balancer.get_load_balancer(lb_id)


@retry(
    (SDKException, ksa_exceptions.base.ClientException),
    delay=1,
    tries=7,
    backoff=2,
    logger=LOG,
    on_exception=handle_retry_exception,
)
def get_amphorae_for_lb(lb_id, oc):
    return list(oc.load_balancer.amphorae(loadbalancer_id=lb_id))


@retry(
    (SDKException, ksa_exceptions.base.ClientException),
    delay=1,
    tries=7,
    backoff=2,
    logger=LOG,
    on_exception=handle_retry_exception,
)
def failover_loadbalancer(lb_id, oc):
    oc.load_balancer.failover_load_balancer(lb_id)


def wait_for_lb_provisioning_status(
    oc,
    lb_id,
    expected_status="active",
    interval=LB_OPERATION_INTERVAL,
    timeout=LB_OPERATION_TIMEOUT,
):
    """Wait for loadbalancer is ACTIVE

    :param oc: openstack connection from opesntacksdk
    :param lb_id: UUID of loadbalancer
    :param expected_status: expected provisioning status in lowercase
    :param interval: interval in seconds between check attempts
    :param timeout: timeout in seconds to wait for LB active

    :returns: when reached target provision state
    :raises RsourceTimeout: when timed out
    :raises RuntimeError: when loadbalancer switched to ERROR state.
    """

    start = time.time()
    while time.time() - start < timeout:
        lb = get_loadbalancer(lb_id, oc)
        lb_status = lb.provisioning_status.lower()
        if not lb_status:
            time.sleep(interval)
            continue
        if lb_status == expected_status.lower():
            return
        if lb_status == "error":
            raise RuntimeError(
                f"Load balancer {lb_id} in ERROR provisioning status"
            )
        time.sleep(interval)
    raise ResourceTimeout(
        f"Timeout waiting for load balancer {lb_id} status reach {expected_status} in {timeout}. Last status was {lb_status}"
    )


def get_amphora_liveness_status(
    amphora_ip, port=LB_FAILOVER_AMPHORA_AGENT_PORT
) -> AmphoraLivenessStatus:
    """Return status of loadbalancer amphora

    :param amphora_ip: IP address of the amphora
    :param port: port where amphora is listening on

    :returns: one of AmphoraLivenessStatus
    """

    url = f"https://{amphora_ip}:{port}"

    ctx = ssl.create_default_context(cafile=CA_CERT_PATH)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(certfile=CLIENT_CERT_PATH)

    try:
        http = urllib3.PoolManager(ssl_context=ctx, assert_hostname=False)
        response = http.request(
            "GET", url, timeout=AMPHORA_CONNECTION_TIMEOUT, retries=False
        )
        if response.status == 200:
            return AmphoraLivenessStatus.ALIVE
    except SSLError as e:
        LOG.debug("Amphora %s certificate is not valid %s.", amphora_ip, e)
        return AmphoraLivenessStatus.CERT_EXPIRED
    except (ConnectTimeoutError, ConnectionError) as e:
        LOG.debug("Amphora %s is unreachable.", amphora_ip)
        return AmphoraLivenessStatus.UNREACHABLE
    except Exception as e:
        LOG.error(
            "Unknown exception %s occured while checking amphora %s",
            e,
            amphora_ip,
        )
        return AmphoraLivenessStatus.UNKNOWN
    return AmphoraLivenessStatus.UNKNOWN


def checksum(data):
    """Calculate checksum for ICMP packet.

    :param data: bytes of data to checksum
    :returns: 16-bit checksum value
    """
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ping(host, timeout=2):
    """Send ICMP echo request to host.

    :param host: target IP
    :param timeout: timeout in seconds for reply
    :returns: True if host replied, False otherwise
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)

        icmp_type = 8
        icmp_code = 0
        icmp_checksum = 0
        run_id = os.getpid() & 0xFFFF

        icmp_seq = ((run_id & 0xFF00) | 1)

        header = struct.pack("bbHHh", icmp_type, icmp_code, icmp_checksum, run_id, icmp_seq)
        icmp_checksum = checksum(header)
        header = struct.pack("bbHHh", icmp_type, icmp_code, socket.htons(icmp_checksum), run_id, icmp_seq)
        packet = header

        sock.sendto(packet, (host, 0))

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                recv_packet, addr = sock.recvfrom(1024)
                if len(recv_packet) >= 8:
                    r_type, r_code, r_checksum, r_id, r_seq = struct.unpack("bbHHh", recv_packet[:8])
                    if r_type == 0 and (run_id >> 8) == (r_seq >> 8):
                        return True
            except socket.timeout:
                LOG.debug(f"Socket recv timeout while waiting for ICMP reply from {host}")
    except (socket.gaierror, socket.timeout, OSError) as e:
        LOG.debug(f"Ping failed for {host}: {e}")
    finally:
        if sock:
            sock.close()
    return False


@retry(
    (Exception),
    delay=1,
    tries=3,
    backoff=1,
    logger=LOG,
)
def ping_with_retry(host, timeout=2):
    """Ping a host with retry logic.

    :param host: target IP
    :param timeout: timeout in seconds for a single ping attempt
    :returns: True if ping succeeded
    :raises RuntimeError: if ping fails after retries
    """
    if not ping(host, timeout=timeout):
        raise RuntimeError(f"Ping failed for {host}")
    return True


def has_connectivity_to_health_managers():
    """Check connectivity to all Octavia health managers.

    :returns: True if all health managers are reachable, False otherwise
    """
    for ip in OCTAVIA_HEALTH_MANAGER_IPS:
        try:
            ping_with_retry(ip)
        except Exception as e:
            LOG.warning("Error pinging health manager after retries: %s - %s", ip, e)
            return False
    LOG.debug("Ping to health managers %s succeeded", OCTAVIA_HEALTH_MANAGER_IPS)
    return True


def is_amphora_failover_needed(amphora):
    """Check if amphora failover is needed

    :param amphora: openstacksdk amphora object
    :returns True: When failover of amphora is needed.
    :returns False: When failover is not needed
    """

    status = get_amphora_liveness_status(amphora.lb_network_ip)
    if (
        status == AmphoraLivenessStatus.CERT_EXPIRED
        and SUPPORTED_FAILOVER_LB_CASES.AMPHORA_CERT_EXPIRED.name
        in FAILOVER_LB_CASES
    ):
        LOG.info(
            "Amphora %s certificate is expired, failover is needed", amphora.id
        )
        return True

    if (
        status == AmphoraLivenessStatus.UNREACHABLE
        and SUPPORTED_FAILOVER_LB_CASES.AMPHORA_UNREACHABLE.name
        in FAILOVER_LB_CASES
    ):
        LOG.info("Amphora %s is unreachable, failover is needed", amphora.id)
        return True
    return False


def is_failover_needed(oc, lb):
    """Determines whether a load balancer should be failover.

    The full list of cases for failover is defined by SUPPORTED_FAILOVER_LB_CASES

    :param oc: openstack connection from openstacksdk
    :param lb: lb instance from openstacksdk

    :returns: True when failover is needed, False otherwise
    """

    LOG.debug("Checking if failover is needed for lb %s", lb)

    if lb.provisioning_status == "ERROR":
        if (
            SUPPORTED_FAILOVER_LB_CASES.PROVISIONING_STATUS_ERROR.name
            in FAILOVER_LB_CASES
        ):
            LOG.debug(
                "Load balancer %s needs failover due to provisioning status: %s",
                lb.id,
                lb.provisioning_status,
            )
            return True

    if lb.provider in AMPHORA_LB_PROVIDERS:
        LOG.debug("Checking loadbalancer %s amphoras", lb.id)
        amphorae = get_amphorae_for_lb(lb.id, oc)

        if (
            len(amphorae) == 0
            and SUPPORTED_FAILOVER_LB_CASES.AMPHORA_MISSING.name
            in FAILOVER_LB_CASES
        ):
            LOG.debug("Amphora is missing for lb %s", lb.id)
            return True

        for amphora in amphorae:
            if is_amphora_failover_needed(amphora):
                LOG.debug("Load balancer %s needs failover", lb.id)
                return True

    LOG.debug("Loadbalancer %s failover is not needed", lb.id)
    return False


@retry(
    (Exception),
    delay=LB_FAILOVER_RETRY_DELAY,
    tries=LB_FAILOVER_RETRY_ATTEMPTS,
    backoff=LB_FAILOVER_RETRY_BACKOFF,
    logger=LOG,
    on_exception=handle_retry_exception,
)
def do_lb_failover(oc, lb_id):
    """Perform Loadbalacenr failover if needed with retries

    :param oc: openstack connection object
    :param lb_id: UUID of Loadbalancer
    """

    LOG.info("Triggering failover for load balancer: %s", lb_id)
    failover_loadbalancer(lb_id, oc)
    LOG.info("Waiting for load balancer %s to reach ACTIVE status...", lb_id)

    # TODO(vsaienko): do not know if status is changed immidiately, maybe we need to add some
    # weiter here that LB status was changed.
    time.sleep(15)
    wait_for_lb_provisioning_status(oc, lb_id, "active")
    LOG.info("Successfully failover load balancer: %s", lb_id)

    # NOTE(vsaienko): we trust octavia API if provisioning status is ACTIVE we assume
    # amphoras are reachable, but may extend with additional check in future.


def handle_lb_failover(lb_id):
    """Handle loadbalancer failover

    :param lb_id: Loadbalancer uuid

    :returns: One of LBFailoverStatus states.
    """
    # TODO(dbiletskyi): consider handling the case where the load balancer starts failing
    # after failover. Might need to recheck LB state and stop the job to prevent disrupting
    # all load balancers in the environment.
    oc = openstack.connect()
    try:
        lb = get_loadbalancer(lb_id, oc)
        LOG.info("Checking load balancer: %s", lb_id)
        if is_failover_needed(oc, lb):
            do_lb_failover(oc, lb_id)
            return LBFailoverStatus.SUCCESS
    except ResourceNotFound:
        LOG.error("Loadbalancer %s was removed while handled it.", lb_id)
        return LBFailoverStatus.CANCELLED
    except Exception as e:
        LOG.error("Failed to failover load balancer: %s. Error: %s", lb_id, e)
        return LBFailoverStatus.FAILED
    return LBFailoverStatus.SKIPPED


def validate_failover_lb_cases(cases):
    good_cases = list(SUPPORTED_FAILOVER_LB_CASES.__members__.keys())
    for case in cases:
        if case not in good_cases:
            raise Exception(
                f"Invalid configuration, {case} not in {good_cases}"
            )

    LOG.info(
        "Script is configured to perform LB failover for the following cases %s",
        cases,
    )


def main():

    # validate if input parameters are okay.
    validate_failover_lb_cases(FAILOVER_LB_CASES)

    # check connectivity to Octavia health managers before starting
    if not has_connectivity_to_health_managers():
        LOG.error("Cannot connect to octavia health managers. Likely network issue on this node.")
        sys.exit(1)

    oc = openstack.connect()
    statistics = {k: [] for k in list(LBFailoverStatus.__members__)}
    lbs = get_loadbalancers(oc)

    with ThreadPoolExecutor(max_workers=LB_FAILOVER_MAX_WORKERS) as executor:
        future_data = {}

        for lb in lbs:
            future = executor.submit(handle_lb_failover, lb.id)
            future_data[lb.id] = future

    wait(future_data.values(), return_when=ALL_COMPLETED)
    for lb_id, future in future_data.items():
        try:
            result = future.result()
            statistics[result.name].append(lb_id)
        except Exception as e:
            LOG.error(
                "Exception while processing load balancer %s: %s", lb_id, e
            )
            statistics[LBFailoverStatus.FAILED.name].append(lb_id)
            continue

    total_lbs = len(lbs)
    stats_msg = "General statistic for loadbalancer failover:\n"
    for status, lbs in statistics.items():
        stats_msg += f"  {status}: {len(lbs)}"

    LOG.debug("Detailed statistics:\n%s", yaml.dump(statistics))
    LOG.info(stats_msg)

    failed_lbs = statistics[LBFailoverStatus.FAILED.name]
    if failed_lbs:
        LOG.error("Failover failed for load balancers: %s", failed_lbs)
        sys.exit(1)


if __name__ == "__main__":
    main()
