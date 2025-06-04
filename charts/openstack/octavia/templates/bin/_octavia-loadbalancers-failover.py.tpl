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
from urllib3.exceptions import SSLError, ConnectionError


def strtobool(v):
    # Clone from the now-deprecated distutils
    return str(v).lower() in ("yes", "true", "t", "1")


LB_FAILOVER_FAIL_ON_ERROR = strtobool(os.environ.get("LB_FAILOVER_FAIL_ON_ERROR", "True"))
LB_FAILOVER_LOG_LEVEL = os.environ.get("LB_FAILOVER_LOG_LEVEL", "DEBUG").upper()
LB_FAILOVER_MAX_WORKERS = int(os.environ.get("LB_FAILOVER_MAX_WORKERS", 5))
LB_FAILOVER_AMPHORA_AGENT_PORT = int(os.environ.get("LB_FAILOVER_AMPHORA_AGENT_PORT", 9443))

LB_FAILOVER_RETRY_DELAY = int(os.environ.get("LB_FAILOVER_RETRY_DELAY", 5))
LB_FAILOVER_RETRY_ATTAMPTS = int(os.environ.get("LB_FAILOVER_RETRY_ATTAMPTS", 7))
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
    except ConnectionError as e:
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

    # TODO(vsaienko): other cases like unreachable will require more careful checks. For example if we have connectivity
    # issues from the node where this job is running all amphoras will be marked as unreachable, so we need to have
    # additional checks before handling UNREACHABLE cases.
    if (
        status == AmphoraLivenessStatus.UNREACHABLE
        and SUPPORTED_FAILOVER_LB_CASES.AMPHORA_UNREACHABLE.name
        in FAILOVER_LB_CASES
    ):
        LOG.warning(
            "Amphora %s is unreachable, but we not sure if its amohora fault, skip failover.",
            amphora.id,
        )
        return False
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
    tries=LB_FAILOVER_RETRY_ATTAMPTS,
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
    oc = openstack.connect()
    lb = get_loadbalancer(lb_id, oc)
    LOG.info("Checking load balancer: %s", lb_id)
    try:
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
        LOG.warning("Failover failed for load balancers: %s", failed_lbs)
        if LB_FAILOVER_FAIL_ON_ERROR:
            LOG.error("One or more failovers failed. Exiting with error.")
            sys.exit(1)


if __name__ == "__main__":
    main()
