#    Copyright 2020 Mirantis, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import datetime

import kopf

from rockoon import constants as const
from rockoon import kube
from rockoon import maintenance
from rockoon import openstack_utils as ostutils
from rockoon import settings
from rockoon import utils

LOG = utils.get_logger(__name__)
CONF = settings.CONF


@kopf.on.field("", "v1", "nodes", field="status.conditions")
def node_status_update_handler(name, body, old, new, reason, **kwargs):
    LOG.debug(f"Handling node status {reason} event.")
    utils.log_changes(kwargs.get("old", {}), kwargs.get("new", {}))

    osdpl = kube.get_osdpl()
    if not osdpl or not osdpl.exists():
        LOG.info("Can't find OpenStackDeployment object")
        return

    # NOTE(vsaienko) get conditions from the object to avoid fake reporing by
    # calico when kubelet is down on the node.
    # Do not remove pods from flapping node.
    kube_api = kube.kube_client()
    node = kube.Node(kube_api, body)
    if node.ready:
        return True

    not_ready_delta = datetime.timedelta(
        seconds=CONF.getint("osctl", "node_not_ready_flapping_timeout")
    )

    # TODO(vsaienko) get last heartbeat time from status
    now = last_transition_time = datetime.datetime.utcnow()

    for cond in node.obj["status"]["conditions"]:
        if cond["type"] == "Ready":
            last_transition_time = datetime.datetime.strptime(
                cond["lastTransitionTime"], "%Y-%m-%dT%H:%M:%SZ"
            )
    not_ready_for = now - last_transition_time
    if now - not_ready_delta < last_transition_time:
        raise kopf.TemporaryError(
            f"The node is not ready for {not_ready_for.seconds}s out of {not_ready_delta.total_seconds()}s. This may be a flap. Waiting.",
        )
    LOG.info(
        f"The node {name} is not ready for {not_ready_for.seconds}s. The node is down permanently."
    )

    LOG.info(f"Removing pods from node {name}")
    node.remove_pods(settings.OSCTL_OS_DEPLOYMENT_NAMESPACE)

    if node.has_role(const.NodeRole.compute):
        ostutils.handle_masakari_host_down(node)


# NOTE(avolkov): watching for update events covers
# the case when node is relabeled and NodeWorkloadLock
# has to be created/deleted accordingly
@kopf.on.create("", "v1", "nodes")
@kopf.on.update("", "v1", "nodes")
@kopf.on.resume("", "v1", "nodes")
def node_change_handler(body, reason, **kwargs):
    name = body["metadata"]["name"]
    LOG.info(f"Got event {reason} for node {name}")
    utils.log_changes(kwargs.get("old", {}), kwargs.get("new", {}))

    kube_api = kube.kube_client()
    node = kube.Node(kube_api, body)
    nwl = maintenance.NodeWorkloadLock.get_by_node(name)
    if nwl.required_for_node(node.name):
        nwl.present()
    else:
        LOG.info(
            f"We do not have OS workloads on node {name} anymore. Remove NodeWorkloadLock."
        )
        nwl.absent(propagation_policy="Background")


@kopf.on.delete("", "v1", "nodes")
def node_delete_handler(body, **kwargs):
    name = body["metadata"]["name"]
    LOG.info(f"Got delete event for node {name}")
    nwl = maintenance.NodeWorkloadLock.get_by_node(name)
    ndn = maintenance.find_ndn(name)
    # NOTE(vsaienko): when node is disabled do not remove nwl
    if not (ndn and ndn.exists()):
        # NOTE(vsaienko): we start OpenStack metadata cleanup on nwl removal.
        # Do not lock node deletion here, as we wait node is deleted and services
        # are not running anymore before starting to remove them.
        LOG.info(
            f"Removing nodeworkloadlock for node {name} as node was deleted."
        )
        nwl.absent(propagation_policy="Background")
