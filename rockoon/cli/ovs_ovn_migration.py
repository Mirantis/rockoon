#!/usr/bin/env python3
import asyncio
import argparse
import traceback
import ipaddress
import json
import logging
import re
import sys
import time
import yaml

from concurrent.futures import ThreadPoolExecutor, ALL_COMPLETED, wait
from pykube import ConfigMap

from rockoon import constants
from rockoon import health
from rockoon import helm
from rockoon import kube
from rockoon import utils
from rockoon import osdplstatus
from rockoon import resource_view
from rockoon import services
from rockoon import settings
from rockoon.openstack_utils import OpenStackClientManager

MIGRATION_FINALIZER = "lcm.mirantis.com/ovs-ovn-migration.finalizer"
MIGRATION_STATE_CONFIGMAP_NAME = "ovs-ovn-migration-state"
BACKUP_NEUTRON_DB_PATH = "/var/lib/mysql"
MARIADB_FULL_BACKUP_TIMEOUT = 1200
MARIADB_NEUTRON_BACKUP_TIMEOUT = 600

TYPE_VXLAN = "vxlan"
DEFAULT_GENEVE_HEADER_SIZE = 38
IP_HEADER_LENGTH = {
    4: 20,
    6: 40,
}

# Stage statuses
STARTED, COMPLETED, FAILED = ("started", "completed", "failed")


def set_args():
    parser = argparse.ArgumentParser(
        prog="osctl-ovs-ovn-migrate",
        description="Migrate from OVS neutron backend to OVN.",
    )
    subparsers = parser.add_subparsers(
        help="Parse subcommands of migration script", dest="mode"
    )
    subparsers.add_parser(
        "backup_db", help="Backup Neutron database before migration"
    )
    migrate_subparcer = subparsers.add_parser(
        "migration",
        help="Start migration process",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    subparsers.add_parser(
        "preflight_checks", help="OpenStack checks before migration"
    )
    migrate_subparcer.add_argument(
        "--non-interactive",
        action="store_false",
        dest="interactive",
        help=("Run migration in non interactive mode"),
    )
    migrate_subparcer.add_argument(
        "--max-workers",
        type=int,
        default=0,
        dest="max_workers",
        help=(
            """Maximum number of workers to spawn for parallel operations.
            If set to 0, internal defaults for operations will be used.
            For example for pods parallel operations (like exec) number of workers will be
            equal to number of target pods.
            """
        ),
    )
    migrate_subparcer.add_argument(
        "--cmp-threshold",
        type=int,
        default=0,
        dest="cmp_threshold",
        help="Maximum number of compute nodes allowed to fail migration.",
    )
    migrate_subparcer.add_argument(
        "--gtw-threshold",
        type=int,
        default=0,
        dest="gtw_threshold",
        help="Maximum number of gateway nodes allowed to fail migration.",
    )

    args = parser.parse_args()
    if not args.mode:
        parser.error("Run mode does not specified")
    return args


def get_logger():
    logging_conf = yaml.safe_load(
        f"""
    disable_existing_loggers: false
    formatters:
      standard:
        format: '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    handlers:
      default:
        class: logging.StreamHandler
        formatter: standard
        stream: ext://sys.stdout
        level: INFO
      default_file:
        class: logging.FileHandler
        formatter: standard
        filename: /tmp/ovs-ovn-migration.log
        level: DEBUG
    loggers:
      aiohttp:
        level: WARNING
      kopf:
        level: INFO
      kopf.activities.probe:
        level: WARNING
      opensearch:
        level: WARNING
      rockoon:
        level: INFO
      rockoon.cli.ovs_ovn_migration:
        level: DEBUG
    root:
      handlers:
      - default
      - default_file
      level: INFO
    version: 1
    """
    )
    logging.config.dictConfig(logging_conf)
    return logging.getLogger(__name__)


LOG = get_logger()


def check_input(check, msg, error_string="Illegal Input"):
    while True:
        result = input(f"[USER INPUT NEEDED] {msg} --> ").strip()
        if check(result):
            return result
        LOG.error(error_string)


class StateCM:

    labels = {"lcm.mirantis.com/ovs-ovn-migration": "state"}

    def __init__(self, name, namespace, stages):
        self.name = name
        self.namespace = namespace
        cm = [
            cm
            for cm in kube.resource_list(
                ConfigMap,
                self.labels,
                namespace=namespace,
            )
        ]
        if len(cm) > 1:
            raise ValueError("Found more than one existing state configmap")
        if not cm:
            LOG.info("State configmap does not exist, creating")
            self.cm = self.create(stages)
        else:
            LOG.warning("State configmap already exists")
            self.cm = cm[0]

    def create(self, stages):
        """Create configmap in format:
        <stage1_name>: '{"status": "init", "error": null}'
        <stage2_name>: '{"status": "init", "error": null}'
        and returns k8s configmap object
        """
        stage_init_state = {"status": "init", "error": None}
        state_cm = kube.dummy(
            ConfigMap,
            self.name,
            namespace=self.namespace,
        )
        state_cm.metadata["labels"] = self.labels
        state_cm.obj["data"] = {
            stage["name"]: json.dumps(stage_init_state) for stage in stages
        }
        state_cm.create()
        return state_cm

    @property
    def state(self):
        self.cm.reload()
        cm_data = self.cm.obj.get("data", {})
        data = {k: json.loads(v) for k, v in cm_data.items()}
        return data

    def update(self, stage, status, error=None):
        state = self.state
        state[stage] = {"status": status, "error": error}
        self.cm.obj["data"] = {k: json.dumps(v) for k, v in state.items()}
        self.cm.update(is_strategic=False)


def get_service(osdpl, service):
    osdpl.reload()
    mspec = osdpl.mspec
    child_view = resource_view.ChildObjectView(mspec)
    osdplst = osdplstatus.OpenStackDeploymentStatus(
        osdpl.name, osdpl.namespace
    )
    svc = services.registry[service](mspec, LOG, osdplst, child_view)
    return svc


def get_objects_by_id(svc, id):
    # switch case is supported from python 3.10
    if id == "openvswitch-ovn-db":
        return [svc.get_child_object("StatefulSet", "openvswitch-ovn-db")]
    elif id == "openvswitch-ovn-northd":
        return [svc.get_child_object("StatefulSet", "openvswitch-ovn-northd")]
    elif id == "ovn-controller":
        return svc.get_child_objects_dynamic("DaemonSet", "ovn-controller")
    elif id == "openvswitch-vswitchd":
        return svc.get_child_objects_dynamic(
            "DaemonSet", "openvswitch-vswitchd"
        )
    elif id == "neutron-ovs-agent":
        return svc.get_child_objects_dynamic("DaemonSet", "neutron-ovs-agent")
    elif id == "neutron-l3-agent":
        return svc.get_child_objects_dynamic("DaemonSet", "neutron-l3-agent")
    elif id == "neutron-ovn-db-sync-migrate":
        return [svc.get_child_object("Job", "neutron-ovn-db-sync-migrate")]
    elif id == "neutron-metadata-agent":
        return svc.get_child_objects_dynamic(
            "DaemonSet", "neutron-metadata-agent"
        )
    elif id == "mariadb-server":
        return [svc.get_child_object("StatefulSet", "mariadb-server")]
    else:
        raise ValueError("Unknown object id {id}")


def update_service_release(hm, service, release_name, patch):
    """Updates only specified release for service with patched values"""
    bundle = service.render()
    for release in bundle["spec"]["releases"]:
        if release["name"] == release_name:
            utils.merger.merge(release["values"], patch)
            bundle["spec"]["releases"] = [release]
            break
    asyncio.run(hm.install_bundle(bundle))


def wait_for_objects_ready(service, object_ids, timeout=1200):
    """
    Waits for child objects of the service to be ready

    :param service: Object of type Service
    :param object_ids: List of strings
    :returns None
    """
    LOG.info(f"Waiting for {object_ids} to be ready")
    for id in object_ids:
        for obj in get_objects_by_id(service, id):
            asyncio.run(obj.wait_ready(timeout=timeout))
    LOG.info(f"{object_ids} are ready")


def daemonsets_check_exec(results, raise_on_error=True):
    failed_nodes = []
    for res in results:
        LOG.debug(
            f"""
        DaemonSet {res['daemonset']} Pod {res['pod']}:{res['container']} exec results:
            NODE:
              {res['node']}
            COMMAND:
              {res['command']}
            STATUS:
              {res['status']}
            STDERR:
              {res['stderr']}
            STDOUT:
              {res['stdout']}
            ERROR:
              {res['error_json']}
            EXCEPTION:
              {res['exception']}
        """
        )
        if res["status"] != "Success":
            failed_nodes.append(res["node"])
    if failed_nodes:
        LOG.error(f"Failed to execute command on nodes {failed_nodes}")
        if raise_on_error:
            raise RuntimeError("Failed to run exec for daemonsets")


def daemonsets_exec_parallel(
    daemonsets,
    command,
    container,
    max_workers=0,
    timeout=30,
    raise_on_error=True,
    nodes=None,
):
    """Run exec inside pods of different daemonsets in parallel
    :param daemonsets: List of kube.DaemonSet objects
    :param command: List of strings
    :param container: String with name of container chosen for command execution
    :param max_workers: Integer number of max parallel threads to spawn
    :param timeout: timeout for command execution inside pod.
    :param nodes: List of nodes selected to run command. If set, command will
                  be run only in pods on specified nodes.
    :returns List of dictionnaries in format
    """
    pods_map = {}
    pods = []
    for ds in daemonsets:
        pods_map[ds] = ds.pods
        pods.extend(pods_map[ds])
    if not max_workers:
        max_workers = len(pods)
    if nodes:
        pods = [
            pod for pod in pods if pod.obj["spec"].get("nodeName") in nodes
        ]
    # Maximum time to wait for all workers to finish
    pool_timeout = len(pods) * timeout
    args = [command]
    kwargs = {
        "container": container,
        "raise_on_error": False,
        "timeout": timeout,
    }
    future_data = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        LOG.info(
            f"Running command {command} on pods of daemonsets {daemonsets}"
        )
        for pod in pods:
            future = executor.submit(pod.exec, *args, **kwargs)
            future_data[pod] = future
        LOG.info(f"Waiting command on pods of daemonsets {daemonsets}")
        done, not_done = wait(
            future_data.values(),
            return_when=ALL_COMPLETED,
            timeout=pool_timeout,
        )
        LOG.info(f"Done waiting command on pods of daemonsets {daemonsets}")
    results = []
    for pod, future in future_data.items():
        for ds in daemonsets:
            if pod in pods_map[ds]:
                pod_ds = ds
        data = {
            "daemonset": pod_ds.name,
            "node": pod.obj["spec"].get("nodeName"),
            "pod": pod.name,
            "container": container,
            "command": command,
            "error_json": {},
            "exception": None,
            "stderr": "",
            "stdout": "",
            "status": "Unknown",
        }
        if future in done:
            result = future.result()
            data["error_json"] = result["error_json"]
            data["exception"] = result["exception"]
            data["stderr"] = result["stderr"]
            data["stdout"] = result["stdout"]
            if result["timed_out"]:
                data["status"] = "Timed_out"
            elif result["exception"]:
                data["status"] = "Failure"
            elif "status" in data["error_json"]:
                data["status"] = data["error_json"]["status"]
        elif future in not_done:
            data["status"] = "Pool_timed_out"
        results.append(data)
    daemonsets_check_exec(results, raise_on_error)
    return results


def check_nodes_results(results, role, threshold):
    """Check results list according to failed nodes threshold and node role.

    :param results: List of maps with command execution results on nodes
    :param role: NodeRole object
    :param threshold: Integer number of nodes which are allowed to fail migration
    :returns: tuple with failed nodes set and boolean result of threshold check
    """
    failed_nodes = set()
    threshold_fail = False
    for res in results:
        kube_node = kube.safe_get_node(res["node"])
        if kube_node.has_role(role):
            if res["status"] != "Success":
                failed_nodes.add(res["node"])
    if failed_nodes:
        LOG.warning(
            f"Got failed command results on next {role.name} nodes: {failed_nodes}"
        )
        if len(failed_nodes) <= threshold:
            LOG.warning(
                f"Number of {role.name} nodes {len(failed_nodes)} doesn't exceed threshold {threshold}."
            )
        else:
            LOG.error(
                f"Number of {role.name} nodes {len(failed_nodes)} exceeds threshold {threshold}."
            )
            threshold_fail = True
    return failed_nodes, threshold_fail


def cleanup_api_resources():
    """Cleanup resources from Openstack API related to neutron ovs backend"""
    ocm = OpenStackClientManager()
    LOG.info("Starting Neutron API resources cleanup")
    for device_owner in [
        "network:dhcp",
        "network:router_ha_interface",
        "network:floatingip_agent_gateway",
    ]:
        LOG.info(f"Cleaning Neutron {device_owner} ports")
        try:
            ocm.network_ensure_ports_absent(device_owner)
        except Exception:
            LOG.exception(f"Failed to clean some {device_owner} ports")
        LOG.info(f"Finished cleaning Neutron {device_owner} ports")
    for agent_type in [
        "Open vSwitch agent",
        "DHCP agent",
        "L3 agent",
        "Metadata agent",
    ]:
        LOG.info(f"Cleaning Neutron {agent_type} agents")
        for agent in ocm.network_get_agents(agent_type=agent_type):
            try:
                ocm.oc.network.delete_agent(agent)
            except Exception:
                LOG.exception(f"Failed to clean agent {agent}")
        LOG.info(f"Finished cleaning Neutron {agent_type} agents")
    for net in ocm.oc.network.networks():
        if re.match("^HA network tenant\s", net.name):
            LOG.info(f"Cleaning Neutron HA tenant network {net.name}")
            try:
                ocm.oc.network.delete_network(net)
            except Exception:
                LOG.exception(f"Failed to clean network {net.name}")
            LOG.info(f"Finished cleaning Neutron HA tenant network {net.name}")
    LOG.info("Finished Neutron API resources cleanup")


def cleanup_ovs_bridges(script_args):
    """Cleanup OVS interfaces, bridges on nodes"""
    osdpl = kube.get_osdpl()
    network_svc = get_service(osdpl, "networking")
    metadata_daemonsets = get_objects_by_id(
        network_svc, "neutron-metadata-agent"
    )
    cleanup_ovs_command = """
    set -ex
    trap err_trap EXIT
    function err_trap {
        local r=$?
        if [[ $r -ne 0 ]]; then
            echo "cleanup_ovs FAILED"
        fi
        exit $r
    }
    OVS_DB_SOCK="--db=tcp:127.0.0.1:6640"
    ovs-vsctl ${OVS_DB_SOCK} --if-exists del-br br-tun
    echo "Remove tunnel and migration bridges"
    ovs-vsctl ${OVS_DB_SOCK} --if-exists del-br br-migration
    ovs-vsctl ${OVS_DB_SOCK} --if-exists del-port br-int patch-tun
    echo "Cleaning all migration fake bridges"
    for br in $(egrep '^migbr-' <(ovs-vsctl ${OVS_DB_SOCK} list-br)); do
        ovs-vsctl ${OVS_DB_SOCK} del-br $br
    done
    """
    LOG.info("Cleaning OVS bridges")
    daemonsets_exec_parallel(
        metadata_daemonsets,
        ["bash", "-c", cleanup_ovs_command],
        "neutron-metadata-agent",
        max_workers=script_args.max_workers,
        timeout=120,
    )
    LOG.info("Finished cleaning OVS bridges")


def cleanup_linux_netns(script_args):
    """Cleanup linux network namespaces and
    related network interfaces
    """
    osdpl = kube.get_osdpl()
    network_svc = get_service(osdpl, "networking")
    metadata_daemonsets = get_objects_by_id(
        network_svc, "neutron-metadata-agent"
    )
    cleanup_netns_command = """
    set -ex
    trap err_trap EXIT
    function err_trap {
        local r=$?
        if [[ $r -ne 0 ]]; then
            echo "cleanup_netns FAILED"
        fi
        exit $r
    }
    OVS_DB_SOCK="--db=tcp:127.0.0.1:6640"
    IP_NETNS="sudo neutron-rootwrap /etc/neutron/rootwrap.conf ip netns"
    EXIT_CODE=0
    for ns in $(egrep 'qrouter-|qdhcp-|snat-|fip-' <(cut -d' ' -f1 <($IP_NETNS))); do
        for link in $(cut -d: -f2 <(grep -v LOOPBACK <($IP_NETNS exec $ns ip -o link show))); do
            link=${link%%@*}
            $IP_NETNS exec $ns ip l delete $link || ovs-vsctl ${OVS_DB_SOCK} --if-exists del-port br-int $link
        done
        if [[ -n $(grep -v LOOPBACK <($IP_NETNS exec $ns ip -o link show)) ]]; then
            echo "Failed to clean all interfaces in network namespace $ns, namespace will not be removed"
            EXIT_CODE=1
        else
            echo "Cleaned all interfaces in network namespace $ns, removing namespace"
            $IP_NETNS delete $ns
        fi
    done
    exit "${EXIT_CODE}"
    """
    # using timeout 1200 as neutron-rootwrap takes a lot of time
    LOG.info("Cleaning network namespaces")
    daemonsets_exec_parallel(
        metadata_daemonsets,
        ["bash", "-c", cleanup_netns_command],
        "neutron-metadata-agent",
        max_workers=script_args.max_workers,
        timeout=1200,
    )
    LOG.info("Finished cleaning network namespaces")


def prepare(script_args):
    osdpl = kube.get_osdpl()
    network_svc = get_service(osdpl, "networking")
    LOG.info("Backing up OVS bridge mappings")
    backup_bridge_mappings = """
    set -ex
    trap err_trap EXIT
    function err_trap {
        local r=$?
        if [[ $r -ne 0 ]]; then
            echo "prepare FAILED"
        fi
        exit $r
    }
    echo "Getting original bridge mapping"
    bm=$(cut -d= -f2 <(grep bridge_mappings /etc/neutron/plugins/ml2/openvswitch_agent.ini))
    [[ -z $bm ]] && echo bridge_mappings is empty! && exit 1
    echo "Original bridge mapping is ${bm}"
    ovs-vsctl set Open_Vswitch . external-ids:ovn-bridge-mappings-back="${bm// /}"
    echo "Finished original bridge mapping backup"
    """
    neutron_ovs_agents = get_objects_by_id(network_svc, "neutron-ovs-agent")
    daemonsets_exec_parallel(
        neutron_ovs_agents,
        ["bash", "-c", backup_bridge_mappings],
        "neutron-ovs-agent",
        max_workers=script_args.max_workers,
    )


def deploy_ovn_db(script_args):
    osdpl = kube.get_osdpl()
    network_svc = get_service(osdpl, "networking")
    LOG.info(
        "Modifying openvswitch and neutron-l3-agent finalizers to prevent early deletion"
    )
    for daemonset in ["openvswitch-vswitchd", "neutron-l3-agent"]:
        for ds in get_objects_by_id(network_svc, daemonset):
            LOG.info(
                f"Adding finalizer {MIGRATION_FINALIZER} to DaemonSet {ds}"
            )
            ds.ensure_finalizer_present(MIGRATION_FINALIZER)

    LOG.info("Patching Openstack deployment to deploy ovn database")
    osdpl.patch(
        {
            "spec": {
                "migration": {
                    "neutron": {"ovs_ovn_migration": True},
                },
                "features": {"neutron": {"backend": "ml2/ovn"}},
                "services": {
                    "networking": {
                        "neutron": {
                            "values": {
                                "manifests": {
                                    "deployment_server": False,
                                    "daemonset_metadata_agent": False,
                                }
                            }
                        },
                        "openvswitch": {
                            "values": {
                                "manifests": {
                                    "daemonset_ovn_controller": False
                                }
                            }
                        },
                    }
                },
            }
        }
    )
    # https://mirantis.jira.com/browse/PRODX-42146
    time.sleep(30)
    asyncio.run(osdpl.wait_applied())
    network_svc = get_service(osdpl, "networking")
    wait_for_objects_ready(
        network_svc,
        ["openvswitch-ovn-db", "openvswitch-ovn-northd"],
    )
    LOG.info("Deployment OVN db done")


def deploy_ovn_controllers(script_args):
    """Deploys ovn controllers in migration mode and syncs ovn db"""
    osdpl = kube.get_osdpl()
    network_svc = get_service(osdpl, "networking")
    ovn_daemonsets = get_objects_by_id(network_svc, "ovn-controller")
    helm_manager = helm.HelmManager(namespace=osdpl.namespace)
    osdpl.patch({"spec": {"draft": True}})
    if not ovn_daemonsets:
        LOG.info("Deploying ovn controllers in migration mode")
        ovs_patch = {
            "conf": {
                "ovn_migration": True,
            },
            "manifests": {"daemonset_ovn_controller": True},
        }
        update_service_release(
            helm_manager,
            network_svc,
            "openstack-openvswitch",
            ovs_patch,
        )
        # ovn controllers should be already running and ready before we running ovn db sync
        wait_for_objects_ready(
            network_svc,
            ["openvswitch-ovn-db", "openvswitch-ovn-northd", "ovn-controller"],
        )
    LOG.info("Starting Neutron database sync to OVN database")
    neutron_patch = {"manifests": {"job_ovn_db_sync_migrate": True}}
    update_service_release(
        helm_manager, network_svc, "openstack-neutron", neutron_patch
    )
    # On large environments ovn db sync can take a lot of time
    wait_for_objects_ready(network_svc, ["neutron-ovn-db-sync-migrate"])
    LOG.info("Neutron database sync to OVN database is completed")


def migrate_dataplane(script_args):
    osdpl = kube.get_osdpl()
    network_svc = get_service(osdpl, "networking")
    ovn_daemonsets = get_objects_by_id(network_svc, "ovn-controller")
    LOG.info(
        "Pre-migration check: Checking ovs db connectivity in ovn controllers"
    )
    try:
        daemonsets_exec_parallel(
            ovn_daemonsets,
            ["ovs-vsctl", "--no-wait", "list-br"],
            "controller",
            max_workers=script_args.max_workers,
        )
    except Exception as e:
        LOG.error(
            f"Failed Pre-migration check, fix issues and rerun migrate_dataplane stage"
        )
        raise e
    LOG.info("Pre-migration check: Ovs db connectivity check completed")

    tries = 0
    failed_nodes = set()
    gtw_threshold_fail = False
    cmp_threshold_fail = False
    while tries < 3:
        results = daemonsets_exec_parallel(
            ovn_daemonsets,
            ["/tmp/ovn-migrate-dataplane.sh"],
            "controller",
            max_workers=script_args.max_workers,
            raise_on_error=False,
            timeout=60,
            nodes=failed_nodes,
        )
        failed_nodes = set()
        failed_gtw, gtw_threshold_fail = check_nodes_results(
            results, constants.NodeRole.gateway, script_args.gtw_threshold
        )
        failed_cmp, cmp_threshold_fail = check_nodes_results(
            results, constants.NodeRole.compute, script_args.cmp_threshold
        )
        failed_nodes = failed_gtw.union(failed_cmp)
        tries += 1
        if not (gtw_threshold_fail or cmp_threshold_fail):
            break
    if gtw_threshold_fail or cmp_threshold_fail:
        LOG.error(
            f"""Still have failed nodes thresholds exceeded after {tries} retries,
            Stage will be marked as failed, if decided to rerun whole script, this
            stage will be rerun.
            """
        )
        raise RuntimeError("Failed nodes thresholds exceeded")
    elif failed_nodes:
        LOG.warning(
            f"""Still have some failed nodes after {tries} retries,
            Stage will be marked as completed, if decided to rerun whole script, this
            stage will be NOT rerun.
            """
        )


def finalize_migration(script_args):
    osdpl = kube.get_osdpl()
    network_svc = get_service(osdpl, "networking")
    LOG.info("Turning off ovn controller pods migration mode")
    osdpl.patch(
        {
            "spec": {
                "draft": False,
                "services": {
                    "networking": {
                        "openvswitch": {
                            "values": {
                                "manifests": {"daemonset_ovn_controller": True}
                            }
                        }
                    }
                },
            }
        }
    )
    # https://mirantis.jira.com/browse/PRODX-42146
    time.sleep(30)
    asyncio.run(osdpl.wait_applied())
    wait_for_objects_ready(
        network_svc, ["openvswitch-ovn-db", "openvswitch-ovn-northd"]
    )
    neutron_l3_daemonsets = get_objects_by_id(network_svc, "neutron-l3-agent")
    vswitchd_daemonsets = get_objects_by_id(
        network_svc, "openvswitch-vswitchd"
    )
    ovn_daemonsets = get_objects_by_id(network_svc, "ovn-controller")
    for ovs_ds in vswitchd_daemonsets:
        for ovs_pod in ovs_ds.pods:
            node = ovs_pod.obj["spec"].get("nodeName")
            LOG.info(f"Found ovs pod on node {node}")
            for ovn_ds in ovn_daemonsets:
                if ovn_ds.get_pod_on_node(node):
                    LOG.info(f"Removing ovs pod {ovs_pod} on node {node}")
                    ovs_pod.delete(propagation_policy="Background")
                    LOG.info(f"Updating ovn pod on node {node}")
                    asyncio.run(ovn_ds.ensure_pod_generation_on_node(node))
                    LOG.info(f"Updated ovn pod on node {node}")
                    break

    # Remove unused DaemonSets
    # TODO: add waiter that no ds are left
    for ds_list in [neutron_l3_daemonsets, vswitchd_daemonsets]:
        for ds in ds_list:
            LOG.info(f"Removing DaemonSet {ds}")
            ds.ensure_finalizer_absent(MIGRATION_FINALIZER)
    # Enable neutron-server and disable migration in osdpl
    LOG.info("Patching Openstack deployment to deploy neutron-server")
    osdpl.patch(
        {
            "spec": {
                "migration": {
                    "neutron": {"ovs_ovn_migration": False},
                },
                "services": {
                    "networking": {
                        "neutron": {
                            "values": {
                                "manifests": {
                                    "deployment_server": True,
                                    "daemonset_metadata_agent": True,
                                }
                            }
                        },
                    }
                },
            }
        }
    )
    # https://mirantis.jira.com/browse/PRODX-42146
    time.sleep(30)
    asyncio.run(osdpl.wait_applied())
    mspec = osdpl.mspec
    child_view = resource_view.ChildObjectView(mspec)
    osdplst = osdplstatus.OpenStackDeploymentStatus(
        osdpl.name, osdpl.namespace
    )
    asyncio.run(health.wait_services_healthy(osdpl.mspec, osdplst, child_view))


def cleanup(script_args):
    cleanup_api_resources()
    cleanup_ovs_bridges(script_args)
    cleanup_linux_netns(script_args)


WORKFLOW = [
    {
        "executable": prepare,
        "name": "10_PREPARE",
        "impact": """
            WORKLOADS: No downtime expected.
            OPENSTACK API: No downtime expected.""",
        "description": """
            Check pre-requisites, backup bridge mappings on nodes.""",
    },
    {
        "executable": deploy_ovn_db,
        "name": "20_DEPLOY_OVN_DB",
        "impact": """
            WORKLOADS: No downtime expected.
            OPENSTACK API: Neutron API and Metadata downtime starts in this stage.""",
        "description": """
            Deploy OVN with only database components enabled,
            Disable neutron server, metadata agent and all neutron ovs related components except L3 agents.""",
    },
    {
        "executable": deploy_ovn_controllers,
        "name": "30_DEPLOY_OVN_CONTROLLERS",
        "impact": """
            WORKLOADS: No downtime expected.
            OPENSTACK API: Neutron API and Metadata downtime continues in this stage.""",
        "description": """
            Deploy OVN controllers in migration mode.
            Sync neutron database with flag migrate to OVN database
            (requires ovn controllers to be running and ready).""",
    },
    {
        "executable": migrate_dataplane,
        "name": "40_MIGRATE_DATAPLANE",
        "impact": """
            WORKLOADS: Short periods of downtime ARE EXPECTED.
            OPENSTACK API: Neutron API and Metadata downtime continues in this stage.""",
        "description": """
            Deploy OVN controller on the same nodes as openvswitch pods are running.
            Switch dataplane to be managed by OVN controller.""",
    },
    {
        "executable": finalize_migration,
        "name": "50_FINALIZE_MIGRATION",
        "impact": """
            WORKLOADS: Short periods of downtime ARE EXPECTED.
            OPENSTACK API: Neutron API downtime stops in this stage.""",
        "description": """
            Stop openvswitch pods and disbale migration mode (switch ovn
            controllers to start own vswitchd and ovs db containers).
            Remove neutron l3 agent daemonsets.
            Enable Neutron server and metadata agents.""",
    },
    {
        "executable": cleanup,
        "name": "60_CLEANUP",
        "impact": """
            WORKLOADS: No downtime expected.
            OPENSTACK API: No downtime expected.""",
        "description": """
            Cleanup OVS leftovers in Openstack API.
            Remove not used OVS interfaces and linux network namespaces.""",
    },
]


def do_migration(script_args):
    state_cm = StateCM(
        MIGRATION_STATE_CONFIGMAP_NAME,
        settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
        WORKFLOW,
    )
    state = state_cm.state
    LOG.info(f"Initial migration state is {state}")
    for stage in WORKFLOW:
        stage_name = stage["name"]
        error = None
        try:
            if state[stage_name]["status"] == COMPLETED:
                LOG.info(
                    f"Stage {stage_name} is already finished, skipping it"
                )
                continue
            LOG.info(
                f"""Running {stage_name} stage
                Description: {stage['description']}
                IMPACT: {stage['impact']}
            """
            )
            state_cm.update(stage_name, STARTED)
            stage["executable"](script_args)
            state_cm.update(stage_name, COMPLETED)
            LOG.info(f"Completed {stage_name} stage")
        except Exception as e:
            error = e
            state_cm.update(stage_name, FAILED, error=traceback.format_exc())
            LOG.exception(f"Failed to run stage {stage_name}")
        finally:
            current_index = WORKFLOW.index(stage)
            if script_args.interactive and current_index != len(WORKFLOW) - 1:
                next_stage = WORKFLOW[current_index + 1]
                LOG.info(
                    f"""Next stage to run is {next_stage['name']}
                        Description: {next_stage['description']}
                        IMPACT: {next_stage['impact']}
                    """
                )
                msg = "To proceed to next stage press Y, to abort WHOLE procedure press N"
                res = check_input(lambda x: x in ["Y", "N"], msg)
                if res == "Y":
                    # Ignoring any errors if user chose to proceed
                    error = None
                elif res == "N":
                    LOG.warning("Aborting execution")
                    break
            if error:
                raise error


class CheckResult:

    def __init__(self, name, status, description):
        """:param name: the name of the check
        :param status: boolean true|false
        :param description: description with issues that are found.
        """
        self.name = name
        self.status = status
        self.description = description

    @property
    def is_success(self):
        return self.status

    def get_report(self):
        result = "\nCheck name: " + self.name
        result += "\nState: " + ("Pass\n" if self.status else "Fail\n")
        result += "Result description:\n" + self.description + "\n"
        return result


def do_preflight_checks():
    general_results = []

    def run_check(check_func):
        def f(*args, **kwargs):
            try:
                return check_func(*args, **kwargs)
            except Exception as e:
                function_name = check_func.__name__
                return CheckResult(
                    function_name,
                    False,
                    f"Check function '{function_name}' throws an exception '{type(e).__name__}: {e}'.",
                )

        return f

    def _get_check_results(check_name, issues_list, comment):
        if issues_list:
            return CheckResult(
                check_name,
                False,
                comment + "\n".join(issues_list),
            )
        else:
            return CheckResult(check_name, True, "No issues are found")

    def _get_security_group_dhcp_allowed_ipv4(connect):
        """Return dictionary. The dictionary key corresponds to security group Id and
        value is a list of IPv4 CIDRs from this security group where access to DHCP is
        enabled. IPs are stored in IPv4Network format.
        """
        dhcp_allowed_sg = {}
        wildcard_cidr = ipaddress.ip_network("0.0.0.0/0")
        for sec_group in connect.network.security_groups():
            networks = []
            for rule in sec_group.security_group_rules:
                # Process egress rules for IPv4
                if (
                    rule["direction"] == "egress"
                    and rule["ethertype"] == "IPv4"
                ):
                    # The DHCP port has no security group
                    if not rule["remote_group_id"] is None:
                        continue
                    # Rule must be protocol independent
                    # or allow access to 67 port by UDP
                    if rule["protocol"] is None or (
                        rule["protocol"].lower() in ["udp", "17"]
                        and (
                            rule["port_range_min"] is None
                            or rule["port_range_min"] <= 67
                        )
                        and (
                            rule["port_range_max"] is None
                            or rule["port_range_max"] >= 67
                        )
                    ):
                        if rule["remote_address_group_id"] is None:
                            # Get CIDR from rule definition
                            if rule["normalized_cidr"] is None:
                                networks.append(wildcard_cidr)
                            else:
                                networks.append(
                                    ipaddress.ip_network(
                                        rule["normalized_cidr"]
                                    )
                                )
                        else:
                            # Get CIDRs if they are stored in address group
                            for cidr in connect.network.get_address_group(
                                rule["remote_address_group_id"]
                            ).addresses:
                                net = ipaddress.ip_network(cidr)
                                if net.version == 4:
                                    networks.append(net)
            if networks:
                dhcp_allowed_sg.update({sec_group.id: networks})
        return dhcp_allowed_sg

    def _are_addresses_allowed_by_firewall(tested_cidrs, permitted_cidrs):
        """param: tested_cidrs - list of IPv4Network
        param: permitted_cidrs - list of IPv4Network
        return: True if all subnets from tested_cidrs are in
                networks from permitted_cidrs
        """
        if ipaddress.ip_network("0.0.0.0/0") in permitted_cidrs:
            return True
        for subnet in tested_cidrs:
            is_blocked = True
            for net in permitted_cidrs:
                if net.prefixlen <= subnet.prefixlen:
                    if subnet in net.subnets(new_prefix=subnet.prefixlen):
                        is_blocked = False
                        break
            if is_blocked:
                return False
        return True

    def _get_port_cidrs_with_dhcp4(connect, port):
        """param: connect - connection to OS API
        param: port - openstack.network.v2.port.Port object
        return: list CIDRs of IPv4 subnets where dhcp is enabled
                CIDRs are stored in IPv4Network format.
        """
        result = []
        subnet_ids = set()
        for fip in port.fixed_ips:
            subnet_ids.add(fip["subnet_id"])
        for id in subnet_ids:
            subnet = connect.network.get_subnet(id)
            if subnet.is_dhcp_enabled and subnet.ip_version == 4:
                result.append(ipaddress.ip_network(subnet.cidr))
        return result

    def _subnet_has_workload_ports(connect, subnet_id):
        ports = connect.network.get_subnet_ports(subnet_id)
        for port in ports:
            if not (
                port.device_owner.startswith("network")
                or port.device_owner.startswith("neutron")
            ):
                return True
        return False

    @run_check
    def _check_for_free_ip(connect):
        LOG.info("Process subnets for free IPs.")
        overfilled_subnets = []
        for net in connect.network.networks():
            LOG.debug(f"Checking free ips in subnet of network {net.name}.")
            for subnet in connect.network.get_network_ip_availability(
                net.id
            ).subnet_ip_availability:
                if subnet.get("used_ips") == subnet.get("total_ips"):
                    overfilled_subnets.append(subnet.get("subnet_id"))
        LOG.info("Finished processing subnets for free IPs.")
        return _get_check_results(
            "IP address availability check",
            overfilled_subnets,
            "The following subnets do not have free IP:\n",
        )

    @run_check
    def _check_network_mtu(connect):
        osdpl = kube.get_osdpl()
        network_params = (
            osdpl.obj.get("spec", {})
            .get("services", {})
            .get("networking", {})
            .get("neutron", {})
            .get("values", {})
            .get("conf", {})
            .get("neutron", {})
        )
        mtu = []
        mtu.append(
            network_params.get("DEFAULT", {}).get("global_physnet_mtu", 1500)
        )
        path_mtu = network_params.get("ml2", {}).get("path_mtu", 0)
        if path_mtu > 0:
            mtu.append(path_mtu)

        ip_version = network_params.get("ml2", {}).get("overlay_ip_version", 4)
        max_mtu_for_network = (
            min(mtu)
            - IP_HEADER_LENGTH[ip_version]
            - DEFAULT_GENEVE_HEADER_SIZE
        )
        bad_mtu_networks = []
        LOG.info("Check MTU value for networks.")
        for net in connect.network.networks(provider_network_type=TYPE_VXLAN):
            if net.mtu > max_mtu_for_network:
                bad_mtu_networks.append(net.id)
        LOG.info("Finished check MTU value for networks.")
        return _get_check_results(
            "MTU size check",
            bad_mtu_networks,
            "The following networks have not suitable MTU size for Geneve:\n",
        )

    @run_check
    def _check_for_no_dhcp_subnet(connect):
        no_dhcp_subnets = []
        LOG.info("Check if DHCP is enabled in subnets.")
        for net in connect.network.networks(provider_network_type=TYPE_VXLAN):
            for subnet_id in net.subnet_ids:
                if not connect.network.get_subnet(
                    subnet_id
                ).is_dhcp_enabled and _subnet_has_workload_ports(
                    connect, subnet_id
                ):
                    no_dhcp_subnets.append(subnet_id)
        LOG.info("Finish check for DHCP enabling.")
        return _get_check_results(
            "Subnets without enabled DHCP check",
            no_dhcp_subnets,
            "The following subnets have no DHCP. You should configure\nthe MTU of instances in these subnets manually:\n",
        )

    @run_check
    def _check_subnets_dns_servers(connect):
        """
        Checks whether dhcp enabled subnets have dns_nameservers set. Check
        is failed if list of dns servers is empty.

        :param connect openstack.connection.Connection
        :returns CheckResult
        """
        no_dns_subnets = []
        LOG.info("Checking subnets have dns_nameservers set")
        for subnet in connect.network.subnets(is_dhcp_enabled=True):
            if not subnet.dns_nameservers and _subnet_has_workload_ports(
                connect, subnet.id
            ):
                no_dns_subnets.append(subnet.id)
        LOG.info("Finished checking subnets have dns_nameservers set")
        return _get_check_results(
            "Subnets without dns_nameservers check",
            no_dns_subnets,
            "The following subnets have no dns_nameservers set. You should set\ndns_nameservers in subnets manually:\n",
        )

    @run_check
    def _check_port_sg_allowed_dhcp4(connect):
        """Test VM ports from networks which are not connected to external routers.
        The test is considered successful if all subnets of the port with enable_dhcp==True
        param have access to 67 UDP port and allow packets to the 255.255.255.255 address.
        """
        allowed_sg = _get_security_group_dhcp_allowed_ipv4(connect)
        broadcast_ip = ipaddress.ip_network("255.255.255.255/32")
        ports_blocked = []
        LOG.info("Check if DHCP is allowed by security groups on the ports.")
        for net in connect.network.networks(is_router_external=False):
            for port in connect.network.ports(network_id=net.id):
                if port.is_port_security_enabled and port.device_owner in [
                    "compute:nova",
                    "",
                ]:
                    port_cidrs_with_dhcp = _get_port_cidrs_with_dhcp4(
                        connect, port
                    )
                    if len(port_cidrs_with_dhcp) == 0:
                        continue

                    permitted_cidrs = set()
                    for sg in port.security_group_ids:
                        if sg in allowed_sg.keys():
                            permitted_cidrs.update(allowed_sg[sg])

                    # If port has permissions to broadcast and 67 UDP port it will get IP via DHCP
                    is_access_allowed = _are_addresses_allowed_by_firewall(
                        [broadcast_ip], permitted_cidrs
                    ) and _are_addresses_allowed_by_firewall(
                        port_cidrs_with_dhcp, permitted_cidrs
                    )
                    if not is_access_allowed:
                        ports_blocked.append(port.id)
        LOG.info("Finish ports check for access to DHCP.")
        return _get_check_results(
            "Checking ports with blocked access to DHCPv4",
            ports_blocked,
            "The following ports have no security groups that allow correct connection to DHCPv4 service:\n",
        )

    ocm = OpenStackClientManager()
    general_results.append(_check_for_free_ip(ocm.oc))
    general_results.append(_check_network_mtu(ocm.oc))
    general_results.append(_check_for_no_dhcp_subnet(ocm.oc))
    general_results.append(_check_subnets_dns_servers(ocm.oc))
    general_results.append(_check_port_sg_allowed_dhcp4(ocm.oc))

    failed_tests = [a for a in general_results if not a.is_success]
    if failed_tests:
        LOG.warning("There are failures in the check results.")
        for test in failed_tests:
            LOG.warning(test.get_report())
        sys.exit(1)
    else:
        LOG.info("All checks are successful.")


def do_full_db_backup():
    LOG.info("Backing up database")
    backup_cj_name = "mariadb-phy-backup"
    osdpl = kube.get_osdpl()
    mspec = osdpl.mspec
    backup_enabled = (
        mspec.get("features", {})
        .get("database", {})
        .get("backup", {})
        .get("enabled", False)
    )
    if not backup_enabled:
        LOG.warning(f"Backup database in disabled state")
        return
    cronjob = kube.find(
        kube.CronJob, backup_cj_name, settings.OSCTL_OS_DEPLOYMENT_NAMESPACE
    )
    if cronjob.obj["spec"].get("suspend", False):
        LOG.warning(f"Cronjob {backup_cj_name} in suspended state")
        return
    asyncio.run(
        cronjob.run(wait_completion=True, timeout=MARIADB_FULL_BACKUP_TIMEOUT)
    )
    LOG.info(f"Database backup is completed")


def do_neutron_db_backup():
    osdpl = kube.get_osdpl()
    LOG.info("Backing up Neutron database")
    database_svc = get_service(osdpl, "database")
    database_obj = get_objects_by_id(database_svc, "mariadb-server")[0]
    database_pods = database_obj.pods
    for pod in database_pods:
        timestamp = time.strftime("%Y%m%d%H%M%S")
        cmd = (
            'mysqldump --user=root --password="${MYSQL_DBADMIN_PASSWORD}" --lock-tables '
            f"--databases neutron --result-file={BACKUP_NEUTRON_DB_PATH}/neutron-ovs-ovn-migration-{timestamp}.sql"
        )
        command = ["/bin/sh", "-c", cmd]
        result = pod.exec(
            command,
            container="mariadb",
            timeout=MARIADB_NEUTRON_BACKUP_TIMEOUT,
            raise_on_error=True,
        )
        if result["timed_out"]:
            raise RuntimeError(
                f"Neutron db backup exceeded time out {MARIADB_NEUTRON_BACKUP_TIMEOUT} seconds"
            )
        if result["exception"]:
            raise RuntimeError(
                f"Failed to do backup because of exception {result['exception']}"
            )
        LOG.info(f"Neutron database dump on {pod} is completed")
    LOG.info(f"Neutron database dumps are completed")


def main():
    args = set_args()
    if args.mode == "migration":
        do_migration(args)
    elif args.mode == "preflight_checks":
        do_preflight_checks()
    elif args.mode == "backup_db":
        do_full_db_backup()
        do_neutron_db_backup()


if __name__ == "__main__":
    main()
