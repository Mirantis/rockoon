import pykube

from rockoon import kube
from rockoon import utils

LOG = utils.get_logger(__name__)


def new_node_added(**kwargs):
    if (
        kwargs["new"]["desiredNumberScheduled"]
        <= kwargs["OK_desiredNumberScheduled"]
    ):
        LOG.info("The number of computes was not increased. Skipping hook...")
        return False
    return True


def run_nova_cell_setup(osdpl, name, namespace, meta, **kwargs):
    LOG.info("Start nova daemonset created hook")
    if not new_node_added(**kwargs):
        return
    cronjob = kube.find(kube.CronJob, "nova-cell-setup", namespace)
    job = cronjob.run(wait_completion=True)
    job.delete(propagation_policy="Foreground")


def run_octavia_create_resources(osdpl, name, namespace, meta, **kwargs):
    LOG.info("Start rerun_octavia_create_resources_job hook")
    if not new_node_added(**kwargs):
        return
    try:
        job = kube.find(kube.Job, "octavia-create-resources", namespace)
    except pykube.exceptions.ObjectDoesNotExist:
        # TODO(avolkov): create job manually?
        LOG.warning("Original octavia_create_resources job is not found")
        return
    if not job.ready:
        LOG.warning("Original octavia_create_resources job is not ready")
        return
    job.rerun()
