import kopf
import time

from rockoon import settings
from rockoon import utils

LOG = utils.get_logger(__name__)


@kopf.on.probe(id="delay")
def check_heartbeat(**kwargs):
    delay = None
    if settings.OSCTL_HEARTBEAT_INTERVAL:
        delay = time.time() - settings.HEARTBEAT
        LOG.debug(f"Current heartbeat delay {delay}")
        if delay > settings.OSCTL_HEARTBEAT_MAX_DELAY:
            raise ValueError("Heartbeat delay is too large")
    return delay


@kopf.on.probe(id="tasks")
def check_number_of_tasks(**kwargs):
    tasks = settings.CURRENT_NUMBER_OF_TASKS
    if tasks > settings.OSCTL_MAX_TASKS:
        raise ValueError("Too many tasks")
    return tasks
