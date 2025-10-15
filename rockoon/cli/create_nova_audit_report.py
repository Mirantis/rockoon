#!/usr/bin/env python3
import logging
import re
import sys
import time

from pykube import ConfigMap
from rockoon import kube, settings, utils

logging.basicConfig()
LOG = utils.get_logger(__name__)


def get_pod_logs(job):
    job_pods = job.pods
    pod_names = []
    for pod in job_pods:
        pod_names.append(pod.name)
        if pod.obj["status"].get("phase") == "Succeeded":
            return pod.logs(container="placement-audit-report")
    else:
        LOG.error(f"No 'Succeeded' pods for {job} found among {pod_names}")


def main():
    if kube.get_configmap("nova-placement-audit-report"):
        LOG.info("Configmap is found, skipping creation")
        sys.exit(0)
    cronjob = kube.find(
        kube.CronJob,
        "nova-placement-audit",
        namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
        silent=True,
    )
    if not cronjob:
        LOG.info("Cronjob is not found, cannot create report")
        sys.exit(0)
    job = cronjob.get_latest_job(status="ready")
    if not job:
        LOG.warning("Ready job is not found, cannot create report")
        sys.exit(0)
    LOG.info(f"Getting logs from job {job}")
    logs = get_pod_logs(job)
    if not logs:
        LOG.error(f"Failed to get logs from {job}")
        sys.exit(0)
    report_match = re.search(r"(\{.*\})", logs)
    if not report_match:
        LOG.error(f"Report not found in logs {logs}")
        sys.exit(0)
    report_ts = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(job.start_time)
    )
    report = report_match[1]
    # check again for case when update has finished while we are starting
    if not kube.get_configmap("nova-placement-audit-report"):
        LOG.info("Report configmap is not found, creating")
        cm = kube.dummy(
            ConfigMap,
            "nova-placement-audit-report",
            namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
        )
        cm.obj["data"] = {"report": report, "report_ts": report_ts}
        cm.create()
    LOG.info("Report configmap is created")
