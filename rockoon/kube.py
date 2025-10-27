import abc
import asyncio
import base64
import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import inspect
import json
from os import urandom
import sys
import time
from typing import List
import functools
from urllib.parse import urlencode

import kopf
import pykube
from typing import Dict

from . import constants as const
from . import settings
from . import utils
from . import layers
from . import websocket_client
from . import exception
from . import osdplstatus

LOG = utils.get_logger(__name__)
CONF = settings.CONF


def kube_client():
    # requests are not thread safe, use uniq sessions for
    # every request
    config = pykube.KubeConfig.from_env()
    client = pykube.HTTPClient(
        config=config, timeout=settings.OSCTL_PYKUBE_HTTP_REQUEST_TIMEOUT
    )
    LOG.debug(f"Created k8s api client from context {config.current_context}")
    return client


def generate_random_name(length):
    chars = "abcdefghijklmnpqrstuvwxyz1234567890"
    return "".join(chars[c % len(chars)] for c in urandom(length))


def _get_kubernetes_objects(module):
    k_objects = {}
    for name, obj in inspect.getmembers(module, inspect.isclass):
        if issubclass(obj, pykube.objects.APIObject) and getattr(
            obj, "kind", None
        ):
            k_objects[(obj.version, obj.kind)] = obj
    return k_objects


def get_kubernetes_objects():
    """Return all classes that are subclass of pykube.objects.APIObject.

    The following order is used:
    1. rockoon.kube classes
    2. pykube.objects classes

    """

    objects = _get_kubernetes_objects(pykube.objects)
    objects.update(_get_kubernetes_objects(sys.modules[__name__]))
    return objects


def get_object_by_kind(kind):
    for item, kube_class in get_kubernetes_objects().items():
        if kind == item[1]:
            return kube_class


def object_factory(api, api_version, kind):
    """Dynamically builds kubernetes objects python class.

    1. Objects from openstack_operator.kube.KUBE_OBJECTS
    2. Objects from pykube.objects
    3. Generic kubernetes object
    """
    resource = KUBE_OBJECTS.get(
        (api_version, kind), pykube.object_factory(api, api_version, kind)
    )
    return resource


class OpenStackDeployment(pykube.objects.NamespacedAPIObject):
    version = "lcm.mirantis.com/v1alpha1"
    kind = "OpenStackDeployment"
    endpoint = "openstackdeployments"
    kopf_on_args = *version.split("/"), endpoint

    @property
    def mspec(self):
        # NOTE(okononenko) we want to avoid spec modification
        spec_copy = copy.deepcopy(self.obj["spec"])
        subs_spec = layers.substitude_osdpl(spec_copy)
        layers.update_ca_bundles(subs_spec)
        mspec = layers.merge_spec(subs_spec, LOG)
        return mspec

    @property
    def fingerprint(self):
        return layers.spec_hash(self.mspec)

    @property
    def is_applied(self):
        self.reload()
        osdplst = osdplstatus.OpenStackDeploymentStatus(
            self.name, self.namespace
        )
        status = self.obj.get("status", {})
        if osdplst.get_osdpl_status() != osdplstatus.APPLIED:
            return False
        if osdplst.get_osdpl_fingerprint() != status.get("fingerprint"):
            return False
        if osdplst.get_osdpl_controller_version() != status.get("version"):
            return False
        return True

    def _wait_applied(self, interval):
        while not self.is_applied:
            time.sleep(interval)

    async def wait_applied(self, timeout=600, interval=30):
        LOG.info(
            f"Waiting {timeout} seconds {self.kind}/{self.name} status is applied"
        )
        utils.run_with_timeout(
            self._wait_applied, args=(interval,), timeout=timeout
        )
        LOG.info(f"{self.kind}/{self.name} is applied")


class HelmBundle(pykube.objects.NamespacedAPIObject):
    version = "lcm.mirantis.com/v1alpha1"
    kind = "HelmBundle"
    endpoint = "helmbundles"
    kopf_on_args = *version.split("/"), endpoint


@dataclass
class HelmBundleExt:
    chart: str
    manifest: str
    images: List[str]
    # List of jsonpath-ng expressions, describes values in release
    # that modify immutable fields.
    hash_fields: list = field(default_factory=lambda: [])


class HelmBundleMixin:
    __helmbundle_ext = {}
    immutable = False

    @property
    def service(self):
        return self.__service

    @service.setter
    def service(self, service):
        self.__service = service

    @property
    def helmbundle_ext(self) -> HelmBundleExt:
        return self.__helmbundle_ext

    @helmbundle_ext.setter
    def helmbundle_ext(self, helmbundle_ext: HelmBundleExt):
        self.__helmbundle_ext = helmbundle_ext

    def _enable(
        self, version, wait_completion=False, extra_values=None, delay=None
    ):
        delay = (
            delay
            if delay is not None
            else CONF.getint("helmbundle", "manifest_enable_delay")
        )
        diff = {"images": {"tags": {}}, "manifests": {}}
        for image in self.helmbundle_ext.images:
            diff["images"]["tags"][image] = self.service.get_image(
                image, self.helmbundle_ext.chart, version
            )
        diff["manifests"][self.helmbundle_ext.manifest] = True
        if extra_values is not None:
            diff.update(extra_values)

        i = 1
        while True:
            self.service.set_release_values(self.helmbundle_ext.chart, diff)

            time.sleep(delay)

            if not wait_completion:
                return
            if self.exists():
                self.reload()
                if self.ready and not self.need_apply_images(version):
                    return
                LOG.info(
                    f"The images are not updated yet for {self.kind} {self.name}."
                )
            LOG.info(
                f"The {self.kind} {self.name} is not ready. Waiting, attempt: {i}"
            )
            i += 1

    async def enable(
        self,
        version,
        wait_completion=False,
        extra_values=None,
        timeout=None,
        delay=None,
    ):
        timeout = (
            timeout
            if timeout is not None
            else CONF.getint("helmbundle", "manifest_enable_timeout")
        )
        delay = (
            delay
            if delay is not None
            else CONF.getint("helmbundle", "manifest_enable_delay")
        )
        utils.run_with_timeout(
            self._enable,
            args=(version,),
            kwargs={
                "wait_completion": wait_completion,
                "extra_values": extra_values,
                "delay": delay,
            },
            timeout=timeout,
        )

    def _disable(
        self,
        wait_completion=False,
        delay=None,
    ):
        delay = (
            delay
            if delay is not None
            else CONF.getint("helmbundle", "manifest_disable_delay")
        )

        diff = {"images": {"tags": {}}, "manifests": {}}
        diff["manifests"][self.helmbundle_ext.manifest] = False
        i = 1
        while True:
            self.service.set_release_values(self.helmbundle_ext.chart, diff)
            if not wait_completion:
                return
            if not self.exists():
                return
            LOG.info(
                f"The object {self.kind} {self.name} still exists, retrying {i}"
            )
            time.sleep(delay)
            i += 1

    async def disable(
        self,
        wait_completion=False,
        timeout=None,
        delay=None,
    ):
        timeout = (
            timeout
            if timeout is not None
            else CONF.getint("helmbundle", "manifest_disable_timeout")
        )
        delay = (
            delay
            if delay is not None
            else CONF.getint("helmbundle", "manifest_disable_delay")
        )
        utils.run_with_timeout(
            self._disable,
            kwargs={"wait_completion": wait_completion, "delay": delay},
            timeout=timeout,
        )

    def _purge(
        self,
        timeout=None,
        delay=None,
    ):
        timeout = (
            timeout
            if timeout is not None
            else CONF.getint("helmbundle", "manifest_purge_timeout")
        )
        delay = (
            delay
            if delay is not None
            else CONF.getint("helmbundle", "manifest_purge_delay")
        )
        i = 1
        while True:
            if not self.exists():
                LOG.info(f"Object {self.kind}: {self.name} is not present.")
                return
            self.delete(propagation_policy="Background")
            LOG.info(
                f"Retrying {i} removing {self.kind}: {self.name} in {delay}s"
            )
            i += 1
            time.sleep(delay)

    async def purge(
        self,
        timeout=None,
        delay=None,
    ):
        timeout = (
            timeout
            if timeout is not None
            else CONF.getint("helmbundle", "manifest_purge_timeout")
        )
        delay = (
            delay
            if delay is not None
            else CONF.getint("helmbundle", "manifest_purge_delay")
        )
        utils.run_with_timeout(
            self._purge, kwargs={"delay": delay}, timeout=timeout
        )

    def image_applied(self, value):
        """Ensure image is applied to at least one of containers"""
        self.reload()
        for container in self.obj["spec"]["template"]["spec"]["containers"]:
            if container["image"] == value:
                LOG.info(
                    f"Found image in container {container['name']} for {self.kind}: {self.name}"
                )
                return True

    def need_apply_images(self, version):
        self.reload()
        applied_images = []
        for image in self.helmbundle_ext.images:
            applied_images.append(
                self.image_applied(
                    self.service.get_image(
                        image, self.helmbundle_ext.chart, version
                    )
                )
            )
        if not all(applied_images):
            return True
        return False


class ObjectStatusMixin(abc.ABC):

    @property
    @abc.abstractmethod
    def ready(self):
        pass

    def _wait_ready(self, interval):
        while not self.ready:
            time.sleep(interval)

    async def wait_ready(self, timeout=None, interval=10):
        LOG.info(f"Waiting for {timeout} {self.kind}/{self.name} is ready")
        utils.run_with_timeout(
            self._wait_ready, args=(interval,), timeout=timeout
        )
        LOG.info(f"The {self.kind}/{self.name} is ready")


class Secret(pykube.Secret, HelmBundleMixin):
    @property
    def data_decoded(self):
        return {
            key: base64.b64decode(value).decode("utf-8")
            for key, value in self.obj["data"].items()
        }


class Service(pykube.Service, HelmBundleMixin):
    @property
    def loadbalancer_ips(self):
        res = []
        for ingress in (
            self.obj["status"].get("loadBalancer", {}).get("ingress", [])
        ):
            if ingress.get("ip"):
                res.append(ingress["ip"])
        return res


class StatefulSet(pykube.StatefulSet, HelmBundleMixin, ObjectStatusMixin):
    @property
    def uid(self):
        return self.obj["metadata"]["uid"]

    @property
    def ready(self):
        self.reload()
        return (
            self.obj["status"].get("observedGeneration", 0)
            >= self.obj["metadata"]["generation"]
            and self.obj["status"].get("updatedReplicas") == self.replicas
            and self.obj["status"].get("readyReplicas") == self.replicas
        )

    async def wait_for_replicas(self, count, times=60, seconds=10):
        for i in range(times):
            self.reload()
            # NOTE(vsaienko): the key doesn't exist when have 0 replicas
            if self.obj["status"].get("readyReplicas", 0) == count:
                return True
            await asyncio.sleep(seconds)
        raise ValueError("Not ready yet.")

    @property
    def pods(self):
        self.reload()
        pod_labels = self.obj["spec"]["selector"].get("matchLabels", {})
        selector = {f"{k}__in": [v] for k, v in pod_labels.items()}
        pods_query = resource_list(
            Pod, selector=selector, namespace=self.namespace
        )
        pods = [x for x in pods_query if x.is_owned_by(self.uid)]
        return pods

    def is_node_locked(self, node_name):
        """Check if node is locked by statefulset

        The node is locked when
        1. Replicas on other nodes are not ready
        2. Number of ready replicas is less than replicas - 1

        :returns True: When node is locked
        :returns False: When node is not locked
        """
        self.reload()
        ready_pods = len([pod.ready for pod in self.pods if pod.ready])
        min_ready_pods = self.obj["spec"]["replicas"] - 1
        if ready_pods < min_ready_pods:
            LOG.error(
                f"Number of ready pods {ready_pods} is not enough. Require at least {min_ready_pods}"
            )
            return True
        other_nodes_pods = []
        for pod in self.pods:
            pod_node = pod.obj["spec"].get("nodeName")
            if pod_node and pod_node != node_name:
                other_nodes_pods.append(pod)
        if len(other_nodes_pods) < min_ready_pods:
            LOG.error(
                f"Do not have enough ready pods for {self.name} on other nodes. Expected {min_ready_pods}, but found {other_nodes_pods}"
            )
            return True
        if not all([pod.ready for pod in other_nodes_pods if pod.ready]):
            LOG.error(
                f"Pods from {self.name} are not ready on other nodes than {node_name}"
            )
            return True
        return False

    def release_persistent_volume_claims(self, node_name):
        for pod in self.pods:
            for pvc in pod.pvcs:
                pv = pvc.pv
                if pv and pv.is_bound_to_node(node_name):
                    LOG.info(
                        f"Deleting PVC {pvc.name} tied to node {node_name}"
                    )
                    pvc.delete()

    def restart(self):
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.reload()
        self.patch(
            {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "kubectl.kubernetes.io/restartedAt": timestamp
                            }
                        }
                    }
                }
            }
        )


class Ingress(pykube.objects.NamespacedAPIObject, HelmBundleMixin):
    version = "extensions/v1beta1"
    endpoint = "ingresses"
    kind = "Ingress"


class Job(pykube.Job, HelmBundleMixin, ObjectStatusMixin):
    immutable = True

    @property
    def uid(self):
        return self.obj["metadata"]["uid"]

    @property
    def start_time(self):
        """
        Timestamp of job start.

        :returns : floating number (unix timestamp) or None
        """
        ts = self.obj["status"].get("startTime")
        if ts:
            return utils.k8s_timestamp_to_unix(ts)

    @property
    def ready(self):
        self.reload()
        conditions = self.obj.get("status", {}).get("conditions", [])
        # TODO(vsaienko): there is no official documentation that describes when job is considered complete.
        # revisit this place in future.
        completed = [
            c["status"] == "True"
            for c in conditions
            if c["type"] in ["Ready", "Complete"]
        ]
        if completed and all(completed):
            LOG.info(
                f"All conditions for the {self.kind}/{self.name} completed."
            )
            return True
        LOG.info(f"The job {self.name} is not Ready yet.")
        return False

    @property
    def completed(self):
        self.reload()
        for c in self.obj["status"].get("conditions", []):
            if (
                c["type"] in ["Ready", "Complete", "Failed"]
                and c["status"] == "True"
            ):
                return True
        LOG.info(f"The job {self.name} is not Completed yet.")
        return False

    @property
    def pods(self):
        self.reload()
        pod_labels = self.obj["spec"]["selector"].get("matchLabels", {})
        selector = {f"{k}__in": [v] for k, v in pod_labels.items()}
        pods_query = resource_list(
            Pod, selector=selector, namespace=self.namespace
        )
        pods = [x for x in pods_query if x.is_owned_by(self.uid)]
        return pods

    def _prepare_for_rerun(self):
        # cleanup the object of runtime stuff
        self.obj.pop("status", None)
        self.obj["metadata"].pop("creationTimestamp", None)
        self.obj["metadata"].pop("resourceVersion", None)
        self.obj["metadata"].pop("selfLink", None)
        self.obj["metadata"].pop("uid", None)
        self.obj["metadata"]["labels"].pop("controller-uid", None)
        self.obj["metadata"]["labels"].pop(
            "batch.kubernetes.io/controller-uid", None
        )
        self.obj["spec"]["template"]["metadata"].pop("creationTimestamp", None)
        self.obj["spec"]["template"]["metadata"]["labels"].pop(
            "controller-uid", None
        )
        self.obj["spec"]["template"]["metadata"]["labels"].pop(
            "batch.kubernetes.io/controller-uid", None
        )
        self.obj["spec"].pop("selector", None)

    def is_owned_by(self, uid):
        for ref in self.obj["metadata"].get("ownerReferences", []):
            if ref.get("uid") == uid:
                return True
        return False

    async def rerun(self):
        self.delete(propagation_policy="Background")
        tries = 10
        for i in range(tries):
            try:
                if not wait_for_deleted(self):
                    LOG.warning("Failed to delete job %s", self.name)
                    return
                self._prepare_for_rerun()
                self.create()
                LOG.info("New job created: %s", self.name)
                return
            except Exception as e:
                LOG.warning(
                    "Got exception %s while trying to rerun job %s. Retyring %s out of %s",
                    e,
                    self.name,
                    i,
                    tries,
                )
                if i == tries - 1:
                    raise e
            await asyncio.sleep(10)

    def wait_completed(self, timeout=600, delay=30):
        LOG.info(f"Waiting job {self.name} is completed.")
        start = time.time()
        while time.time() - start < timeout:
            if self.completed:
                return
            time.sleep(delay)
        raise TimeoutError(f"Job {self.name} is not finished in time")


class CronJob(pykube.CronJob, HelmBundleMixin):

    @property
    def jobs(self):
        self.reload()
        job_labels = (
            self.obj["spec"]["jobTemplate"]
            .get("metadata", {})
            .get("labels", {})
        )
        selector = {f"{k}__in": [v] for k, v in job_labels.items()}
        jobs_query = resource_list(
            Job, selector=selector, namespace=self.namespace
        )
        jobs = [x for x in jobs_query if x.is_owned_by(self.uid)]
        return jobs

    def get_latest_job(self, status=None):
        """
        Get latest job of cronjob. If status is specified,
        returns latest job in that status.

        :param status: string "completed" or "ready"

        :returns : Job object or None
        """
        # filter to get jobs which already started
        jobs = [job for job in self.jobs if job.start_time]
        if not jobs:
            LOG.info(f"Cronjob {self.name} has not started jobs yet")
            return
        sorted_jobs = sorted(
            jobs, key=lambda job: job.start_time, reverse=True
        )
        if status is None:
            return sorted_jobs[0]
        for job in sorted_jobs:
            if getattr(job, status):
                return job
        LOG.info(f"Cronjob {self.name} has no jobs in {status} status")

    @property
    def uid(self):
        return self.obj["metadata"]["uid"]

    def _suspend(
        self,
        wait_completion=False,
        delay=None,
    ):
        delay = (
            delay
            if delay is not None
            else CONF.getint("helmbundle", "manifest_disable_delay")
        )
        diff = {"conf": {"cronjob": {"suspend": True}}}
        i = 1
        while True:
            self.reload()
            self.service.set_release_values(self.helmbundle_ext.chart, diff)
            if not wait_completion:
                return
            check_apply = self.obj["spec"].get("suspend", None)
            if check_apply:
                return
            LOG.info(
                f"The object {self.kind} {self.name} still not suspended, retrying {i}"
            )
            time.sleep(delay)
            i += 1

    async def suspend(
        self,
        wait_completion=False,
        timeout=None,
        delay=None,
    ):
        timeout = (
            timeout
            if timeout is not None
            else CONF.getint("helmbundle", "manifest_disable_timeout")
        )
        delay = (
            delay
            if delay is not None
            else CONF.getint("helmbundle", "manifest_disable_delay")
        )
        utils.run_with_timeout(
            self._suspend,
            kwargs={"wait_completion": wait_completion, "delay": delay},
            timeout=timeout,
        )

    async def run(self, wait_completion=False, timeout=600, delay=10):
        """Force run job from cronjob.

        :returns : the job object
        """
        job_name = f"{self.name}-{generate_random_name(10)}"
        job = self.obj["spec"]["jobTemplate"]
        job["metadata"]["name"] = job_name
        job["metadata"]["namespace"] = self.namespace
        kopf.adopt(job, self.obj)
        kube_api = kube_client()
        kube_job = Job(kube_api, job)
        kube_job.create()

        def _wait_completion(job, delay):
            while not job.ready:
                time.sleep(delay)

        if wait_completion:
            utils.run_with_timeout(
                self._wait_completion,
                args=(kube_job,),
                kwargs={"delay": delay},
                timeout=timeout,
            )
        return kube_job


class Deployment(pykube.Deployment, HelmBundleMixin, ObjectStatusMixin):
    @property
    def ready(self):
        self.reload()
        return (
            self.obj["status"].get("observedGeneration", 0)
            >= self.obj["metadata"]["generation"]
            and self.obj["status"].get("updatedReplicas") == self.replicas
            and self.obj["status"].get("readyReplicas") == self.replicas
        )

    async def wait_for_replicas(self, count, times=60, seconds=10):
        for i in range(times):
            self.reload()
            # NOTE(vsaienko): the key doesn't exist when have 0 replicas
            if self.obj["status"].get("readyReplicas", 0) == count:
                return True
            await asyncio.sleep(seconds)
        raise ValueError("Not ready yet.")


class DaemonSet(pykube.DaemonSet, HelmBundleMixin, ObjectStatusMixin):

    @property
    def uid(self):
        return self.obj["metadata"]["uid"]

    @property
    def ready(self):
        self.reload()
        if (
            self.obj["status"].get("observedGeneration", 0)
            < self.obj["metadata"]["generation"]
        ):
            return False
        desired = self.obj["status"].get("desiredNumberScheduled", 0)
        ready = self.obj["status"].get("numberReady", 0)
        update_strategy = (
            self.obj["spec"].get("updateStrategy", {}).get("type")
        )
        if update_strategy == "OnDelete":
            # NOTE(vsaienko): With OnDelete strategy updatedNumberScheduled is not present
            # and we do not know when pods will be rollout so thread ds as ready when
            # number of desired replicas and ready are same
            return desired == ready
        else:
            return ready == self.obj["status"].get("updatedNumberScheduled", 0)

    @property
    def pods(self):
        self.reload()
        pod_labels = self.obj["spec"]["selector"].get("matchLabels", {})
        selector = {f"{k}__in": [v] for k, v in pod_labels.items()}
        pods_query = resource_list(
            Pod, selector=selector, namespace=self.namespace
        )
        pods = [x for x in pods_query if x.is_owned_by(self.uid)]
        return pods

    def get_pod_on_node(self, node_name):
        for pod in self.pods:
            if pod.obj["spec"].get("nodeName") == node_name:
                return pod

    async def ensure_pod_generation_on_node(self, node_name, wait_ready=True):
        """Ensure pod template generation on the given node is same as ds.

        If generation does not match restart pod.

        :param node_name: the name of the node
        :param wait_ready: boolean to wait for pod is ready after restart
        """
        pod = self.get_pod_on_node(node_name)
        if not pod:
            return
        pod_generation = pod.generation
        ds_generation = self.generation
        if (
            pod_generation
            and ds_generation
            and pod_generation != ds_generation
        ):
            pod.delete()
            if wait_ready:
                await self.wait_pod_on_node(node_name)

    async def wait_pod_on_node(self, node_name):
        LOG.info(f"Waiting pods for {self.name} on {node_name} are ready.")
        while True:
            pod = self.get_pod_on_node(node_name)
            if (
                pod
                and "deletionTimestamp" not in pod.obj["metadata"]
                and pod.ready
            ):
                break
            await asyncio.sleep(5)
        LOG.info(f"Pods for {self.name} on {node_name} are ready.")

    async def ensure_pod_generation(self):
        """Ensure pod template generation matches ds generation"""
        for pod in self.pods:
            pod_generation = pod.generation
            ds_generation = self.generation
            if (
                pod
                and pod_generation
                and ds_generation
                and pod_generation != ds_generation
            ):
                LOG.info(
                    f"Pod {pod.name} generation {pod_generation} does not match ds generation {ds_generation}. Restarting..."
                )
                pod_node = pod.obj["spec"].get("nodeName")
                pod.delete()
                if pod_node:
                    await self.wait_pod_on_node(pod_node)

    @property
    def finalizers(self):
        self.reload()
        return self.obj["metadata"].get("finalizers", [])

    @finalizers.setter
    def finalizers(self, finalizers):
        self.obj["metadata"]["finalizers"] = finalizers
        # we use is_strategic=False because if we need to remove
        # some finalizer strategic merge is unable to do this.
        self.update(is_strategic=False)

    def ensure_finalizer_present(self, finalizer):
        finalizers = self.finalizers
        if finalizer not in finalizers:
            finalizers.append(finalizer)
            self.finalizers = finalizers

    def ensure_finalizer_absent(self, finalizer):
        finalizers = self.finalizers
        if finalizer in finalizers:
            finalizers.remove(finalizer)
            self.finalizers = finalizers

    @property
    def generation(self):
        # NOTE(vsaienko): generations may not match, and pod uses
        # deprecated generation PRODX-38935
        template_generation = (
            self.obj["metadata"]
            .get("annotations", {})
            .get("deprecated.daemonset.template.generation")
        )
        generation = template_generation or self.obj["metadata"].get(
            "generation"
        )
        if generation:
            generation = int(generation)
        return generation


class Pod(pykube.Pod):
    # NOTE(vsaienko): override delete method unless client accepts grace_period parameter
    def delete(
        self, propagation_policy: str = None, grace_period_seconds=None
    ):
        """
        Delete the Kubernetes resource by calling the API.
        The parameter propagation_policy defines whether to cascade the delete. It can be "Foreground", "Background" or "Orphan".
        See https://kubernetes.io/docs/concepts/workloads/controllers/garbage-collection/#setting-the-cascading-deletion-policy
        """
        options = {}
        if propagation_policy:
            options["propagationPolicy"] = propagation_policy
        if grace_period_seconds is not None:
            options["gracePeriodSeconds"] = grace_period_seconds
        r = self.api.delete(**self.api_kwargs(data=json.dumps(options)))
        if r.status_code != 404:
            self.api.raise_for_status(r)

    @property
    def job_child(self):
        for owner in self.metadata.get("ownerReferences", []):
            if owner["kind"] == "Job":
                return True
        # NOTE(vsaienko): if job is removed but pod is still present, ownerReference is empty
        if (
            "job-name" in self.labels
            or "batch.kubernetes.io/job-name" in self.labels
        ):
            return True
        return False

    def exec(self, command, container=None, timeout=15, raise_on_error=False):
        """Run command in pod and return output

        :param command: List with command to execute
        :param container: The name of container
        :param timeout: Timeout to run command

        :raises PodExecCommandFailed: when resp["error"]["status"] != Success and raise_on_error
        :returns : dictionary with the following structure
          {
              "timed_out": <boolan flag to specify is command timed out>
              "exception": The exception instnace if got any from k8s API
                           while communicating
              "stdout": stdout output
              "stderr": strder output
              "error": content of error channel
              "error_json": content of error channel in json format (if able to convert)
              <channel_name>: <channel_data>
          }
        """
        kwargs = {}
        headers = {
            "User-Agent": f"pykube-ng/{self.version}",
            "Sec-Websocket-Protocol": "v4.channel.k8s.io",
        }
        if "token" in self.api.config.user:
            headers.update(
                {"Authorization": f"Bearer {self.api.config.user['token']}"}
            )

        query_string = urlencode({"command": command}, doseq=True)
        # NOTE(vsaienko): when running with stdin: False, ie passed needed command
        # API will not return error in stderr channel, and everything will be combined
        # into stdout. To split channels we need use interactive mode, but with this
        # we do not know actually when command finished and will wait whole timeout.
        # Handle stderr here maybe in future this will be fixed in kubernetes API.
        params = {
            "tty": False,
            "stdin": False,
            "stderr": True,
            "stdout": True,
        }
        if container is not None:
            params["container"] = container
        kwargs["headers"] = headers
        kwargs["params"] = params
        kwargs["operation"] = "exec"

        api_kwargs = self.api_kwargs(**kwargs)
        api_kwargs["url"] = (
            self.api_kwargs(**kwargs)["url"] + f"&{query_string}"
        )
        data = self.api.get_kwargs(**api_kwargs)

        wsclient = None
        res = {
            "timed_out": False,
            "exception": None,
            "stderr": "",
            "stdout": "",
            "error_json": {},
        }
        exc_to_raise = None
        try:
            wsclient = websocket_client.KubernetesWebSocketsClient(
                self.api.config, **data
            )
            try:
                wsclient.run_forever(timeout=timeout)
            except TimeoutError as e:
                LOG.error(
                    "Timed out while runing command %s in %s/%s",
                    command,
                    self.name,
                    container,
                )
                res["timed_out"] = True
                exc_to_raise = e
            res.update(wsclient.read_all())
        except Exception as e:
            LOG.exception(
                "Got exception when running command in pod", exc_info=e
            )
            res["exception"] = e
            exc_to_raise = e
        finally:
            if wsclient is not None:
                wsclient.close()
        if "error" in res:
            try:
                # k8s returns error in json format, if no error encountered
                # error field looks like: '{"status": "Success", "metadata":{}}'
                res["error_json"] = json.loads(res["error"])
                if res["error_json"].get("status") != "Success":
                    LOG.error(
                        "Got error %s while running command %s in pod/container %s/%s",
                        res["error_json"],
                        command,
                        self.name,
                        container,
                    )
                    raise exception.PodExecCommandFailed(stderr=res["stderr"])
            except Exception as e:
                LOG.exception(e)
                exc_to_raise = e
        if raise_on_error and exc_to_raise:
            raise exc_to_raise
        return res

    @property
    def pvcs(self):
        self.reload()
        pvcs = []
        kube_api = kube_client()
        for volume in self.obj["spec"].get("volumes", []):
            if "persistentVolumeClaim" in volume:
                pvcs.append(
                    PersistentVolumeClaim.objects(kube_api)
                    .filter(namespace=self.namespace)
                    .get(name=volume["persistentVolumeClaim"]["claimName"])
                )
        return pvcs

    @property
    def generation(self):
        generation = self.obj["metadata"]["labels"].get(
            "pod-template-generation"
        )
        if generation:
            generation = int(generation)
        return generation

    def is_owned_by(self, uid):
        for ref in self.obj["metadata"].get("ownerReferences", []):
            if ref.get("uid") == uid:
                return True
        return False


class Node(pykube.Node, ObjectStatusMixin):

    @property
    def ready(self):
        """
        Return whether the given pykube Node has "Ready" status
        """
        self.reload()
        for condition in self.obj.get("status", {}).get("conditions", []):
            if condition["type"] == "Ready" and condition["status"] == "True":
                return True
        return False

    def get_pods(self, namespace=None):
        kube_api = kube_client()
        pods = Pod.objects(kube_api).filter(
            namespace=namespace, field_selector={"spec.nodeName": self.name}
        )
        return pods

    def remove_pods(self, namespace=None):
        pods = self.get_pods(namespace=namespace)
        for pod in pods:
            LOG.debug(f"Removing pod: {pod.name} from node: {self.name}")
            pod.delete(propagation_policy="Background", grace_period_seconds=0)

    def has_role(self, role: const.NodeRole) -> bool:
        for k, v in settings.OSCTL_OPENSTACK_NODE_LABELS[role].items():
            if self.labels.get(k) == v:
                return True
        return False

    def has_os_role(self):
        for role in const.NodeRole:
            if self.has_role(role):
                return True
        return False


class PersistentVolumeClaim(pykube.PersistentVolumeClaim):
    @property
    def pv(self):
        self.reload()
        volume_name = self.obj["spec"].get("volumeName")
        kube_api = kube_client()
        if volume_name:
            return PersistentVolume.objects(kube_api).get(name=volume_name)
        LOG.error(f"No volume is associated with {self.name}")


class PersistentVolume(pykube.PersistentVolume):
    def is_bound_to_node(self, node_name):
        for node_selector in (
            self.obj["spec"]
            .get("nodeAffinity", {})
            .get("required", {})
            .get("nodeSelectorTerms", [])
        ):
            for expression in node_selector.get("matchExpressions", []):
                if (
                    expression.get("key") == "kubernetes.io/hostname"
                    and expression.get("operator") == "In"
                    and node_name in expression.get("values", [])
                ):
                    return True
        return False


class RedisFailover(pykube.objects.NamespacedAPIObject):
    version = "databases.spotahome.com/v1"
    kind = "RedisFailover"
    endpoint = "redisfailovers"


class ClusterWorkloadLock(pykube.objects.APIObject):
    version = "lcm.mirantis.com/v1alpha1"
    kind = "ClusterWorkloadLock"
    endpoint = "clusterworkloadlocks"


class NodeWorkloadLock(pykube.objects.APIObject):
    version = "lcm.mirantis.com/v1alpha1"
    endpoint = "nodeworkloadlocks"
    kind = "NodeWorkloadLock"


class ClusterMaintenanceRequest(pykube.objects.APIObject):
    version = "lcm.mirantis.com/v1alpha1"
    endpoint = "clustermaintenancerequests"
    kind = "ClusterMaintenanceRequest"


class NodeMaintenanceRequest(pykube.objects.APIObject):
    version = "lcm.mirantis.com/v1alpha1"
    endpoint = "nodemaintenancerequests"
    kind = "NodeMaintenanceRequest"


class OpenStackDeploymentStatus(pykube.objects.NamespacedAPIObject):
    version = "lcm.mirantis.com/v1alpha1"
    kind = "OpenStackDeploymentStatus"
    endpoint = "openstackdeploymentstatus"


class NodeDisableNotification(pykube.objects.APIObject):
    version = "lcm.mirantis.com/v1alpha1"
    endpoint = "nodedisablenotifications"
    kind = "NodeDisableNotification"
    kopf_on_args = *version.split("/"), endpoint


def resource(data):
    kube_api = kube_client()
    return object_factory(kube_api, data["apiVersion"], data["kind"])(
        kube_api, data
    )


def dummy(klass, name, namespace=None):
    meta = {"name": name}
    if namespace:
        meta["namespace"] = namespace
    kube_api = kube_client()

    obj = {"apiVersion": klass.version, "kind": klass.kind, "metadata": meta}
    return klass(kube_api, obj)


def find(klass, name, namespace=None, silent=False, cluster=False):
    kube_api = kube_client()
    try:
        if cluster:
            return klass.objects(kube_api).get(name=name)
        return (
            klass.objects(kube_api).filter(namespace=namespace).get(name=name)
        )
    except pykube.exceptions.ObjectDoesNotExist:
        if not silent:
            raise


def artifacts_configmap(osdpl_name):
    cm_name = f"{osdpl_name}-artifacts"
    return find(
        pykube.ConfigMap,
        cm_name,
        namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
        silent=True,
    )


def resource_list(klass, selector, namespace=None):
    kube_api = kube_client()
    return klass.objects(kube_api).filter(
        namespace=namespace, selector=selector
    )


def wait_for_resource(klass, name, namespace=None, delay=60):
    try:
        find(klass, name, namespace)
    except pykube.exceptions.ObjectDoesNotExist:
        raise kopf.TemporaryError(
            f"The object: {klass.kind} with name '{name}' is not found yet.",
            delay=delay,
        )
    except:
        raise kopf.TemporaryError(
            f"Unknown error occured while getting object: {klass.kind}.",
            delay=delay,
        )


def wait_for_secret(namespace, name):
    wait_for_resource(pykube.Secret, name, namespace)


def wait_for_service(namespace, name):
    wait_for_resource(pykube.Service, name, namespace)


def save_secret_data(
    namespace: str, name: str, data: Dict[str, str], labels=None
):
    secret = {"metadata": {"name": name, "namespace": namespace}, "data": data}
    if labels is not None:
        secret["metadata"]["labels"] = labels

    kube_api = kube_client()
    try:
        find(pykube.Secret, name, namespace)
    except pykube.exceptions.ObjectDoesNotExist:
        pykube.Secret(kube_api, secret).create()
    else:
        pykube.Secret(kube_api, secret).update()


def wait_for_deleted(
    obj,
    times=settings.OSCTL_RESOURCE_DELETED_WAIT_RETRIES,
    seconds=settings.OSCTL_RESOURCE_DELETED_WAIT_TIMEOUT,
):
    for i in range(times):
        if not obj.exists():
            return True
        time.sleep(seconds)
    return False


def get_osdpl(namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE):
    LOG.debug("Getting osdpl object")
    client = kube_client()
    osdpl = list(
        OpenStackDeployment.objects(client).filter(namespace=namespace)
    )
    if len(osdpl) != 1:
        LOG.warning(
            f"Could not find unique OpenStackDeployment resource "
            f"in namespace {namespace}, client: {client}, osdpl: {osdpl}"
        )
        return
    return osdpl[0]


def safe_get_node(name):
    """Get node safe

    Returns a node object with estra safity.
    1. If object exists return it
    2. If nodeWorkloadLock exists return latest known node
    3. Return dummy node
    """
    node = find(Node, name, silent=True)
    if node and node.exists():
        return node

    nwl = find(NodeWorkloadLock, f"openstack-{name}", silent=True)
    if nwl and nwl.exists():
        nwl.reload()
        original_node = json.loads(
            nwl.obj["metadata"]
            .get("annotations", {})
            .get("openstack.lcm.mirantis.com/original-node", "{}")
        )
    else:
        original_node = {}
    dummy = {
        "apiVersion": Node.version,
        "kind": Node.kind,
        "metadata": {
            "name": name,
            "annotations": original_node.get("metadata", {}).get(
                "annotations", {}
            ),
        },
        "spec": original_node.get("spec", {}),
    }
    kube_api = kube_client()
    return Node(kube_api, dummy)


find_osdpl = functools.partial(find, OpenStackDeployment)
find_secret = functools.partial(find, Secret)
KUBE_OBJECTS = get_kubernetes_objects()
