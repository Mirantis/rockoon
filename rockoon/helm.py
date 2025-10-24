from datetime import datetime
import os
import re
import yaml
import tempfile
import subprocess
from subprocess import PIPE

import kopf
from filelock import FileLock

from rockoon import utils
from rockoon import constants
from rockoon import exception
from rockoon import kube
from rockoon import settings

LOG = utils.get_logger(__name__)

CONF = settings.CONF


def helm_retry(func):
    def wrapper(*args, **kwargs):
        attempt = 1
        max_retries = CONF.getint("helmbundle", "helm_max_retries")
        while attempt <= max_retries:
            try:
                start = datetime.utcnow()
                res = func(*args, **kwargs)
                running_for = (datetime.utcnow() - start).total_seconds()
                LOG.info(
                    f"Running helm {args}, {kwargs} command took {running_for}"
                )
                return res

            except (
                exception.HelmImmutableFieldChange,
                exception.HelmRollback,
                subprocess.TimeoutExpired,
            ) as e:
                LOG.warning(
                    f"Got retriable exception {e}, when calling {func}, retrying, attempt: {attempt}"
                )
                attempt += 1
        raise kopf.PermanentError(
            f"Exhausted all retries {max_retries} while running helm {args} {kwargs}"
        )

    return wrapper


class HelmManager:
    def __init__(
        self,
        binary="helm3",
        namespace="openstack",
        history_max=1,
    ):
        self.binary = binary
        self.namespace = namespace
        self.max_history = str(history_max)
        os_env = os.environ
        os_env.update(
            {
                "HELM_NAMESPACE": namespace,
                "HELM_MAX_HISTORY": str(history_max),
            }
        )
        self.env = os_env
        self.lock = FileLock("/tmp/rockoon_helm.lock")

    def _substitute_local_proxy(self, repo):
        node_ip = os.environ["NODE_IP"]
        return utils.substitute_local_proxy_hostname(repo, node_ip)

    def get_chart_url(self, chart):
        chart_group = [
            chart_group
            for chart_group, charts in constants.CHART_GROUP_MAPPING.items()
            if chart in charts
        ][0]
        return os.path.join(settings.HELM_CHARTS_DIR, chart_group, chart)

    def _guess_and_delete(self, stderr):
        immutable_pattern = r'cannot patch "(.*?)" with kind ([a-zA-Z]+):'
        for match in re.findall(immutable_pattern, stderr):
            try:
                name, kind = match
            except:
                kopf.TemporaryError("Failed to guess name and kind.")

            if kind in constants.KINDS_FOR_MANUAL_UPDATE:
                raise kopf.TemporaryError(
                    f"The {kind} object can't be updated automatically. Please do this update manually."
                )

            LOG.info(f"Trying to remove kind: {kind} with name: {name}")
            kube_class = kube.get_object_by_kind(kind)
            if not kube_class:
                kopf.TemporaryError(
                    "Failed to find pykube class for kind: {kind}"
                )

            obj = kube.find(kube_class, name, self.namespace, silent=True)
            if obj and obj.exists():
                obj.delete(propagation_policy="Background")
                kube.wait_for_deleted(obj)
            LOG.info(f"Successfully removed kind: {kind} with name {name}")

    def _rollback(self, name, args=None):
        args = args or []
        timeout = CONF.getint("helmbundle", "helm_cmd_timeout")

        LOG.info(f"Rolling back release {name}")
        cmd = [
            self.binary,
            "rollback",
            name,
            "--namespace",
            self.namespace,
            *args,
        ]
        res = subprocess.run(
            cmd,
            env=self.env,
            stdin=PIPE,
            stdout=PIPE,
            stderr=PIPE,
            timeout=timeout,
        )
        stdout, stderr = res.stdout.decode(), res.stderr.decode()
        return (stdout, stderr)

    @helm_retry
    def _run_cmd(self, cmd, raise_on_error=True, release_name=None):
        LOG.info(
            "Running helm command started: '%s'",
            cmd,
        )
        timeout = CONF.getint("helmbundle", "helm_cmd_timeout")
        res = subprocess.run(
            [self.binary, *cmd],
            env=self.env,
            stdin=PIPE,
            stdout=PIPE,
            stderr=PIPE,
            timeout=timeout,
        )
        stdout, stderr = res.stdout.decode(), res.stderr.decode()

        LOG.debug(
            "Helm command %s output is: stdout: %s, stderr: %s",
            cmd,
            stdout,
            stderr,
        )
        if res.returncode and raise_on_error:
            LOG.error(
                "Helm command failed. stdout: %s, stderr: %s",
                stdout,
                stderr,
            )
            if stderr.rstrip().endswith(
                ("field is immutable", "are forbidden")
            ):
                LOG.warning("Trying to modify object")
                self._guess_and_delete(stderr)
                raise exception.HelmImmutableFieldChange()
            if (
                "another operation (install/upgrade/rollback) is in progress"
                in stderr
                and release_name
            ):
                LOG.warning(
                    f"The release {release_name} stuck in install/upgrade/rollback. Rollback it."
                )
                self._rollback(release_name)
                raise exception.HelmRollback()
            raise kopf.TemporaryError("Helm command failed")
        return (stdout, stderr)

    def run_cmd(self, cmd, raise_on_error=True, release_name=None):
        LOG.debug(f"Acquiring helm lock for cmd {cmd}")
        with self.lock:
            LOG.debug(f"Acquired helm lock for cmd {cmd}")
            return self._run_cmd(cmd, raise_on_error, release_name)

    def exist(self, name, args=None):
        args = args or []
        cmd = [
            "list",
            "--namespace",
            self.namespace,
            "-o",
            "json",
            *args,
        ]
        stdout, stderr = self.run_cmd(cmd)
        for release in yaml.safe_load(stdout):
            if release["name"] == name:
                return True

    def list(self, args=None):
        args = args or []
        cmd = [
            "list",
            "--namespace",
            self.namespace,
            "-o",
            "json",
            *args,
        ]
        stdout, stderr = self.run_cmd(cmd)
        return yaml.safe_load(stdout)

    def get_release_values(self, name, args=None):
        args = args or []
        cmd = [
            "get",
            "values",
            "--namespace",
            self.namespace,
            name,
            "-o",
            "json",
            *args,
        ]
        stdout, stderr = self.run_cmd(cmd)
        return yaml.safe_load(stdout)

    def set_release_values(self, name, values, chart, args=None):
        args = args or []
        chart_url = self.get_chart_url(chart)
        # Avoid using --reuse-values, it drops values for overrides related upstream
        # https://github.com/helm/helm/issues/10214
        with tempfile.NamedTemporaryFile(
            mode="w", prefix=name, delete=True
        ) as tmp:
            current_values = self.get_release_values(name)
            utils.merger.merge(current_values, values)
            yaml.dump(current_values, tmp)
            cmd = [
                "upgrade",
                name,
                chart_url,
                "--namespace",
                self.namespace,
                "--values",
                tmp.name,
                "--history-max",
                self.max_history,
                *args,
            ]
            return self.run_cmd(cmd, release_name=name)

    def install(self, name, values, chart, args=None):
        args = args or []
        chart_url = self.get_chart_url(chart)
        with tempfile.NamedTemporaryFile(
            mode="w", prefix=name, delete=True
        ) as tmp:
            yaml.dump(values, tmp)
            cmd = [
                "upgrade",
                name,
                chart_url,
                "--namespace",
                self.namespace,
                "--values",
                tmp.name,
                "--history-max",
                self.max_history,
                "--install",
                *args,
            ]
            return self.run_cmd(cmd, release_name=name)

    def install_bundle(self, data):
        for release in data["spec"]["releases"]:
            chart = release["chart"]
            self.install(
                release["name"],
                release["values"],
                chart,
            )

    def delete(self, name, args=None):
        args = args or []
        cmd = ["delete", name, "--namespace", self.namespace, *args]

        stdout, stderr = self.run_cmd(cmd, raise_on_error=False)
        if stderr and "Release not loaded" not in stderr:
            raise kopf.TemporaryError(f"Helm command failed: {stderr}")

    def delete_bundle(self, available_releases):
        current_releases = [x["name"] for x in self.list()]
        to_delete = set(current_releases).intersection(available_releases)
        for release in to_delete:
            self.delete(release)

    def delete_not_active_releases(self, data, available_releases):
        """Remove releases which a dynamic and enabled by feature flag."""

        if not available_releases:
            return
        current_releases = [r["name"] for r in data["spec"]["releases"]]
        to_remove = set(available_releases) - set(current_releases)

        for release in to_remove:
            self.delete(release)
