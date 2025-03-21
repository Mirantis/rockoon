#!/usr/bin/python3
{{/*
Copyright 2020 Mirantis Inc.

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

r"""
    The script provides tooling for resque operations (e.g data backup, data restore) procedure
    for mariadb galera cluster (master-master) in k8s/helm environment.
    Currently supported:
        - physical data backup and restore using mariadb-backup.
        - upload of backups to remote storage (s3).
        - download of backups from remote storage, if local backups are not valid.

    General backup workflow looks like:
        1. Validate all backups against backup hash if it exists.
        2. Get mariadb pods in ready state and perform simple sanity checks ( e.g check wsrep status
           for each pod).
        3. Get information needed for backup (target replica ip, backup paths)
        4. Make pre-backup validation using mariadb_resque.sh
        5. Desynchronize replica from galera cluster.
        6. Launch backup using mariadb_resque.sh
        7. Put mariadb replica back to sync
        8. Update backups hash with newly created backup, or if backups hash does not exist
           calculate backups hash for all backups and create hash cm.
        9. Purge old backups according to backups_to_keep option.
           And remove deleted backups from backups hash

    General restore workflow looks like:
        1. Check target backup hash, if incremental is requested check all needed incrementals
        2. Get list of mariadb pvcs
        3. Make pre-restore validation using using mariadb_resque.sh
        4. Scale mariadb statefulset to 0 replicas
        5. Sequentally for each pvc in list (from step 1) cleanup mysql data directory
           using runner pod
        6. Make restore of mysql data directory using mariadb_resque.sh.
        7. Put cluster in reboot state and select replica from step 5 as leader.
        8. Scale mariadb statefulset back to MARIADB_REPLICAS replicas.
        9. Cleanup unarchieved data from backup directory using mariadb_resque.sh
"""

import argparse
import json
import logging
import operator
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import jinja2
import pymysql
import pykube
from retry import retry
from datetime import datetime, timedelta
from urllib.parse import urlencode
from waiter import wait
import yaml

BACKUP_NAME_FORMAT = "%Y-%m-%d_%H-%M-%S"
MARIADB_VERSION_REGEX = r"([0-9]+)\.([0-9]+)\.([0-9]+)-MariaDB"

def backup_name_format(backup_name):
    names = backup_name.split("/")
    if len(names) > 2:
        raise argparse.ArgumentTypeError(
            f"""Got {backup_name} but backup name should be in <base_backup> or
              <base_backup>/<incremental_backup> format"""
        )
    else:
        for t in names:
            try:
                datetime.strptime(t, BACKUP_NAME_FORMAT)
            except Exception as e:
                raise argparse.ArgumentTypeError(
                    f"In {backup_name} part {t} should be in {BACKUP_NAME_FORMAT} format"
                )
    return backup_name


def set_args():
    parser = argparse.ArgumentParser(description="Process resque script arguments")

    subparsers = parser.add_subparsers(
        help="Parse subcommands of resque script", dest="operation"
    )

    for op in ["backup", "restore"]:
        subparser = subparsers.add_parser(
            op, formatter_class=argparse.RawTextHelpFormatter
        )
        if op == "backup":
            subparser.add_argument(
                "--backup-type",
                choices=["incremental", "full"],
                required=True,
                help="""String. Type of backup.
                    incremental - if latest full backup older than MARIADB_FULL_BACKUP_CYCLE make full backup, else
                                make incremental backup
                    full - make full backup""",
            )
            subparser.add_argument(
                "--backup-timeout",
                default=21600,
                type=int,
                help="Integer. Timeout in seconds for backup runner pod to succeed.",
            )
            subparser.add_argument(
                "--sync-remote-path",
                type=str,
                help="String. Remote path to sync backups to, e.g <remote>:<bucket>/<path>/<to>/<dir>",
            )
        if op == "restore":
            subparser.add_argument(
                "--backup-name",
                type=backup_name_format,
                required=True,
                help="""String. Name of folder with backup e.g 2020-07-30_10-00-17.
                    Will be restored base backup 2020-07-30_10-00-17. In order to restore to specific
                    incremental backup of base 2020-07-30_10-00-17, specify incremental backup after slash
                    e.g. 2020-07-30_10-00-17/2020-07-30_10-00-36. In this case if 2020-07-30_10-00-36
                    is not found the restore procedure will fail.""",
            )
            subparser.add_argument(
                "--replica-restore-timeout",
                type=int,
                default=3600,
                help="Integer. Timeout in seconds for 1 replica data to be restored to mysql data folder",
            )
            subparser.add_argument(
                "--sync-remote-path",
                type=str,
                help="String. Remote path to sync backups from, e.g <remote>:<bucket>/<path>/<to>/<dir>",
            )
    return parser.parse_args(), parser

args, parser = set_args()

operation = args.operation
if not operation:
    parser.error("Mandatory to specify operation")

logger = logging.getLogger(f"mariadb_{operation}")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

def login():
    config = pykube.KubeConfig.from_env()
    client = pykube.HTTPClient(config, timeout=30)
    logger.info(f"Created k8s api client from context {config.current_context}")
    return client


def get_env_var(env_var, default=None):
    if env_var in os.environ:
        return os.environ[env_var]
    if default is not None:
        return default

    logger.critical(f"environment variable {env_var} not set")
    raise RuntimeError("FATAL")

class Pod(pykube.Pod):

    def logs(
         self,
         container=None,
         pretty=None,
         previous=False,
         since_seconds=None,
         since_time=None,
         timestamps=False,
         tail_lines=None,
         limit_bytes=None,
         stream=False,
     ):
         """
         Produces the same result as calling kubectl logs pod/<pod-name>.
         Check parameters meaning at
         http://kubernetes.io/docs/api-reference/v1/operations/,
         part 'read log of the specified Pod'. The result is plain text.
         """
         log_call = "log"
         params = {}
         if container is not None:
             params["container"] = container
         if pretty is not None:
             params["pretty"] = pretty
         if previous:
             params["previous"] = "true"
         if since_seconds is not None and since_time is None:
             params["sinceSeconds"] = int(since_seconds)
         elif since_time is not None and since_seconds is None:
             params["sinceTime"] = since_time
         if timestamps:
             params["timestamps"] = "true"
         if tail_lines is not None:
             params["tailLines"] = int(tail_lines)
         if limit_bytes is not None:
             params["limitBytes"] = int(limit_bytes)

         query_string = urlencode(params)
         log_call += f"?{query_string}" if query_string else ""
         kwargs = {
             "version": self.version,
             "namespace": self.namespace,
             "operation": log_call,
             "stream": stream,
         }
         r = self.api.get(**self.api_kwargs(**kwargs))
         r.raise_for_status()
         if stream:
             return r

         return r.text

class Settings:
    def __init__(self, operation):
        mariadb_pod_namespace = get_env_var("MARIADB_POD_NAMESPACE")

        # common settings
        self.mariadb_replicas = int(get_env_var("MARIADB_REPLICAS"))
        self.runner_image = get_env_var("MARIADB_RESQUE_RUNNER_IMAGE")
        self.runner_service_account = get_env_var(
            "MARIADB_RESQUE_RUNNER_SERVICE_ACCOUNT"
        )
        self.runner_pod_name_prefix = os.environ.get(
            "MARIADB_RESQUE_RUNNER_POD_NAME_PREFIX", "mariadb"
        )
        self.runner_deletion_timeout = int(
            os.environ.get("MARIADB_RESQUE_RUNNER_DELETION_TIMEOUT", 60)
        )
        self.mariadb_target_replica = get_env_var("MARIADB_TARGET_REPLICA")
        self.mariadb_pod_selector = {"application": "mariadb", "component": "server"}
        self.runner_pod_selector = {
            "application": f"mariadb-phy-{operation}-runner",
            "component": f"{operation}-runner",
        }
        self.admin_config_file = "/etc/mysql/admin_user.cnf"

        self.namespace = mariadb_pod_namespace
        self.release_name = f"{mariadb_pod_namespace}-mariadb"

        self.cleanup_mysql_data = False
        self.cleanup_unarchieved_data = False
        self.validate = False
        self.back_path = "/var/backup"
        self.base_back_path = f"{self.back_path}/base"
        self.incr_back_path = f"{self.back_path}/incr"
        self.backup_hash_configmap = get_env_var("MARIADB_BACKUP_HASH_CONFIGMAP")
        self.backup_hash_algo = "md5"
        self.openssl_encryption = get_env_var("MARIADB_OPENSSL_ENCRYPTION", "False").lower() == "true"

        # backup settings
        if operation == "backup":
            self.full_backup_cycle = int(
                os.environ.get("MARIADB_FULL_BACKUP_CYCLE", 604800)
            )
            self.backups_to_keep = int(os.environ.get("MARIADB_BACKUPS_TO_KEEP", 3))
            self.required_space_ratio = float(
                os.environ.get("MARIADB_BACKUP_REQUIRED_SPACE_RATIO", 1.2)
            )
        # restore settings
        if operation == "restore":
            self.mariadb_sts_name = "mariadb-server"
            self.mariadb_sts_scale_timeout = int(
                os.environ.get("MARIADB_STS_SCALE_TIMEOUT", 800)
            )
            self.runner_restore_node_selector = json.loads(
                get_env_var("MARIADB_RESQUE_RUNNER_RESTORE_NODE_SELECTOR")
            )
            self.mariadb_state_configmap = get_env_var(
                "MARIADB_STATE_CONFIGMAP"
            )

    def get_opts_dict(self):
        return self.__dict__


class MysqlBackupException(Exception):
    pass


def mysql_connect(
    host=None,
    port=None,
    unix_socket=None,
    user=None,
    password=None,
    config_file="",
    ssl_cert=None,
    ssl_key=None,
    ssl_ca=None,
    db=None,
    connect_timeout=30,
):
    config = {}

    if ssl_ca is not None or ssl_key is not None or ssl_cert is not None:
        config["ssl"] = {}

    if os.path.exists(config_file):
        config["read_default_file"] = config_file

    if unix_socket is not None:
        config["unix_socket"] = unix_socket
    else:
        if host is not None:
            config["host"] = host
        if port is not None:
            config["port"] = port

    if user is not None:
        config["user"] = user
    if password is not None:
        config["passwd"] = password
    if ssl_cert is not None:
        config["ssl"]["cert"] = ssl_cert
    if ssl_key is not None:
        config["ssl"]["key"] = ssl_key
    if ssl_ca is not None:
        config["ssl"]["ca"] = ssl_ca
    if db is not None:
        config["db"] = db
    if connect_timeout is not None:
        config["connect_timeout"] = connect_timeout

    db_connection = pymysql.connect(**config)

    return db_connection.cursor()


def mysql_get_global_status_vars(host, vars):
    try:
        cursor = mysql_connect(host=host, config_file=SETTINGS.admin_config_file)
        cursor.execute(
            "SHOW GLOBAL STATUS WHERE Variable_name IN ({0})".format(
                ",".join(["'" + var + "'" for var in vars])
            )
        )
        val = cursor.fetchall()
        # fetchall returns tuple of tuples, set is needed to compare statuses
        return set(val)
    except Exception as e:
        logger.critical(f"Failed to get mysql global status variables")
        raise e
    finally:
        cursor.close()


def mysql_set_global_variable(host, var, value):
    try:
        cursor = mysql_connect(host=host, config_file=SETTINGS.admin_config_file)
        cursor.execute("SET GLOBAL {0} = {1}".format(var, value))
    except Exception as e:
        logger.critical(f"Failed to set mysql variable {var} to value {value}")
        raise e
    finally:
        cursor.close()


def get_pods_query(namespace, selector):
    return Pod.objects(K8S_API).filter(namespace=namespace, selector=selector,)


def get_pods_list(namespace, selector):
    return [pod for pod in get_pods_query(namespace, selector)]


def get_mariadb_ready_pods():
    pods = get_pods_list(SETTINGS.namespace, SETTINGS.mariadb_pod_selector)
    return [pod for pod in filter(operator.attrgetter("ready"), pods)]


def get_pods_logs(namespace, selector):
    try:
        pods = get_pods_list(namespace, selector)
        logger.info(f"Gathering pods logs")
        for pod in pods:
            for container in pod.obj["spec"]["containers"]:
                logger.info(f"Pod {pod.name} {container['name']} LOGS START")
                container_log = pod.logs(
                    container=container["name"], timestamps=True, stream=True,
                )
                with container_log as r:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            ch.stream.buffer.write(chunk)
                logger.info(f"Pod {pod.name} {container['name']} LOGS END")
    except Exception as e:
        logger.critical(f"Got an error while gathering logs")
        logging.exception(e)


def wait_pods_removed(namespace, selector, timeout=60):
    try:
        pods = get_pods_list(namespace, selector)
        for pod in pods:
            logger.info(f"Removing pod {pod.name}")
            pod.delete()
        for _ in wait(10, timeout):
            res = get_pods_list(namespace, selector)
            if not res:
                logger.info(f"Pods {pods} are not present.")
                return
    except Exception as e:
        logger.critical("Unable to remove pods, got an error")
        logging.exception(e)


def get_galera_member_state(host, state_fields):
    try:
        status = mysql_get_global_status_vars(host, state_fields)
        return status
    except Exception as e:
        logger.critical(f"Unable to get galera memeber {host} state")
        raise e


def galera_members_in_state(state, pods):
    statuses = {}
    expected = set(state.items())
    res = True
    for pod in pods:
        host = pod.obj["status"]["podIP"]
        status = get_galera_member_state(host, state.keys())
        diff = status.difference(expected)
        statuses[pod] = {"status": status, "diff": diff}
        if diff:
            res = False
    logger.info(f"Galera members states are {statuses}")
    return res


def pre_backup_sanity_check(pods, synced):
    pods_count = len(pods)
    if pods_count == SETTINGS.mariadb_replicas and galera_members_in_state(
        synced, pods
    ):
        logger.info("Sanity check successful")
    else:
        logger.critical(
            f"Something wrong with Galera cluster. Ready pods count {pods_count}."
        )
        raise RuntimeError("FATAL: Sanity check failed")


def get_target_replica_ip(pods, target_pod_name):
    pod_names = []
    for pod in pods:
        pod_names.append(pod.name)
    for pod in pods:
        if pod.name == target_pod_name:
            return pod.obj["status"]["podIP"]


def wait_mariadb_desynced(host, pod_name, desynced, timeout):
    for _ in wait(30, timeout):
        logger.info("Waiting galera to become desynced")
        pod = get_pods_query(SETTINGS.namespace, SETTINGS.mariadb_pod_selector).get(
            name=pod_name
        )
        if not pod.ready:
            if galera_members_in_state(desynced, [pod]):
                logger.info("Galera cluster member is desynced.")
                return
    logger.critical("Galera cluster is not in expected state! Exiting.")
    raise RuntimeError("FATAL: failed wait for mariadb desynced")


def wait_mariadb_synced(host, pod_name, synced, timeout):
    for _ in wait(30, timeout):
        logger.info("Waiting galera to become synced")
        pod = get_pods_query(SETTINGS.namespace, SETTINGS.mariadb_pod_selector).get(
            name=pod_name
        )
        if pod.ready:
            if galera_members_in_state(synced, [pod]):
                logger.info("Galera cluster member is synced.")
                return
    logger.critical("Galera cluster is not in expected state! Exiting.")
    raise RuntimeError("FATAL: failed to wait for mariadb synced")


def get_statefulset(name, namespace, selector):
    return (
        pykube.StatefulSet.objects(K8S_API)
        .filter(namespace=namespace, selector=selector,)
        .get_by_name(name)
    )


def wait_mariadb_sts_scaled(replicas, timeout):
    sts = get_statefulset(
        SETTINGS.mariadb_sts_name, SETTINGS.namespace, SETTINGS.mariadb_pod_selector
    )
    for _ in wait(30, timeout):
        sts.reload()
        sts_status = sts.obj["status"]
        logger.info(
            f"Waiting StatefulSet {SETTINGS.mariadb_sts_name} to be scaled, current sts status is {sts_status}"
        )
        readyReplicas = int(sts_status.get("readyReplicas", 0))
        currentReplicas = int(sts_status.get("currentReplicas", 0))
        sts_replicas = int(sts_status.get("replicas", 0))
        if readyReplicas == currentReplicas == replicas == sts_replicas:
            logger.info(f"StatefulSet {SETTINGS.mariadb_sts_name} scaled")
            return
    logger.critical(
        f"StatefulSet {SETTINGS.mariadb_sts_name} failed to scale within timeout {timeout}"
    )
    raise RuntimeError("FATAL: failed to wait for mariadb StatefulSet scaled")


def run_cmd(popenargs,
            return_stdout=False,
            return_stderr=False,
            check=True,
            timeout=None,
            **kwargs):
    """Run subprocess and write output to tmp files"""
    def _get_output(out_file, return_out=False):
        out = []
        out_file.seek(0)
        for line in out_file:
            l = line.decode().strip()
            logger.info(l)
            if return_out:
                out.append(l)
        return out
    out = []
    err = []
    with tempfile.NamedTemporaryFile(delete=True) as errf:
        with tempfile.NamedTemporaryFile(delete=True) as outf:
            try:
                logger.info(f"Running command: {popenargs}, started at {time.ctime(time.time())}")
                child = subprocess.run(popenargs, stdout=outf, stderr=errf, timeout=timeout, check=check, **kwargs)
                logger.info(f"Finished command: {popenargs} at {time.ctime(time.time())}")
                res = child.returncode
            finally:
                logger.info("Command STDOUT:")
                out = _get_output(outf, return_stdout)
                logger.info("Command STDERR:")
                err = _get_output(errf, return_stderr)
    return (res, out, err)


def get_mariabackup_version():
    """ $ mariadb-backup --version
    mariadb-backup based on MariaDB server 10.6.17-MariaDB debian-linux-gnu (x86_64)
    """
    cmd_res = run_cmd(["mariadb-backup", "--version"], return_stderr=True)[2]
    res = re.search(MARIADB_VERSION_REGEX, " ".join(cmd_res))
    return {"major": res.group(1), "minor": res.group(2), "patch": res.group(3)}


def get_dirs(path):
    if os.path.exists(path):
        return os.listdir(path)
    return []


def find_latest_backup(path):
    # sorting backup directories (dates) in ascending order
    back_dirs = sorted(get_dirs(path))
    if back_dirs:
        back_dir = back_dirs[-1]
        backup_path = f"{path}/{back_dir}"
        if not os.path.exists(f"{backup_path}/backup.successful"):
            raise Exception(f"Successful backup not found at {backup_path} !!!! Cannot proceed")
        return back_dir

def get_backup_version():

    def find_latest_backup_info(path):
        back_dirs = sorted(get_dirs(path), reverse=True)
        for d in back_dirs:
            for info_file in ["mariadb_backup_info", "xtrabackup_info"]:
                info_file_path = os.path.join(path, d, info_file)
                if os.path.exists(info_file_path):
                    return info_file_path

    backup_info = find_latest_backup_info(SETTINGS.base_back_path)
    if backup_info:
        with open(backup_info) as f:
            for line in f:
                if line.startswith("tool_version"):
                    res = re.search(MARIADB_VERSION_REGEX, line.split("=")[1].strip())
                    return {"major": res.group(1), "minor": res.group(2), "patch": res.group(3)}
    else:
        return {"major": "0", "minor": "0", "patch": "0"}


def get_backup_type(args):
    backup_type = args.backup_type
    if not backup_type == "full" and os.path.exists(SETTINGS.base_back_path):
        mb_version = get_mariabackup_version()
        bk_version = get_backup_version()
        logger.info(
            f"Current MariaDB version is {mb_version['major']}.{mb_version['minor']}.{mb_version['patch']}"
        )
        logger.info(
            f"The last backup archive was created with MariaDB version {bk_version['major']}.{bk_version['minor']}.{bk_version['patch']}"
        )
        if not (
            mb_version["major"] == bk_version["major"]
            and mb_version["minor"] == bk_version["minor"]
        ):
            logger.warning(f"Version of MariaDB is changed. Process FULL backup instead {backup_type}")
            backup_type = "full"
    return backup_type

def get_backup_dirs(type):

    def _need_incremental(op_start, latest_base_back_dir):
        latest_base_backup_date = datetime.strptime(latest_base_back_dir, BACKUP_NAME_FORMAT)
        full_backup_max_age = timedelta(seconds=SETTINGS.full_backup_cycle)
        return (op_start - latest_base_backup_date) <= full_backup_max_age

    def _get_incremental_dirs(incr_back_path, latest_base_back_dir, backup_d):
        # /var/backup/incr/YYYY-MM-DD_hh-mm-ss
        incr_base_back_path = f"{incr_back_path}/{latest_base_back_dir}"
        latest_incr_backup_dir = find_latest_backup(incr_base_back_path)
        if latest_incr_backup_dir:
            logger.info(f"Doing incremental backup over base incremental backup {latest_base_back_dir}/{latest_incr_backup_dir}")
            # incr/YYYY-MM-DD_hh-mm-ss/YYYY-MM-DD_hh-mm-ss
            incremental_basedir = f"incr/{latest_base_back_dir}/{latest_incr_backup_dir}"
        else:
            logger.info(f"Doing first incremental backup over base backup {latest_base_back_dir}")
            # base/YYYY-MM-DD_hh-mm-ss
            incremental_basedir = f"base/{latest_base_back_dir}"
        target_dir = f"incr/{latest_base_back_dir}/{backup_d}"
        return (target_dir, incremental_basedir)

    op_start = datetime.now()
    backup_d = op_start.strftime(BACKUP_NAME_FORMAT)
    base_back_path = SETTINGS.base_back_path
    incr_back_path = SETTINGS.incr_back_path

    if type == "incremental":
        # TODO: if latest base backup was unsuccessfull, backups won't be created
        #       till user resolve this manulally
        latest_base_back_dir = find_latest_backup(base_back_path)
        if latest_base_back_dir and _need_incremental(op_start, latest_base_back_dir):
            return _get_incremental_dirs(incr_back_path, latest_base_back_dir, backup_d)

    target_dir = f"base/{backup_d}"
    return (target_dir, "")


def get_operation_cmd_args(operation, **kwargs):
    cmd_args_mapping = {
        "backup": [
            "target_dir",
            "incremental_base_dir",
            "mariadb_host",
            "required_space_ratio",
            "validate",
            "openssl_encryption"
        ],
        "restore": ["backup_name", "validate"],
        "cleanup": ["cleanup_unarchieved_data", "cleanup_mysql_data"]
    }
    cmd_args = []
    for arg in cmd_args_mapping[operation]:
        cmd_args.append(f"--{arg.replace('_', '-')}={kwargs[arg]}")
    return cmd_args


def run_operation_cmd(operation, timeout, **kwargs):
    cmd = ["/tmp/run_mariadb_resque.sh", operation]
    try:
        logger.info(f"Operation timeout set to {timeout}")
        args = get_operation_cmd_args(operation, **kwargs)
        cmd.extend(args)
        return run_cmd(cmd, timeout=timeout)
    except Exception as e:
        logger.critical(f"FATAL: {operation} failed")
        logging.exception(e)
        raise e


def run_rclone_cmd(args, **kwargs):
    cmd = ["rclone"]
    if "filters" in kwargs:
        filters = kwargs.pop("filters")
        for f in filters:
            args.append(f"--filter={f}")
    cmd.extend(args)
    return run_cmd(cmd, **kwargs)


def get_dirs_filters(dirs):
    if not dirs:
        raise Exception("Directories list is required")
    # exclude nested service paths
    res = []
    rules_start = '- {**/unarchieved/**,*.prepared}'
    # exclude anything that can be present in root backup dir
    rules_end = '- /**'
    res.append(rules_start)
    for d in dirs:
        res.append(f"+ {d}/**")
    res.append(rules_end)
    return res


def get_remote_dirs(path):
    #TODO: maybe need filters
    res = []
    res_json = "\n".join(run_rclone_cmd(["lsjson", "--dirs-only", path], return_stdout=True)[1])
    res_data = json.loads(res_json)
    for item in res_data:
        res.append(item["Name"])
    return res


def get_hashsum(path, dirs=None, algo="md5"):
    cmd_args = ["hashsum", algo, path]
    kwargs = {"return_stdout": True}
    if dirs:
        kwargs["filters"] = get_dirs_filters(dirs)
    return run_rclone_cmd(cmd_args, **kwargs)[1]


def check_hashsum(path, check, dirs=None, algo="md5"):
    cmd_args = ["hashsum", algo, path, f"--checkfile={check}"]
    kwargs = {}
    if dirs:
        kwargs["filters"] = get_dirs_filters(dirs)
    run_rclone_cmd(cmd_args, **kwargs)


def run_mariadb_operation(operation, timeout, **kwargs):
    try:
        ENV = jinja2.Environment(
            loader=jinja2.FileSystemLoader("/tmp"),
            extensions=["jinja2.ext.do", "jinja2.ext.loopcontrols"],
        )
        tpl = ENV.get_template("resque_runner.yaml.j2")
        logger.debug(f"Using template {tpl.filename}")
        kwargs["cmd_args"] = get_operation_cmd_args(operation, **kwargs)
        text = tpl.render(
            operation=operation,
            timestamp=int(time.time()),
            cmd_args=kwargs["cmd_args"],
            pvc_name=kwargs["pvc_name"],
            namespace=kwargs["namespace"],
            runner_pod_name_prefix=kwargs["runner_pod_name_prefix"],
            runner_pod_selector=kwargs["runner_pod_selector"],
            runner_node_selector=kwargs["runner_node_selector"],
            runner_service_account=kwargs["runner_service_account"],
            runner_image=kwargs["runner_image"],
            openssl_encryption=kwargs["openssl_encryption"],
        )
        data = yaml.safe_load(text)
        Pod(K8S_API, data).create()
        runner_status = None
        r_pods = []
        for _ in wait(60, timeout):
            r_pods = get_pods_list(kwargs["namespace"], kwargs["runner_pod_selector"])
            if r_pods:
                runner_status = r_pods[0].obj["status"]
                if runner_status["phase"] == "Failed":
                    logger.critical(
                        f"{operation.upper()} failed! {operation} runner pod status {runner_status}"
                    )
                    raise MysqlBackupException()
                elif runner_status["phase"] == "Succeeded":
                    logger.info(
                        f"{operation.upper()} is finished successfully, {operation} runner pod status {runner_status}"
                    )
                    return
                else:
                    logger.info(
                        f"{operation.upper()} is still running, {operation} runner pod status {runner_status}"
                    )
            else:
                logger.info(f"No any {operation} runner pods found, waiting...")
        logger.critical(
            f"{operation.upper()} is timed out! {operation} runner pod status {runner_status}"
        )
    except Exception as e:
        logger.critical(f"FATAL: {operation} failed")
        logging.exception(e)
        raise e
    finally:
        get_pods_logs(kwargs["namespace"], kwargs["runner_pod_selector"])
        wait_pods_removed(
            kwargs["namespace"],
            kwargs["runner_pod_selector"],
            SETTINGS.runner_deletion_timeout,
        )


def purge_old_backups():
    # sorting backup directories (dates) in ascending order
    base_back_path = SETTINGS.base_back_path
    incr_back_path = SETTINGS.incr_back_path
    to_keep = SETTINGS.backups_to_keep
    full_backups = sorted(get_dirs(base_back_path))
    full_backups_count = len(full_backups)
    remove_count = full_backups_count - to_keep
    removed = []
    logger.info(f"Keeping {to_keep} newest backups")
    if remove_count > 0:
        for i in range(remove_count):
            backup_name = full_backups[i]
            base_backup = f"{base_back_path}/{backup_name}"
            incr_backup = f"{incr_back_path}/{backup_name}"
            logger.info(f"Deleting backup {base_backup} and all its incrementals")
            shutil.rmtree(base_backup)
            removed.append(f"base/{backup_name}")
            if os.path.exists(incr_backup):
                shutil.rmtree(incr_backup)
                removed.append(f"incr/{backup_name}")
    else:
        logger.info("No outdated backups found")
    return removed


def run_mariadb_phy_backup(pod_ip, timeout, **kwargs):
    kwargs["mariadb_host"] = pod_ip
    run_operation_cmd("backup", timeout, **kwargs)


def run_mariadb_phy_backup_validation(pod_ip, timeout, **kwargs):
    kwargs["mariadb_host"] = pod_ip
    kwargs["validate"] = True
    run_operation_cmd("backup", timeout, **kwargs)


def run_mariadb_data_cleanup(pvc_name, timeout, **kwargs):

    kwargs["pvc_name"] = pvc_name
    kwargs["cleanup_mysql_data"] = True
    run_mariadb_operation("cleanup", timeout, **kwargs)


def run_mariadb_unarchieved_cleanup(timeout, **kwargs):

    kwargs["cleanup_unarchieved_data"] = True
    run_operation_cmd("cleanup", timeout, **kwargs)


def run_mariadb_phy_restore(timeout, **kwargs):

    run_operation_cmd("restore", timeout, **kwargs)


def run_mariadb_phy_restore_validation(timeout, **kwargs):

    kwargs["validate"] = True
    run_operation_cmd("restore", timeout, **kwargs)


def scale_mariadb_sts(sts, replicas, retries=5):
    # The object can be changed between reload and scale steps,
    # this can cause scale to fail, so adding retries
    res = False
    for i in range(0, retries):
        try:
            sts.reload()
            sts.scale(replicas)
            res = True
        except Exception as e:
            logger.critical(f"{sts.kind} {sts.name} scale failed, retrying")
            logging.exception(e)
            continue
        break
    if not res:
        logger.critical(f"Unable to scale {sts.kind} {sts.name}")
        raise RuntimeError("FATAL")


@retry(Exception, delay=1, tries=7, backoff=2, logger=logger)
def update_configmap_annotations(cm_name, namespace, cm_data):
    cm = pykube.ConfigMap.objects(K8S_API).filter(namespace=namespace).get_by_name(cm_name)
    cm.reload()
    cm.patch({"metadata":{"annotations":cm_data}})


@retry(Exception, delay=1, tries=2, backoff=2, logger=logger)
def get_configmap(cm_name, namespace):
    cm = pykube.ConfigMap.objects(K8S_API).filter(namespace=namespace).get_by_name(cm_name)
    cm.reload()
    return cm


@retry(Exception, delay=5, tries=7, backoff=2, logger=logger)
def update_configmap_data(cm, data):
    logger.info(f"Patching configmap {cm.name}")
    cm.reload()
    cm.patch({"data": data})


@retry(Exception, delay=1, tries=7, backoff=2, logger=logger)
def create_configmap(cm_name, namespace, data):
    obj = {
            "kind": "ConfigMap",
            "apiVersion": "v1",
            "data": data,
            "metadata":{
                "name": cm_name,
                "namespace": namespace,
            }
        }
    pykube.ConfigMap(K8S_API, obj).create()


def get_backups_hash_data(cm):
    cm_data = cm.obj.get("data", {})
    data = json.loads(cm_data.get("hash_table", "{}"))
    return data


def set_hash_data(rclone_out, data):
    for line in rclone_out:
        checksum, key = line.split()
        if key in data.keys():
            raise Exception(f"Key {key} already present in hash, overwriting hash is forbidden")
        data[key] = {"checksum": checksum}
    return {"hash_table": json.dumps(data)}


def create_backups_hash(cm_name, namespace, algo="md5"):
    logger.info(f"Creating new etalon hash")
    out = get_hashsum(SETTINGS.back_path, dirs=["base", "incr"], algo=algo)
    data = {}
    cm_data = set_hash_data(out, data)
    create_configmap(cm_name, namespace, cm_data)


def add_hash_records(cm, backup_dir, algo="md5"):
    logger.info(f"Adding new records to backups hash")
    data = get_backups_hash_data(cm)
    out = get_hashsum(SETTINGS.back_path, dirs=[backup_dir], algo=algo)
    cm_data = set_hash_data(out, data)
    update_configmap_data(cm, cm_data)


def remove_hash_records(cm_name, namespace, to_remove):
    logger.info(f"Removing backups from hash")
    cm = get_configmap(cm_name, namespace)
    data = get_backups_hash_data(cm)
    for d in to_remove:
        for key in list(data):
            if key.startswith(d):
                data.pop(key)
    cm_data = {"hash_table": json.dumps(data)}
    update_configmap_data(cm, cm_data)


def ensure_backups_hash(backup_dir, cm_name, namespace, algo="md5"):
    try:
        cm = get_configmap(cm_name, namespace)
        add_hash_records(cm, backup_dir, algo=algo)
    except pykube.exceptions.ObjectDoesNotExist:
        logger.info(f"Backups hash does not exist")
        create_backups_hash(cm_name, namespace, algo=algo)


def check_backups_data(hash_data, backups, algo="md5", backup_dir=None):
    if not backup_dir:
        backup_dir = SETTINGS.back_path
    try:
        with tempfile.NamedTemporaryFile(delete=False, mode="w+t") as checkf:
            for file_path, item in hash_data.items():
                # rclone requires 2 whitespaces between checksum and file
                line = f"{item['checksum']}  {file_path}"
                checkf.write(f"{line}\n")
        check_hashsum(backup_dir, checkf.name, dirs=backups, algo=algo)
        return True
    except subprocess.CalledProcessError as e:
        logger.info(f"Backups data in wrong state, {e}")
    finally:
        os.remove(checkf.name)
    return False


def copy_backups(src, dst, backups=None):
    # copy new backups with checking by hashsum, fail if existing backup changed
    cmd = ["copy", src, dst, "-c", "--immutable"]
    if backups:
        filters = get_dirs_filters(backups)
    else:
        # copy all backups from base and incr directories
        filters = get_dirs_filters(["base", "incr"])
    run_rclone_cmd(cmd, filters=filters)


def sync_backups(src, dst, backups=None):
    # sync directories structure from src to dst, check files by checksum
    cmd = ["sync", src, dst, "-c"]
    if backups:
        filters = get_dirs_filters(backups)
    else:
        filters = get_dirs_filters(["base", "incr"])
    run_rclone_cmd(cmd, filters=filters)


def remove_remote_backups(path, to_remove):
    logger.info(f"Removing backups {to_remove} from remote ")
    for backup in to_remove:
        run_rclone_cmd(["purge", f"{path}/{backup}"])


def get_incremental_backups(base_backup, target_backup, remote_back_dir=None):
    if remote_back_dir:
        incr_path = f"{remote_back_dir}/incr/{base_backup}"
        generic_get_dirs = get_remote_dirs
    else:
        incr_path = f"{SETTINGS.back_path}/incr/{base_backup}"
        generic_get_dirs = get_dirs
    incr_dirs = generic_get_dirs(incr_path)
    incr_backups = [f"{base_backup}/{incr}" for incr in sorted(incr_dirs)]
    try:
        index = incr_backups.index(f"{base_backup}/{target_backup}")
    except ValueError as e:
        logger.error(f"Incremental backup {target_backup} not found in {incr_path}")
        return []
    return incr_backups[0:index+1]


def validate_backups_hash(cm_name, namespace, base_backup=None, incr_backups=[], algo="md5", backup_dir=None):

    backups = []

    if base_backup:
        base_backup_path = f"base/{base_backup}"
        backups = [base_backup_path]

    if incr_backups:
        incr_backup_paths = [f"incr/{incr}" for incr in incr_backups]
        backups.extend(incr_backup_paths)

    if not base_backup and not incr_backups:
        backups = ["base", "incr"]

    logger.info(f"Checking backup hash for backup dirs {backups}")
    res = False
    try:
        cm = get_configmap(cm_name, namespace)
        data = get_backups_hash_data(cm)
        res = check_backups_data(data, backups, algo=algo, backup_dir=backup_dir)
    except pykube.exceptions.ObjectDoesNotExist:
        logger.info(f"Backups hash does not exist, will be created after backup")
        res = True
    return res


def pre_restore_backups_check(backup_name, remote_back_dir=None):
    backup_names = backup_name.split("/")
    base_backup = backup_names[0]
    incr_backups = []
    if len(backup_names) == 2:
        incr_backup = backup_names[1]
        incr_backups = get_incremental_backups(
            base_backup,
            incr_backup,
            remote_back_dir=remote_back_dir
        )
        if not incr_backups:
            logger.warning(f"Requested incremental backup {incr_backup} not found")
            return []
    if validate_backups_hash(
            SETTINGS.backup_hash_configmap,
            SETTINGS.namespace,
            algo=SETTINGS.backup_hash_algo,
            base_backup=base_backup,
            incr_backups=incr_backups,
            backup_dir=remote_back_dir
        ):
         logger.info("Backups file data is valid")
         res = [f"base/{base_backup}"]
         res.extend([f"incr/{incr}" for incr in incr_backups])
         return res
    return []


K8S_API = login()

SETTINGS = Settings(operation)

operation_kwargs = SETTINGS.get_opts_dict()

sync_enabled = False

if args.sync_remote_path:
    logger.info(f"Remote sync for backups is enabled. Remote path is {args.sync_remote_path}")
    sync_enabled = True

def main():
    # Concurrent operations are not allowed
    existing_runners = get_pods_list(SETTINGS.namespace, SETTINGS.runner_pod_selector)
    if existing_runners:
        logger.critical(
            f"Found another {operation} already running! Found existing runner pods {existing_runners}"
        )
        raise RuntimeError("FATAL")

    if operation == "backup":
        # checks and validation start

        # check local backups hash
        if not validate_backups_hash(
            SETTINGS.backup_hash_configmap, SETTINGS.namespace, algo=SETTINGS.backup_hash_algo
        ):
            # check remote backups hash
            if sync_enabled and validate_backups_hash(
                SETTINGS.backup_hash_configmap,
                SETTINGS.namespace,
                algo=SETTINGS.backup_hash_algo,
                backup_dir=args.sync_remote_path,
            ):
                logger.info("Remote backups are valid, downloading them with overwrite")
                # syncing backups from remote with removing of directories not present on remote
                sync_backups(args.sync_remote_path, SETTINGS.back_path)
            else:
                raise RuntimeError("FATAL")


        synced_state = {
            "wsrep_ready": "ON",
            "wsrep_cluster_status": "Primary",
            "wsrep_local_state_comment": "Synced",
            "wsrep_cluster_size": str(SETTINGS.mariadb_replicas),
            "wsrep_connected": "ON",
        }
        desynced_state = synced_state.copy()
        desynced_state["wsrep_local_state_comment"] = "Donor/Desynced"

        ready_pods = get_mariadb_ready_pods()
        logger.info(f"Found mariadb ready pods {ready_pods}")

        pre_backup_sanity_check(ready_pods, synced_state)

        logger.info(f"Target replica is: {SETTINGS.mariadb_target_replica}")
        # we need pod ip as mariadb-backup util doesn't work with fqdn
        mariadb_pod_ip = get_target_replica_ip(ready_pods, SETTINGS.mariadb_target_replica)
        # target_dir and incremental_base_dir are required in operation kwargs
        # according to get_operation_cmd_args, we can remove them from operation
        # kwargs when validation is removed from resque.sh
        backup_type = get_backup_type(args)
        backup_target_dir, incremental_base_dir = get_backup_dirs(backup_type)

        operation_kwargs["target_dir"] = backup_target_dir
        operation_kwargs["incremental_base_dir"] = incremental_base_dir

        logger.info(
            f"""Target replica ip is: {mariadb_pod_ip},
                Target backup type is: {backup_type},
                Target backup directory is {backup_target_dir},
                """
        )

        run_mariadb_phy_backup_validation(
                mariadb_pod_ip,
                args.backup_timeout,
                **operation_kwargs,
            )
        # checks and validation end

        # backup start
        try:
            mysql_set_global_variable(mariadb_pod_ip, "wsrep_desync", "ON")
            wait_mariadb_desynced(
                mariadb_pod_ip, SETTINGS.mariadb_target_replica, desynced_state, 300
            )

            run_mariadb_phy_backup(
                mariadb_pod_ip,
                args.backup_timeout,
                **operation_kwargs,
            )

        except Exception as e:
            logger.critical("Fatal, got an error")
            raise e
        finally:
            mysql_set_global_variable(mariadb_pod_ip, "wsrep_desync", "OFF")
            wait_mariadb_synced(mariadb_pod_ip, SETTINGS.mariadb_target_replica, synced_state, 300)
        # backup end
        ensure_backups_hash(
            backup_target_dir,
            SETTINGS.backup_hash_configmap,
            SETTINGS.namespace,
            algo=SETTINGS.backup_hash_algo
        )
        # copy all backups not present on remote
        if sync_enabled:
            copy_backups(SETTINGS.back_path, args.sync_remote_path)

        # removed_backup_dirs are needed to update etalon hash
        removed_backup_dirs = purge_old_backups()
        if removed_backup_dirs:
            remove_hash_records(
                SETTINGS.backup_hash_configmap,
                SETTINGS.namespace,
                removed_backup_dirs
            )
            if sync_enabled:
                remove_remote_backups(args.sync_remote_path, removed_backup_dirs)

    elif operation == "restore":
        operation_kwargs["backup_name"] = args.backup_name
        operation_kwargs["runner_node_selector"] = SETTINGS.runner_restore_node_selector

        # checks and validation start
        if not pre_restore_backups_check(args.backup_name):
            if sync_enabled:
                to_sync = pre_restore_backups_check(args.backup_name, remote_back_dir=args.sync_remote_path)
                if to_sync:
                    sync_backups(args.sync_remote_path, SETTINGS.back_path, backups=to_sync)
                else:
                    logger.error(f"Remote backups are corrupted")
                    raise RuntimeError("FATAL")
            else:
                logger.error(f"Local backups are corrupted")
                raise RuntimeError("FATAL")

        mariadb_sts = get_statefulset(
            SETTINGS.mariadb_sts_name, SETTINGS.namespace, SETTINGS.mariadb_pod_selector
        )

        mariadb_pvc_list = [
            f"mysql-data-{mariadb_sts.name}-{num}" for num in range(SETTINGS.mariadb_replicas)
        ]

        run_mariadb_phy_restore_validation(args.replica_restore_timeout, **operation_kwargs)
        # checks and validation end

        # restore start
        scale_mariadb_sts(mariadb_sts, 0)
        wait_mariadb_sts_scaled(0, SETTINGS.mariadb_sts_scale_timeout)

        for pvc in mariadb_pvc_list:
            run_mariadb_data_cleanup(pvc, args.replica_restore_timeout, **operation_kwargs)

        run_mariadb_phy_restore(args.replica_restore_timeout, **operation_kwargs)

        cm_data = {
            "openstackhelm.openstack.org/cluster.state": "reboot",
            "openstackhelm.openstack.org/reboot.node": SETTINGS.mariadb_target_replica
        }

        update_configmap_annotations(SETTINGS.mariadb_state_configmap, SETTINGS.namespace, cm_data)

        scale_mariadb_sts(mariadb_sts, SETTINGS.mariadb_replicas)
        wait_mariadb_sts_scaled(
            SETTINGS.mariadb_replicas, SETTINGS.mariadb_sts_scale_timeout
        )
        # restore end

        # cleanup unarchieved data left from restore
        run_mariadb_unarchieved_cleanup(args.replica_restore_timeout, **operation_kwargs)

    logger.info(f"{operation} finished successful!")


if __name__ == "__main__":
    main()
