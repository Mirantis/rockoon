#!/usr/bin/env python3

"""
Mariadb controller

The script is responsible for set mariadb_role: primary to first
active pod in mariadb deployment.

Env variables:
MARIADB_CONTROLLER_DEBUG: Flag to enable debug when set to 1.
MARIADB_CONTROLLER_CHECK_PODS_DELAY: The delay between check pod attempts.
MARIADB_CONTROLLER_PYKUBE_REQUEST_TIMEOUT: The timeout for kubernetes http session
MARIADB_CONTROLLER_PODS_NAMESPACE: The namespace to look for mariadb pods.
MARIADB_MASTER_SERVICE_NAME: The name of master service for mariadb.

Changelog:
0.1.0: Initial varsion
"""


import logging
import os
import sys
import time
import threading
import json

import pykube

from http.server import BaseHTTPRequestHandler, HTTPServer

MARIADB_CONTROLLER_DEBUG = os.getenv("MARIADB_CONTROLLER_DEBUG")
MARIADB_CONTROLLER_CHECK_PODS_DELAY = int(
    os.getenv("MARIADB_CONTROLLER_CHECK_PODS_DELAY", 10)
)
MARIADB_CONTROLLER_PYKUBE_REQUEST_TIMEOUT = int(
    os.getenv("MARIADB_CONTROLLER_PYKUBE_REQUEST_TIMEOUT", 60)
)
MARIADB_CONTROLLER_PODS_NAMESPACE = os.getenv(
    "MARIADB_CONTROLLER_PODS_NAMESPACE", "openstack"
)
MARIADB_MASTER_SERVICE_NAME = os.getenv(
    "MARIADB_MASTER_SERVICE_NAME", "mariadb"
)

log_level = "DEBUG" if MARIADB_CONTROLLER_DEBUG else "INFO"
logging.basicConfig(
    stream=sys.stdout,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOG = logging.getLogger("mariadb-controller")

LOG.setLevel(log_level)

last_master_check = 0

class HealthServer(BaseHTTPRequestHandler):
    def do_GET(self):
        status = {"status": "Ok", "last_master_check": last_master_check}
        if time.time() - last_master_check > MARIADB_CONTROLLER_CHECK_PODS_DELAY * 2:
            self.send_response(500)
            status["status"] = "Fail"
        else:
            self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(bytes(json.dumps(status), "utf-8"))

def health_server():
    webServer = HTTPServer(("localhost", 8080), HealthServer)
    LOG.info("Start health check server.")
    webServer.serve_forever()

health_server_thread = threading.Thread(target=health_server, args=())
health_server_thread.daemon = True

def health_server_start():
    if not health_server_thread.is_alive():
        health_server_thread.start()

def login():
    config = pykube.KubeConfig.from_env()
    client = pykube.HTTPClient(
        config=config, timeout=MARIADB_CONTROLLER_PYKUBE_REQUEST_TIMEOUT
    )
    LOG.info(f"Created k8s api client from context {config.current_context}")
    return client


api = login()


def resource_list(klass, selector, namespace=None):
    return klass.objects(api).filter(namespace=namespace, selector=selector)


def get_mariadb_pods():
    sorted_pods = sorted(
        resource_list(
            pykube.Pod,
            {"application": "mariadb", "component": "server"},
            MARIADB_CONTROLLER_PODS_NAMESPACE,
        ).iterator(),
        key=lambda i: i.name,
    )
    return sorted_pods


def get_mariadb_master_service(namespace):
    return pykube.Service.objects(api).filter(namespace=namespace).get(name=MARIADB_MASTER_SERVICE_NAME)


def link_master_service(pod):
    svc = get_mariadb_master_service(MARIADB_CONTROLLER_PODS_NAMESPACE)
    svc.reload()
    if svc.obj['spec']['selector'].get('statefulset.kubernetes.io/pod-name') == pod.name:
        LOG.debug(f"Nothing to do, master service points to {pod.name}")
    else:
        svc.obj['spec']['selector']['statefulset.kubernetes.io/pod-name'] = pod.name
        svc.update()
        LOG.info(f"Link master service with {pod.name}")


def is_ready(pod):
    if pod.ready and "deletionTimestamp" not in pod.metadata:
        return True


def main():
    global last_master_check
    health_server_start()
    while True:
        for pod in get_mariadb_pods():
            pod.reload()
            if is_ready(pod):
                link_master_service(pod)
                break
        LOG.debug(f"Sleeping for {MARIADB_CONTROLLER_CHECK_PODS_DELAY}")
        last_master_check = time.time()
        time.sleep(MARIADB_CONTROLLER_CHECK_PODS_DELAY)


main()
