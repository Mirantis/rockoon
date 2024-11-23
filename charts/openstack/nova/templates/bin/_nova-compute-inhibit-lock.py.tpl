#!/usr/bin/env python3

import os
import sys
import time
import json
import random
import socket

import dbus
from gi.repository import GLib
from dbus.mainloop.glib import DBusGMainLoop
import libvirt
import logging
import openstack


logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger(__name__)

LOOP = None

SHUTDOWN_TIMEOUT = int(os.getenv("SHUTDOWN_TIMEOUT", "300"))
SHUTDOWN_INSTANCES_FILE = os.getenv(
    "SHUTDOWN_INSTANCES_FILE", "/var/lib/nova/shutdown_instances.json"
)


def get_stopped_domains():
    try:
        with open(SHUTDOWN_INSTANCES_FILE, "r") as f:
            return json.load(f)
    except Exception:
        pass
    return []


def clear_stopped_domains():
    with open(SHUTDOWN_INSTANCES_FILE, "w") as f:
        json.dump([], f)


def save_stopped_domains(instances):
    with open(SHUTDOWN_INSTANCES_FILE, "w") as f:
        json.dump(instances, f)


def wait_compute_service(oc, host):
    def _is_alive(oc, host):
        binary = "nova-compute"
        for service in oc.compute.services(host=host, binary=binary):
            if service["state"] == "up":
                return True
        return False

    while not _is_alive(oc, host):
        LOG.info("Waiting compute serice UP on host %s", host)
        delay = random.randrange(10, 30)
        time.sleep(delay)


def recover_stopped_domains():
    instances = get_stopped_domains()
    if instances:
        oc = openstack.connect()
        host = socket.gethostname()
        wait_compute_service(oc, host)
        for instance in instances:
            LOG.info("Recovering stopped instance %s", instance)
            try:
                oc.compute.start_server(instance)
            except openstack.exceptions.ResourceNotFound:
                LOG.warning("Instance %s no longer exists, skipping", instance)
            except openstack.exceptions.ConflictException as e:
                LOG.warning(
                    "Failed to start instance %s with exception: %s", instance, str(e)
                )
    clear_stopped_domains()


def stop_domains(loop):
    conn = None
    stopped_domains = []
    try:
        conn = libvirt.open("qemu:///system")
        for domain in conn.listAllDomains():
            if not domain.isActive():
                continue
            dom_name = domain.name()
            dom_uuid = domain.UUIDString()
            LOG.info(f"Shutting down domain {dom_uuid} {dom_name}")
            domain.shutdownFlags(libvirt.VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN)
            stopped_domains.append(dom_uuid)

        save_stopped_domains(stopped_domains)

        start = time.time()
        while True:
            active = [x.name() for x in conn.listAllDomains() if x.isActive()]
            if time.time() - start > SHUTDOWN_TIMEOUT:
                LOG.error("Timed out while shutting down doamins")
                break
            if not active:
                break
            else:
                LOG.info("Still have running domains %s. Waiting...", active)
            time.sleep(1)
        LOG.info("All domains are stopped.")
    except libvirt.libvirtError as e:
        LOG.error(repr(e), file=sys.stderr)
        loop.quit()


def handle_systemd_shutdown(*args):
    global LOOP
    stop_domains(LOOP)
    LOOP.quit()


# Mask permissions to files 416 dirs 0750
os.umask(0o027)

DBusGMainLoop(set_as_default=True)
bus = dbus.SystemBus()

login = bus.get_object("org.freedesktop.login1", "/org/freedesktop/login1")
manager = dbus.Interface(login, dbus_interface="org.freedesktop.login1.Manager")
inhibitor = manager.Inhibit(
    "shutdown",
    "Nova Shutdown Handler",
    "Handle events on shutdown notification",
    "delay",
)

inhibitor_fd = inhibitor.take()

try:
    recover_stopped_domains()

    LOG.info("Setup singals")
    bus.add_signal_receiver(
        handle_systemd_shutdown,
        dbus_interface="org.freedesktop.login1.Manager",
        signal_name="PrepareForShutdown",
    )
    LOG.info("Setup signals completed")
    LOOP = GLib.MainLoop()
    LOOP.run()
finally:
    os.close(inhibitor_fd)
