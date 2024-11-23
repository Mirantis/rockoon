#!/usr/bin/env python3

import logging
import os
import sys
import yaml
import openstack
import time


logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger(__name__)


ZONES_FILE = os.environ.get("ZONES_FILE", "/tmp/zones.yaml")
ZONE_ACTIVE_TIMEOUT = int(os.environ.get("ZONES_FILE", "600"))
oc = openstack.connect()

def get_zones(zones_file):
    with open(zones_file, 'r') as f:
        return yaml.safe_load(f)

def ensure_recordset(oc, name, zone, type, records):
    try:
        oc.dns.create_recordset(zone, name=name, type=type, records=records)
    except openstack.exceptions.ConflictException:
        pass

def ensure_zone(oc, name, email):
    try:
        zone = oc.dns.create_zone(name=name, email=email)
    except openstack.exceptions.ConflictException:
        zone = list(oc.dns.zones(name=name))[0]
    return zone

zones = get_zones(ZONES_FILE)

LOG.info("Handling zones.")
for zone_name, data in zones.items():
    LOG.info("Handling zone %s", zone_name)
    zone = ensure_zone(oc, zone_name, data["email"])
    LOG.info("Handlings zone %s recordsets", zone_name)
    for recordset in data["recordsets"]:
        ensure_recordset(oc, recordset["name"], zone.id, recordset["type"], records=recordset["records"])

    LOG.info("Waiting zone %s is ACTIVE", zone_name)
    start = time.time()
    while list(oc.dns.zones(name=zone_name))[0].status != "ACTIVE":
        if time.time() - start >= ZONE_ACTIVE_TIMEOUT:
            LOG.error("Timed out in %d waiting zone %s to be active", ZONE_ACTIVE_TIMEOUT, zone_name)
            sys.exit(1)
        time.sleep(5)
    LOG.info("Zone %s is ACTIVE", zone_name)
    LOG.info(f"Handlings zone {zone_name} finished successfully.")
