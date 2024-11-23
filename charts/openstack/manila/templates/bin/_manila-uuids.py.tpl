#!/usr/bin/env python3
"""
This script expects that environment variable CONVERT_TO_UUID exists and it
is a JSON string with a dictionary describing the parameters to be converted
for the driver. In YAML this dictionary looks like:

driver1:
  param1:
    type: type
    name: name
  param2:
    type: type
    name: name
driver2:
 .....

For example:
generic:                         - driver name
  service_instance_flavor_id:    - parameter name for this driver
    type: flavor                 - type of object which name will be converted
    name: m1.tiny_test           - name of object which name will be converted
"""

from abc import abstractmethod
from retry import retry
import openstack
import os
import json
import logging
import sys

# Mask permissions to files 0640 dirs 0750
os.umask(0o027)

UUID_CONF="/etc/manila/manila.conf.d/01_uuids.conf"

logging.basicConfig(
    level=logging.WARNING,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger(__name__)

class GenericResource():
    _uuid = None
    _ost = None

    def __init__(self, name):
        os_cloud = os.getenv("OS_CLOUD", "envvars")
        self._ost = openstack.connect(cloud=os_cloud)
        self.name = name

    @abstractmethod
    def _find(self):
        pass

    @property
    def uuid(self):
        if not self._uuid:
            self._uuid = self.find().id
        return self._uuid

    @retry(Exception, delay=1, tries=7, backoff=2, logger=LOG)
    def find(self):
        return self._find()


class Flavor(GenericResource):
    def _find(self):
        return self._ost.compute.find_flavor(self.name, ignore_missing=False)


for_convert = json.loads(os.environ["CONVERT_TO_UUID"])
with open(UUID_CONF, 'w') as f:
    for driver in for_convert:
        f.write(f"[{driver}]\n")
        items_dict = for_convert[driver]
        for item in items_dict:
            uuid = {
                'flavor': Flavor(items_dict[item]['name']).uuid
            }[items_dict[item]['type'].lower()]
            f.write(f"{item} = {uuid}\n")
