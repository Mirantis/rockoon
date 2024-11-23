#!/usr/bin/env python3

{{/*
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

import openstack
import logging
import sys
import os

from keystoneauth1 import exceptions as ksa_exceptions
from retry import retry
from distutils.util import strtobool
from uuid import UUID

LOG = logging.getLogger(__name__)
logging.basicConfig(
    stream=sys.stdout,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
LOG.setLevel(logging.INFO)

DEPLOY_KERNEL_IMAGE = os.environ.get("DEPLOY_KERNEL_IMAGE")
DEPLOY_RAMDISK_IMAGE = os.environ.get("DEPLOY_RAMDISK_IMAGE")
IRONIC_FAIL_ON_NOT_UPDATED_NODES = strtobool(os.environ.get("IRONIC_FAIL_ON_NOT_UPDATED_NODES", "False"))
CONTROLLER_MANAGED_TAG = "rockoon:managed-image"
IMAGE_TAGS = {}

# ENTRYPOINT
ost = openstack.connect()

@retry((openstack.exceptions.SDKException, ksa_exceptions.base.ClientException), delay=1, tries=7, backoff=2, logger=LOG)
def get_image_id(image_name):
    LOG.info('Get id for image: %s', image_name)
    return ost.image.find_image(image_name, ignore_missing=False)["id"]

@retry((openstack.exceptions.SDKException, ksa_exceptions.base.ClientException), delay=1, tries=7, backoff=2, logger=LOG)
def get_nodes():
    return ost.baremetal.nodes(details=True)

@retry((openstack.exceptions.SDKException, ksa_exceptions.base.ClientException), delay=1, tries=7, backoff=2, logger=LOG)
def get_image_tags(image_id):
    global IMAGE_TAGS
    if image_id in IMAGE_TAGS:
        return IMAGE_TAGS[image_id]["tags"]
    image = ost.image.find_image(image_id)
    if image:
        IMAGE_TAGS[image["id"]] = image
        return image["tags"]

@retry((openstack.exceptions.SDKException, ksa_exceptions.base.ClientException), delay=1, tries=7, backoff=2, logger=LOG)
def patch_node(node, patch):
    return ost.baremetal.patch_node(node, patch, reset_interfaces=None, retry_on_conflict=False)

def is_valid_uuid(uuid, version=4):
    try:
        uuid_obj = UUID(uuid, version=version)
    except ValueError:
        return False
    return True

def is_image_change_needed(node):
    deploy_kernel_id = node.driver_info.get("deploy_kernel")
    deploy_ramdisk_id = node.driver_info.get("deploy_ramdisk")
    if all([deploy_kernel_id, deploy_ramdisk_id]) and is_valid_uuid(deploy_kernel_id) and is_valid_uuid(deploy_ramdisk_id):
        tags_image_kernel = get_image_tags(deploy_kernel_id)
        tags_image_ramdisk = get_image_tags(deploy_ramdisk_id)
        if CONTROLLER_MANAGED_TAG in tags_image_kernel and CONTROLLER_MANAGED_TAG in tags_image_ramdisk:
            return True
    return False

def set_tinyipa_images(image_kernel_id, image_ramdisk_id):
    skip_updating_nodes = []
    updated_nodes = []
    not_updated_nodes = []
    for node in get_nodes():
        patch = []
        LOG.info('Checking node: %s', node["name"])
        if not is_image_change_needed(node):
            LOG.warning('Node: %s has user managed kernel/ramdisk', node["name"])
            skip_updating_nodes.append(node["name"])
            continue
        LOG.info('Updating images driver info for node: %s', node["name"])
        patch = [
            {
                "op": "replace",
                "path": "/driver_info/deploy_kernel",
                "value": image_kernel_id
            },
            {
                "op": "replace",
                "path": "/driver_info/deploy_ramdisk",
                "value": image_ramdisk_id
            }
        ]
        try:
            patch_node(node, patch)
            LOG.info('Updated node: %s', node["name"])
            updated_nodes.append(node["name"])
        except Exception:
            LOG.warning('Error updating node: %s', node["name"])
            not_updated_nodes.append(node["name"])
    return (updated_nodes, not_updated_nodes, skip_updating_nodes)

image_kernel_id = get_image_id(DEPLOY_KERNEL_IMAGE)
image_ramdisk_id = get_image_id(DEPLOY_RAMDISK_IMAGE)
updated_nodes, not_updated_nodes, skip_updating_nodes = set_tinyipa_images(image_kernel_id, image_ramdisk_id)

if skip_updating_nodes:
    LOG.warning('Skip updating kernel/ramdisk for user managed nodes: %s', skip_updating_nodes)

if updated_nodes:
    LOG.info('Successfully updated nodes: %s', updated_nodes)

if not_updated_nodes:
    LOG.warning('Nodes cannot be updated: %s', not_updated_nodes)
    if IRONIC_FAIL_ON_NOT_UPDATED_NODES:
        LOG.error('Failed to update nodes that using MOSK built in kernel/ramdisk')
        sys.exit(1)
