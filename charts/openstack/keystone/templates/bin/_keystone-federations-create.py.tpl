#!/usr/bin/env python
# 
# Copyright 2024 Mirantis inc.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging
import os
import sys

import openstack

LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"
LOG_FORMAT = "%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s"
logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATEFMT)
LOG = logging.getLogger("keystone-federations-create")
LOG.setLevel(logging.INFO)
FEDERATION_DATA_FILE_PATH="/etc/keystone/keystone-federations.json"
OLD_DEFAULT_MAPPING = [
    {
        "local": [
            {"user": {"name": "{0}", "email": "{1}", "domain": {"name": "Default"}}},
            {"groups": "{2}", "domain": {"name": "Default"}},
            {"domain": {"name": "Default"}},
        ],
        "remote": [
            {"type": "OIDC-iam_username"},
            {"type": "OIDC-email"},
            {"type": "OIDC-iam_roles"},
        ],
    }
]
NEW_DEFAULT_MAPPING = [
    {
        "local": [
            {"user": {"name": "{0}", "email": "{1}"}},
            {"groups": "{2}", "domain": {"name": "Default"}},
        ],
        "remote": [
            {"type": "OIDC-iam_username"},
            {"type": "OIDC-email"},
            {"type": "OIDC-iam_roles"},
        ],
    }
]


def ensure_identity_provider(cloud, name, domain, remote_ids):
    """Ensure idp exists with the remote_ids provided"""
    try:
        idp = cloud.identity.get_identity_provider(name)
    except openstack.exceptions.ResourceNotFound:
        LOG.info("Creating identity provider %s" % name)
        dom = cloud.identity.find_domain(name_or_id=domain)
        if dom is None:
            LOG.error("Can not resolve domain %s" % domain)
            sys.exit(1)
        idp = cloud.identity.create_identity_provider(
            domain_id=dom.id,
            enabled=True,
            id=name,
            remote_ids=remote_ids,
        )
    else:
        LOG.info("Identity provider %s already exists" % name)
        # TODO(pas-ha): recreate or fail if domain changed in the input?
        if set(idp.remote_ids) != set(remote_ids):
            LOG.info("Enforcing remote_ids on identity_provider %s" % name)
            cloud.identity.update_identity_provider(idp, remote_ids=remote_ids)


def ensure_mapping(cloud, name, rules):
    """Create mapping if absent, edit only if our default one."""
    try:
        mapping = cloud.identity.get_mapping(name)
    except openstack.exceptions.ResourceNotFound:
        LOG.info("Creating mapping %s" % name)
        cloud.identity.create_mapping(id=name, rules=rules)
    else:
        LOG.info("Mapping %s already exists" % name)
        if mapping.rules == OLD_DEFAULT_MAPPING:
            LOG.warning(
                "Existing mapping %s is identical to old MOSK default. "
                "Removing erroneous domain specs from the mapping." % name
            )
            cloud.identity.update_mapping(mapping, rules=NEW_DEFAULT_MAPPING)


def ensure_protocol(cloud, name, idp, mapping):
    try:
        cloud.identity.get_federation_protocol(idp, name)
    except openstack.exceptions.ResourceNotFound:
        LOG.info("Creating protocol %s}." % name)
        cloud.identity.create_federation_protocol(idp, id=name, mapping_id=mapping)
    else:
        LOG.info("Protocol %s already exists" % name)


def main():
    cloud_name = os.getenv("OS_CLOUD_SYSTEM")
    if not cloud_name:
        LOG.error("OS_CLOUD_SYSTEM env var is not defined")
        sys.exit(1)
    cloud = openstack.connect(cloud=cloud_name)

    with open(FEDERATION_DATA_FILE_PATH) as f:
        ks_federations = json.load(f)

    for fed_name, fed in ks_federations.items():
        assert all(k in fed for k in ("identity_provider", "mapping", "protocol"))
        ensure_identity_provider(
            cloud,
            fed["identity_provider"]["id"],
            fed["identity_provider"]["domain_id"],
            fed["identity_provider"]["remote_ids"],
        )
        ensure_mapping(
            cloud,
            fed["mapping"]["id"],
            fed["mapping"]["rules"],
        )
        for protoname, proto in fed["protocol"].items():
            ensure_protocol(
                cloud,
                protoname,
                proto["idp_id"],
                proto["mapping_id"]
            )


if __name__ == "__main__":
    main()
