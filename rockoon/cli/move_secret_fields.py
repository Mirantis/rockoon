#!/usr/bin/env python3
import argparse
import base64
import sys

import pykube

from rockoon import constants
from rockoon import kube
from rockoon import utils

LOG = utils.get_logger(__name__)

SUPPORTED_OSDPL_FIELDS = [
    ("spec:features:ssl:public_endpoints:ca_cert", "public_endpoints_%s"),
    ("spec:features:ssl:public_endpoints:api_cert", "public_endpoints_%s"),
    ("spec:features:ssl:public_endpoints:api_key", "public_endpoints_%s"),
    ("spec:features:barbican:backends:vault:approle_role_id", "vault_%s"),
    ("spec:features:barbican:backends:vault:approle_secret_id", "vault_%s"),
    ("spec:features:barbican:backends:vault:ssl_ca_crt_file", "vault_%s"),
    (
        "spec:features:keystone:domain_specific_configuration:ks_domains:*:config:ldap:user",
        "ldap_%s_%s",
    ),
    (
        "spec:features:keystone:domain_specific_configuration:ks_domains:*:config:ldap:password",
        "ldap_%s_%s",
    ),
    #    (
    #        "spec:features:neutron:baremetal:ngs:hardware:devices:*:username",
    #        "ngs_%s_%s",
    #    ),
    #    (
    #        "spec:features:neutron:baremetal:ngs:hardware:devices:*:password",
    #        "ngs_%s_%s",
    #    ),
    #    (
    #        "spec:features:neutron:baremetal:ngs:hardware:devices:*:ssh_private_key",
    #        "ngs_%s_%s",
    #    ),
    #    (
    #        "spec:features:neutron:baremetal:ngs:hardware:devices:*:secret",
    #        "ngs_%s_%s",
    #    ),
]


def is_value_from(val):
    if isinstance(val, dict) and "value_from" in val:
        return True
    return False


def handle_field(obj, search, field):
    obj_value = utils.get_in(obj, search)
    if obj_value is None:
        return
    if is_value_from(obj_value):
        LOG.info(f"The field: {field} is already link to secret.")
        return
    if not isinstance(obj_value, str):
        LOG.warning(f"The field: {field} type is not string. Skipping it.")
        return
    return base64.b64encode(obj_value.encode()).decode()


def handle_objects(objs, secret_name=None):
    secret_data = {}
    for obj in objs:
        LOG.info(f"Handling object {obj['metadata']['name']}")
        for field, prefix in SUPPORTED_OSDPL_FIELDS:
            search = field.split(":")
            if "*" not in search:
                res = handle_field(obj, search, field)
                if res is None:
                    continue
                secret_key = prefix % search[-1]
                secret_data[secret_key] = res
            else:
                for key, val in utils.get_in(
                    obj, search[: search.index("*")], {}
                ).items():
                    res = handle_field(
                        val, search[search.index("*") + 1 :], field
                    )
                    if res is None:
                        continue
                    secret_key = prefix % (key, search[-1])
                    secret_data[secret_key] = res

    if secret_data:
        secret_name = secret_name or f"{obj['metadata']['name']}-hidden"
        try:
            kube.find(pykube.Secret, secret_name, obj["metadata"]["namespace"])
        except pykube.exceptions.ObjectDoesNotExist:
            kube.save_secret_data(
                obj["metadata"]["namespace"],
                secret_name,
                data=secret_data,
                labels={
                    constants.OSCTL_SECRET_LABEL[
                        0
                    ]: constants.OSCTL_SECRET_LABEL[1]
                },
            )
            LOG.info(f"Created secret {secret_name}")
        else:
            LOG.warning(
                f"Secret {secret_name} already exists. No data is moved. Skipping secret creation."
            )


def main():
    parser = argparse.ArgumentParser(
        prog="osctl-move-sensitive-data",
        description="Move secret fields from osdpl/osdplsecret objects to kubernetes secret.",
    )
    parser.add_argument("name", help=("OpenStackDeployment name"))
    parser.add_argument(
        "--secret-name",
        help=(
            "The name of hidden secret name, by default is <osdpl-name>-hidden"
        ),
    )

    args = parser.parse_args()
    namespace = "openstack"

    objs = []
    osdpl = kube.find(
        kube.OpenStackDeployment, args.name, namespace, silent=True
    )
    if not osdpl:
        LOG.error(
            f"The OpenStackDeployment {namespace}/{args.name} was not found!"
        )
        sys.exit(1)
    osdpl.reload()
    objs.append(osdpl.obj)

    osdplsecret = kube.OpenStackDeploymentSecret(args.name, namespace)
    if not osdplsecret.exists():
        LOG.info(f"The OpenStackDeploymentSecret does not exists.")
    else:
        osdplsecret.reload()
        objs.append(osdplsecret.obj)

    handle_objects(objs, args.secret_name)
