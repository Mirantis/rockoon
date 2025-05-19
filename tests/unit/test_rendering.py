import logging
import copy
import os
import yaml
from jsonschema import validate
from unittest import mock

import pytest

from rockoon import constants
from rockoon import layers
from rockoon import kube

logger = logging.getLogger(__name__)

OUTPUT_DIR = "tests/fixtures/render_service_template/output"
INPUT_DIR = "tests/fixtures/render_service_template/input"
SIZES_DIR = "rockoon/templates/size"
CHILD_OBJECTS_DIR = "child_objects"
CHILD_OBJECTS_SCHEMA = """
type: object
additionalProperties: False
patternProperties:
  ".*":
    type: object
    additionalProperties: False
    patternProperties:
      "(Deployment|StatefulSet|DaemonSet)":
        additionalProperties: False
        type: object
        patternProperties:
          ".*":
            additionalProperties: False
            type: object
            required:
              - hash_fields
              - images
              - manifest
              - pod_labels
            properties:
              hash_fields:
                type: array
                items:
                  type: string
              images:
                type: array
                items:
                  type: string
              manifest:
                type: string
              type:
                type: string
                enum:
                  - static
                  - dynamic
              pod_labels:
                type: object
                patternProperties:
                  ".*":
                    type: string
              ports:
                type: array
                items:
                   required:
                   - name
                   - port
                   - protocol
                   type: object
                   properties:
                     port:
                       type: integer
                     protocol:
                       type: string
                       enum:
                       - TCP
                       - UDP
                     name:
                       type: string
              connections:
                type: object
                items: &connection_items
                  properties:
                    egress:
                      type: array
                      items:
                        type: object
                        properties:
                          to_child_object:
                            type: object
                            required:
                            - service
                            - chart
                            - kind
                            - ports
                            properties:
                              service:
                                type: string
                              chart:
                                type: string
                              kind:
                                type: string
                                enum:
                                - StatefulSet
                                - DaemonSet
                                - Deployment
                              ports:
                                type: array
                                items:
                                  type: string
      "(Job|CronJob)":
        additionalProperties: False
        type: object
        patternProperties:
          ".*":
            additionalProperties: False
            type: object
            required:
              - hash_fields
              - images
              - manifest
              - pod_labels
            properties:
              hash_fields:
                type: array
                items:
                  type: string
              images:
                type: array
                items:
                  type: string
              manifest:
                type: string
              type:
                type: string
                enum:
                  - static
                  - dynamic
              pod_labels:
                type: object
                patternProperties:
                  ".*":
                    type: string
              connections:
                type: object
                <<: *connection_items
      "(Ingress|Service|Secret)":
        additionalProperties: False
        type: object
        patternProperties:
          ".*":
            additionalProperties: False
            type: object
            required:
              - hash_fields
              - images
              - manifest
            properties:
              hash_fields:
                type: array
                items:
                  type: string
              images:
                type: array
                items:
                  type: string
              manifest:
                type: string
              type:
                type: string
                enum:
                  - static
                  - dynamic
              pod_labels:
                type: object
                patternProperties:
                  ".*":
                    type: string
              connections:
                type: object
                <<: *connection_items
"""

# Remove excluded services once contexts with these services are added
excluded_services = {
    "tempest",
    "object-storage",
    "stepler",
}
infra_services = {
    "cloudprober",
    "messaging",
    "database",
    "memcached",
    "ingress",
    "redis",
    "coordination",
    "descheduler",
    "dynamic-resource-balancer",
}


def render_helmbundle(service, spec, **kwargs):
    data = layers.render_service_template(
        service,
        # osdpl body and metadata are not used in templates rendering
        spec,
        logging,
        **kwargs,
    )
    return data


def get_render_kwargs(service, context, default_args):
    service_t_args = {}
    with open(f"{INPUT_DIR}/{context}/context_template_args.yaml", "r") as f:
        context_template_args = yaml.safe_load(f)
        service_t_args = context_template_args[service]
        service_t_args["images"] = context_template_args.get(
            "images", default_args["images"]
        )
        service_t_args["admin_creds"] = context_template_args.get(
            "admin_creds", default_args["admin_creds"]
        )
        service_t_args["guest_creds"] = context_template_args.get(
            "guest_creds", default_args["guest_creds"]
        )
        service_t_args["proxy_vars"] = context_template_args.get(
            "proxy_vars", default_args["proxy_vars"]
        )
        service_t_args["network_policies"] = context_template_args.get(
            "network_policies", default_args["network_policies"]
        )

    with open(f"{INPUT_DIR}/{context}/context_spec.yaml", "r") as f:
        spec = yaml.safe_load(f)

    return spec, service_t_args


def get_sizes():
    sizes = [name for name in os.listdir(SIZES_DIR)]
    return sizes


def get_services_and_contexts():
    all_services = (
        set(constants.OS_SERVICES_MAP.keys())
        .union(infra_services)
        .difference(excluded_services)
    )
    params = []
    for service in all_services:
        srv_dir = f"{OUTPUT_DIR}/{service}"
        contexts = [name.split(".")[0] for name in os.listdir(srv_dir)]
        if not contexts:
            raise RuntimeError(f"No contexts provided for service {service}")
        for context in contexts:
            params.append((service, context))
    return params


def get_child_object_templates():
    all_services = (
        set(constants.OS_SERVICES_MAP.keys())
        .union(infra_services)
        .difference(excluded_services)
    )
    all_openstack_versions = set(
        [it.name for it in constants.OpenStackVersion]
    ) - set(["zed", "bobcat", "dalmatian", "master"])
    service_excludes = {
        "shared-file-system": [
            "queens",
            "rocky",
            "stein",
            "train",
            "ussuri",
            "victoria",
            "xena",
            "wallaby",
        ],
        "placement": ["queens", "rocky"],
        "instance-ha": ["queens", "rocky", "stein", "train", "ussuri"],
    }
    res = []
    for service in all_services:
        openstack_versions = all_openstack_versions
        if service in service_excludes:
            openstack_versions = set(all_openstack_versions) - set(
                service_excludes.get(service, [])
            )
        for openstack_version in openstack_versions:
            res.append(
                (
                    service,
                    os.path.join(CHILD_OBJECTS_DIR, f"{service}.yaml"),
                    openstack_version,
                )
            )
    return res


@pytest.mark.parametrize(
    "service,context", sorted(get_services_and_contexts())
)
@mock.patch.object(layers, "_get_dashboard_default_policy")
@mock.patch.object(layers, "_get_default_policy")
def test_render_service_template(
    gdp_mock,
    gddp_mock,
    common_template_args,
    dashboard_policy_default,
    service,
    context,
    child_view,
):
    if service == "dashboard":
        gdp_mock.return_value = {}
        gddp_mock.return_value = dashboard_policy_default
    elif service in infra_services:
        gdp_mock.return_value = {}
    else:
        gdp_mock.return_value = {f"{service}_rule1": f"{service}_value1"}
    logger.info(f"Rendering service {service} for context {context}")
    spec, kwargs = get_render_kwargs(service, context, common_template_args)
    kwargs["service_childs"] = child_view.childs
    data = render_helmbundle(service, spec, **kwargs)
    with open(f"{OUTPUT_DIR}/{service}/{context}.yaml") as f:
        output = yaml.safe_load(f)
        assert data == output, f"Mismatch when comparing to file {f.name}"


@pytest.mark.parametrize("size", sorted(get_sizes()))
def test_render_sezes(size):
    layers.render_template(f"size/{size}")


@pytest.mark.parametrize(
    "service,template,openstack_version", sorted(get_child_object_templates())
)
@mock.patch.object(kube, "artifacts_configmap")
def test_render_child_object_template(
    artifacts_cm,
    service,
    template,
    openstack_version,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
):
    artifacts_cm.return_value = None
    schema = yaml.safe_load(CHILD_OBJECTS_SCHEMA)
    data = layers.render_template(template, spec=openstackdeployment_mspec)
    validate(data, schema)


@pytest.mark.parametrize(
    "service,template,openstack_version", sorted(get_child_object_templates())
)
@mock.patch.object(kube, "artifacts_configmap")
def test_render_child_object_template_ensure_images(
    artifacts_cm,
    service,
    template,
    openstack_version,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
):
    artifacts_cm.return_value = None
    osdpl = copy.deepcopy(openstackdeployment_mspec)
    osdpl["openstack_version"] = openstack_version
    data = layers.render_template(template, spec=osdpl)
    images = layers.render_artifacts(osdpl)
    for chart, kinds in data.items():
        for kind, childs in kinds.items():
            for child_name, child_meta in childs.items():
                for image in child_meta["images"]:
                    assert (
                        image in images.keys()
                    ), f"Image {image} is not present in {openstack_version}/artifacts.yaml"
