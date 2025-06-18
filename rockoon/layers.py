import base64
import copy
import json
import functools
import hashlib

import deepmerge
import deepmerge.exception
import deepmerge.strategy.type_conflict
import jinja2
import kopf
import yaml

from rockoon import constants
from rockoon import settings
from rockoon.filters.tempest import generate_tempest_config
from rockoon.filters.common_filters import (
    substitute_local_proxy_hostname,
    raise_error,
    namespaces,
)
from rockoon import utils
from rockoon import kube
from rockoon import secrets
from rockoon.utils import merger

LOG = utils.get_logger(__name__)


ENV = jinja2.Environment(
    loader=jinja2.PackageLoader(__name__.split(".")[0]),
    extensions=["jinja2.ext.do", "jinja2.ext.loopcontrols"],
)
LOG.debug(f"found templates {ENV.list_templates()}")

ENV.filters["generate_tempest_config"] = generate_tempest_config
ENV.filters["substitute_local_proxy_hostname"] = (
    substitute_local_proxy_hostname
)
ENV.filters["namespaces"] = namespaces
ENV.globals["raise_error"] = raise_error
ENV.filters["b64encode"] = base64.b64encode
ENV.filters["toyaml"] = yaml.dump
ENV.filters["decode"] = lambda x: x.decode()
ENV.filters["encode"] = lambda x: x.encode()
ENV.globals["OSVer"] = constants.OpenStackVersion


def kopf_exception(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (kopf.TemporaryError, kopf.PermanentError):
            raise
        except deepmerge.exception.InvalidMerge as e:
            raise kopf.PermanentError(f"DeepMerge Error: {e}") from e
        except yaml.YAMLError as e:
            raise kopf.PermanentError(f"YAML error: {e}") from e
        except jinja2.TemplateNotFound as e:
            raise kopf.PermanentError(
                f"Template {e.name} (loaded from file {e.filename}) "
                f"was not found: {e}"
            ) from e
        except jinja2.TemplateSyntaxError as e:
            raise kopf.PermanentError(
                f"Template {e.name} (loaded from {e.filename}) "
                f"has syntax error at lineno {e.lineno}: {e.message}"
            ) from e
        except jinja2.UndefinedError as e:
            raise kopf.TemporaryError(
                f"Template for tried to operate on undefined: " f"{e.message}"
            ) from e
        except Exception as e:
            raise kopf.TemporaryError(f"{e}") from e

    return wrapper


def spec_hash(spec):
    """Generate stable hash of body.spec structure

    as these are objects received from k8s API it is presumed
    that this object is already JSON-serializable w/o any need
    for additional conversions
    """
    hasher = hashlib.sha256()
    hasher.update(json.dumps(spec, sort_keys=True).encode())
    return hasher.hexdigest()


# TODO(avolkov): remove  logger arg
def services(mspec, logger, **kwargs):
    to_apply = set(mspec["features"].get("services", []))
    LOG.debug(f"Working with openstack services: {to_apply}")

    to_delete = {}
    # NOTE(pas-ha) each diff is (op, (path, parts, ...), old, new)
    # kopf ignores changes to status except its own internal fields
    # and metadata except labels and annotations
    # (kind and apiVersion and namespace are de-facto immutable)
    for op, path, old, new in kwargs.get("diff", []):
        LOG.debug(f"{op} {'.'.join(path)} from {old} to {new}")
        if path == ("spec", "features", "services"):
            # NOTE(pas-ha) something changed in services,
            # need to check if any were deleted
            to_delete = set(old or []) - set(new or [])
    return to_apply, to_delete


def _get_default_policy(spec, chart):
    openstack_version = spec["openstack_version"]
    template_path = f"{openstack_version}/policies/{chart}.yaml"
    return (
        yaml.safe_load(
            ENV.get_template(template_path).render(
                spec=spec,
            )
        )
        or {}
    )


def _get_dashboard_default_policy(spec, charts):
    return dict((chart, _get_default_policy(spec, chart)) for chart in charts)


@kopf_exception
def render_template(template, **template_args):
    tpl = ENV.get_template(template)
    text = tpl.render(
        **template_args,
    )
    data = yaml.safe_load(text)
    return data


def get_child_tree(mspec):
    res = {}
    for template in ENV.loader.list_templates():
        if not template.startswith("child_objects"):
            continue
        name = template.split("/")[-1].split(".")[0]
        res[name] = render_template(template, spec=mspec)
    return res


@kopf_exception
def render_service_template(service, mspec, logger, **template_args):
    tpl = ENV.get_template(f"services/{service}.yaml")
    LOG.debug(f"Using template {tpl.filename}")

    # get supported openstack versions
    openstack_versions = [v for v in constants.OpenStackVersion.__members__]
    # get supported SLURP releases
    slurp_releases = constants.SLURP_RELEASES
    service_policy = {}
    # Add default policies
    if service in constants.OS_POLICY_SERVICES:
        chart = constants.OS_POLICY_SERVICES[service]
        service_policy = _get_default_policy(mspec, chart)
    elif service == "dashboard":
        os_services = set(mspec.get("features", {}).get("services", []))
        charts = set(constants.OS_POLICY_SERVICES.values()).intersection(
            os_services
        )
        service_policy = _get_dashboard_default_policy(mspec, charts)

    pod_networks = settings.OSCTL_POD_NETWORKS_DATA

    text = tpl.render(
        spec=mspec,
        openstack_versions=openstack_versions,
        service_policy=service_policy,
        slurp_releases=slurp_releases,
        pod_networks=pod_networks,
        **template_args,
    )
    data = yaml.safe_load(text)
    # NOTE(vsaienko): for case when deploy_main_service is set to false
    if "releases" in data["spec"] and not data["spec"]["releases"]:
        data["spec"]["releases"] = []
    return data


def merge_osdpl_into_helmbundle(service, spec, service_helmbundle):
    # let's make sure no deeply located dict are linked during the merge
    # we don't modify input params and return a completely new dict
    spec = copy.deepcopy(spec)
    service_helmbundle = copy.deepcopy(service_helmbundle)

    # We have 4 level of hierarchy, in increasing priority order:
    # 1. helm values.yaml - which is default
    # 2. rockoon/templates/services/<helmbundle>.yaml
    # 3. OpenstackDeployment or preset charts section
    # 4. OpenstackDeployment or preset common/group section

    # The values are merged in this specific order.
    for release in service_helmbundle["spec"]["releases"]:
        chart_name = release["chart"]
        merger.merge(
            release,
            spec.get("common", {}).get("charts", {}).get("releases", {}),
        )
        for group, charts in constants.CHART_GROUP_MAPPING.items():
            if chart_name in charts:
                common_releases = (
                    spec.get("common", {}).get(group, {}).get("releases", {})
                )
                if chart_name in common_releases:
                    merger.merge(release, common_releases[chart_name])
                else:
                    merger.merge(release, common_releases)

                merger.merge(
                    release["values"],
                    spec.get("common", {}).get(group, {}).get("values", {}),
                )

        merger.merge(
            release["values"],
            spec.get("services", {})
            .get(service, {})
            .get(chart_name, {})
            .get("values", {}),
        )

        # Merge nodes settings
        chart_normalized_override = {}
        for label_tag, override in spec.get("nodes", {}).items():
            daemonset_override = (
                override.get("services", {})
                .get(service, {})
                .get(chart_name, {})
            )
            if daemonset_override:
                for daemonset_name, override in daemonset_override.items():
                    if daemonset_name not in chart_normalized_override:
                        chart_normalized_override[daemonset_name] = {}
                    merger.merge(
                        chart_normalized_override[daemonset_name],
                        {"labels": {label_tag: override}},
                    )

        if chart_normalized_override:
            LOG.debug(
                f"Applying node specific override for {service}:{chart_name}"
            )
            merger.merge(
                release["values"], {"overrides": chart_normalized_override}
            )

    return service_helmbundle


def merge_service_layer(service, spec, kind, data):
    merger.merge(
        data["spec"],
        spec.get("services", {}).get(service, {}).get(kind, {}),
    )

    return data


@kopf_exception
def merge_all_layers(service, mspec, logger, **template_args):
    """Merge releases and values from osdpl crd into service HelmBundle"""

    mspec = copy.deepcopy(dict(mspec))
    images = render_artifacts(mspec)
    service_helmbundle = render_service_template(
        service, mspec, logger, images=images, **template_args
    )

    # and than an "original" osdpl on top of that
    service_helmbundle = merge_osdpl_into_helmbundle(
        service, mspec, service_helmbundle
    )
    return service_helmbundle


@kopf_exception
def merge_spec(spec, logger):
    """Merge user-defined OsDpl spec with base for preset and OS version

    The merging is done in following order, higher overrides. It is important
    to keep the order to ensure user defined data takes higher precedence.
    1. Preset
    2. Size
    3. User defined osdpl spec.

    """
    spec = copy.deepcopy(dict(spec))
    preset = spec["preset"]
    size = spec["size"]
    os_release = spec["openstack_version"]
    LOG.debug(f"Using preset {preset}")
    LOG.debug(f"Using size {size}")

    base = yaml.safe_load(
        ENV.get_template(f"preset/{preset}.yaml").render(
            openstack_version=os_release,
            openstack_namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
            services=spec.get("features", {}).get("services", []),
            signature_enabled=spec.get("features", {})
            .get("glance", {})
            .get("signature", {})
            .get("enabled", False),
            ironic_mt_enabled=spec.get("features", {})
            .get("ironic", {})
            .get("networks", {})
            .get("baremetal", {})
            .get("network_type")
            in ["vlan", "geneve", "vxlan"],
            ovn_enabled=spec.get("features", {})
            .get("neutron", {})
            .get("backend", "ml2")
            == "ml2/ovn",
            nova_img_encrypt_enabled=spec.get("features", {})
            .get("nova", {})
            .get("images", {})
            .get("encryption", {}),
            neutron_dvr_enabled=spec.get("features", {})
            .get("neutron", {})
            .get("dvr", {})
            .get("enabled", False),
        )
    )
    # Order for artifacts base urls overrides:
    # 1. Url from controller settings
    # 2. Url from Osdpl spec
    base["artifacts"] = {
        "binary_base_url": settings.OSCTL_BINARY_BASE_URL,
        "images_base_url": settings.OSCTL_IMAGES_BASE_URL,
    }
    sizing = yaml.safe_load(ENV.get_template(f"size/{size}.yaml").render())
    merger.merge(base, sizing)

    # Merge IAM data defined via values, the user defined via spec
    # still have priority
    if settings.OSDPL_IAM_DATA["enabled"]:
        validate_server_opts = (
            {"oidcCASecret": settings.OSDPL_IAM_DATA["oidcCASecret"]}
            if "oidcCASecret" in settings.OSDPL_IAM_DATA
            else {
                "OIDCSSLValidateServer": False,
                "OIDCOAuthSSLValidateServer": False,
            }
        )
        iam_features = {
            "features": {
                "keystone": {
                    "keycloak": {
                        "enabled": True,
                        "url": settings.OSDPL_IAM_DATA["url"],
                        "oidc": {
                            "OIDCClientID": settings.OSDPL_IAM_DATA["client"],
                            **validate_server_opts,
                        },
                    }
                }
            }
        }
        merger.merge(base, iam_features)

    # Merge operator defaults with user context.
    return merger.merge(base, spec)


def update_ca_bundles(spec):
    ca_bundles = [
        spec["features"]["ssl"]["public_endpoints"]["ca_cert"].strip()
    ]
    # Add extra proxy CA bundle to mspec
    if settings.OSCTL_PROXY_DATA["enabled"]:
        proxy_secret = secrets.ProxySecret()
        proxy_ca = proxy_secret.get_proxy_certs()
        if proxy_ca:
            ca_bundles.append(proxy_ca)

    if settings.OSCTL_CDN_CA_BUNDLE_DATA.get("caBundleSecret"):
        cdn_secret = secrets.CdnCaBundleSecret()
        cdn_ca = cdn_secret.get_cdn_ca_bundle()
        if cdn_ca:
            ca_bundles.append(cdn_ca)

    spec["features"]["ssl"]["public_endpoints"]["ca_cert"] = "\n".join(
        ca_bundles
    )


def render_cache_template(mspec, name, images, node_selector):
    artifacts = render_artifacts(mspec)
    tpl = ENV.get_template("native/cache.yaml")
    text = tpl.render(
        images=images,
        name=name,
        pause_image=artifacts["pause"],
        node_selector=node_selector,
    )
    return yaml.safe_load(text)


def render_cache_images(role):
    return yaml.safe_load(
        ENV.get_template(f"native/cache_images_{role}.yaml").render()
    )


def render_artifacts(spec):
    os_release = spec["openstack_version"]
    # values from preset were earlier merged to spec.
    images_base_url = spec["artifacts"]["images_base_url"]
    binary_base_url = spec["artifacts"]["binary_base_url"]

    artifacts = yaml.safe_load(
        ENV.get_template(f"{os_release}/artifacts.yaml").render(
            images_base_url=images_base_url, binary_base_url=binary_base_url
        )
    )
    osdpl = kube.get_osdpl()
    artifacts_cm = kube.artifacts_configmap(osdpl.obj["metadata"]["name"])
    if artifacts_cm:
        LOG.info("Applying artifact overrides from %s", artifacts_cm.name)
        custom_artifacts = (
            yaml.safe_load(artifacts_cm.obj["data"].get(os_release, "")) or {}
        )
        merger.merge(artifacts, custom_artifacts)
    return artifacts


def substitude_osdpl(obj):
    subs_secrets = {
        s.name: s.obj.get("data", {})
        for s in kube.resource_list(
            kube.Secret,
            selector=f"{constants.OSCTL_SECRET_LABEL[0]}={constants.OSCTL_SECRET_LABEL[1]}",
            namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
        )
    }
    return utils.find_and_substitute(obj, subs_secrets)
