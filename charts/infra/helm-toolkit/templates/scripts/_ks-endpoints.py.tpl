{{- define "helm-toolkit.scripts.keystone_endpoints" }}
#!/usr/bin/env python

import logging
import os
import sys
import time

import openstack

logging.basicConfig(
    stream=sys.stdout,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOG = logging.getLogger(os.environ["HOSTNAME"])
LOG.setLevel("INFO")

def get_env_var(env_var, default=None):
    if env_var in os.environ:
        return os.environ[env_var]

    if default is not None:
        return default

    LOG.critical(f"environment variable {env_var} not set")
    raise RuntimeError("FATAL")

OS_SERVICE_NAME = get_env_var("OS_SERVICE_NAME")
OS_SERVICE_TYPE = get_env_var("OS_SERVICE_TYPE")
OS_INTERFACE = get_env_var("OS_SVC_ENDPOINT")
OS_SERVICE_ENDPOINT = get_env_var("OS_SERVICE_ENDPOINT")

OS_CLOUD = get_env_var("OS_CLOUD_SYSTEM", "envvars")
CLOUD = openstack.connection.Connection(cloud=OS_CLOUD)
OS_REGION_NAME = CLOUD.identity.region_name
STATE = get_env_var("STATE", "present")

CLOUD_CALL_RETRIES = int(os.getenv("CLOUD_CALL_RETRIES", 200))

def retry_cloud_call(times, interval=3):
    def decorator(func):
        def newfn(*args, **kwargs):
            attempt = 0
            while attempt < times:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    # If http exception with code > 500 or 0 retry
                    if hasattr(e, "http_status") and (
                        e.http_status >= 500 or e.http_status == 0
                    ):
                        attempt += 1
                        LOG.exception(
                            f"Exception thrown when attempting to run {func}, attempt {attempt} of {times}"
                        )
                        time.sleep(interval)
                    else:
                        raise e
            return func(*args, **kwargs)

        return newfn

    return decorator


@retry_cloud_call(CLOUD_CALL_RETRIES)
def get_services(name, s_type):
    return CLOUD.search_services(filters={"name": name, "type": s_type})


@retry_cloud_call(CLOUD_CALL_RETRIES)
def get_service_endpoints(id, region, interface):
    return CLOUD.search_endpoints(
        filters={"service_id": id, "region": region, "interface": interface}
    )


@retry_cloud_call(CLOUD_CALL_RETRIES)
def update_endpoint(id, **kwargs):
    return CLOUD.update_endpoint(id, **kwargs)


@retry_cloud_call(CLOUD_CALL_RETRIES)
def create_endpoint(id, **kwargs):
    return CLOUD.create_endpoint(id, **kwargs)


@retry_cloud_call(CLOUD_CALL_RETRIES)
def delete_endpoint(id):
    return CLOUD.delete_endpoint(id)

services = get_services(OS_SERVICE_NAME, OS_SERVICE_TYPE)

if len(services) > 1:
    raise RuntimeError(
        f"FATAL: Found more than 1 service {OS_SERVICE_NAME} {OS_SERVICE_TYPE}: {services}"
    )

if STATE == "absent" and len(services) == 0:
    LOG.info(f"Service {OS_SERVICE_NAME} is not present, not checking endpoints.")
    sys.exit(0)

# Get Service ID
OS_SERVICE_ID = services[0].id
LOG.info(f"Found service {OS_SERVICE_NAME} {OS_SERVICE_TYPE} with id {OS_SERVICE_ID}")

# Get Endpoint ID if it exists
endpoints = get_service_endpoints(OS_SERVICE_ID, OS_REGION_NAME, OS_INTERFACE)
LOG.info(f"Found endpoint(s) {endpoints}")

if STATE == "absent":
    for endpoint in endpoints:
        deleted = delete_endpoint(endpoint.id)
        LOG.info(f"Deleted endpoint {endpoint.id}")
    sys.exit(0)

# Making sure only a single endpoint exists for a service within a region
if len(endpoints) > 1:
    LOG.info("More than one endpoint found, cleaning up")
    for endpoint in endpoints:
        deleted = delete_endpoint(endpoint.id)
        LOG.info(f"Deleted endpoint {deleted}")
    endpoints = []

endpoint_kwargs = {
    "region": OS_REGION_NAME,
    "interface": OS_INTERFACE,
    "url": OS_SERVICE_ENDPOINT,
}

# Determine if Endpoint needs to be updated
if endpoints:
    current_url = endpoints[0].url
    if current_url == OS_SERVICE_ENDPOINT:
        LOG.info("Endpoints Match: no action required")
    else:
        LOG.info("Endpoints Dont Match: updating existing entries")
        updated = update_endpoint(endpoints[0].id, **endpoint_kwargs)
        LOG.info("Updated existing endpoint to {updated}")
else:
    created = create_endpoint(OS_SERVICE_ID, **endpoint_kwargs)
    LOG.info(f"Created endpoint {created}")
{{- end }}
