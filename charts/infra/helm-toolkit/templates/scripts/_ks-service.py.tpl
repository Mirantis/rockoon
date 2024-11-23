{{- define "helm-toolkit.scripts.keystone_service" }}
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

CLOUD_CALL_RETRIES = int(os.getenv("CLOUD_CALL_RETRIES", 200))


def get_env_var(env_var, default=None):
    if env_var in os.environ:
        return os.environ[env_var]

    if default is not None:
        return default

    LOG.critical(f"environment variable {env_var} not set")
    raise RuntimeError("FATAL")

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
def delete_service(s_id):
    LOG.info(f"Removing service {s_id}")
    return CLOUD.delete_service(s_id)


@retry_cloud_call(CLOUD_CALL_RETRIES)
def create_service(name, s_type, s_desc):
    LOG.info(f"Creating service {name} {s_type}")
    return CLOUD.create_service(name, type=s_type, description=s_desc)

OS_CLOUD = get_env_var("OS_CLOUD_SYSTEM", "envvars")
CLOUD = openstack.connection.Connection(cloud=OS_CLOUD)

OS_SERVICE_NAME = get_env_var("OS_SERVICE_NAME")
OS_SERVICE_TYPE = get_env_var("OS_SERVICE_TYPE")
OS_REGION_NAME = CLOUD.identity.region_name
STATE = get_env_var("STATE", "present")

OS_SERVICE_DESC = f"{OS_REGION_NAME}: {OS_SERVICE_NAME} ({OS_SERVICE_TYPE}) service"

services = get_services(OS_SERVICE_NAME, OS_SERVICE_TYPE)

if STATE == "absent":
    for service in services:
        delete_service(service.id)
        LOG.info(f"Removed service {service.id}")
    sys.exit(0)

if len(services) > 1:
    LOG.info(
        f"Found more than 1 service {OS_SERVICE_NAME} {OS_SERVICE_TYPE}, cleanup needed"
    )
    for service in services[1:]:
        delete_service(service.id)
elif not services:
    service = create_service(OS_SERVICE_NAME, OS_SERVICE_TYPE, OS_SERVICE_DESC)
    LOG.info(f"Created service {service.name} {service.id}")
else:
    LOG.info(f"Service {OS_SERVICE_NAME} {OS_SERVICE_TYPE} already present")
{{- end }}
