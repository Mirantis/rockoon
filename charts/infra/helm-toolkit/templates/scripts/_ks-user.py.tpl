{{- define "helm-toolkit.scripts.keystone_user" }}
#!/usr/bin/env python

import logging
import os
import random
import sys
import time

import keystoneauth1
import openstack

logging.basicConfig(
    stream=sys.stdout,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOG = logging.getLogger(os.environ["HOSTNAME"])
LOG.setLevel("INFO")

CLOUD_CALL_RETRIES = int(os.getenv("CLOUD_CALL_RETRIES", 200))
RANDOM_MAX_BACKOFF = int(os.getenv("RANDOM_MAX_BACKOFF", 60))


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


def log_info(func):
    def wrapper(*args, **kwargs):
        LOG.info("Applying %s: %s ...", args[1].__name__, args[2]["name"])
        result = func(*args, **kwargs)
        LOG.info("  Done [%s=%s]", result.name, result.id)
        return result

    return wrapper


SERVICE_OS_PROJECT_DOMAIN_NAME = get_env_var("SERVICE_OS_PROJECT_DOMAIN_NAME")
SERVICE_OS_USER_DOMAIN_NAME = get_env_var("SERVICE_OS_USER_DOMAIN_NAME")
SERVICE_OS_REGION_NAME = get_env_var("SERVICE_OS_REGION_NAME")
SERVICE_OS_USER_DOMAIN_NAME = get_env_var("SERVICE_OS_USER_DOMAIN_NAME")

SERVICE_OS_PROJECT_NAME = get_env_var("SERVICE_OS_PROJECT_NAME")
SERVICE_OS_SERVICE_NAME = get_env_var("SERVICE_OS_SERVICE_NAME")
SERVICE_OS_USERNAME = get_env_var("SERVICE_OS_USERNAME")
SERVICE_OS_PASSWORD = get_env_var("SERVICE_OS_PASSWORD")

SERVICE_OS_ROLES = get_env_var("SERVICE_OS_ROLES")
MEMBER_OS_ROLE = get_env_var("MEMBER_OS_ROLE", "member")

OS_CLOUD = get_env_var("OS_CLOUD_SYSTEM", "envvars")
osc = openstack.connection.Connection(cloud=OS_CLOUD)


@log_info
@retry_cloud_call(CLOUD_CALL_RETRIES)
def ensure_openstack_resource(find, create, attrs, filter_attrs=None):
    filter_attrs = filter_attrs or {}
    return find(attrs["name"], **filter_attrs) or create(**attrs)


@retry_cloud_call(CLOUD_CALL_RETRIES)
def find_user(name, domain_id):
    res = [
        x for x in osc.list_users(domain_id=domain_id) if x.name == SERVICE_OS_USERNAME
    ]
    if res:
        return res[0]

backoff = random.randrange(0, RANDOM_MAX_BACKOFF)
LOG.info(f"Sleeping for {backoff} seconds.")
time.sleep(backoff)

# Project domain
project_domain_def = {
    "name": SERVICE_OS_PROJECT_DOMAIN_NAME,
    "description": f"Domain for ${SERVICE_OS_REGION_NAME}/${SERVICE_OS_PROJECT_DOMAIN_NAME}",
}

project_domain = ensure_openstack_resource(
    osc.identity.find_domain, osc.identity.create_domain, project_domain_def
)

user_domain_def = {
    "name": SERVICE_OS_USER_DOMAIN_NAME,
    "description": f"Domain for ${SERVICE_OS_REGION_NAME}/${SERVICE_OS_USER_DOMAIN_NAME}",
}

user_domain = ensure_openstack_resource(
    osc.identity.find_domain, osc.identity.create_domain, user_domain_def
)

user_project_def = {
    "name": SERVICE_OS_PROJECT_NAME,
    "description": f"Service User for ${SERVICE_OS_REGION_NAME}/${SERVICE_OS_USER_DOMAIN_NAME}/${SERVICE_OS_SERVICE_NAME}",
    "domain_id": user_domain.id,
}
user_project = ensure_openstack_resource(
    osc.identity.find_project, osc.identity.create_project, user_project_def,
    filter_attrs={"domain_id": user_domain.id}
)


user_def = {
    "name": SERVICE_OS_USERNAME,
    "description": f"Service User for ${SERVICE_OS_REGION_NAME}/${SERVICE_OS_USER_DOMAIN_NAME}/${SERVICE_OS_SERVICE_NAME}",
    "domain_id": user_domain.id,
    "default_project_id": user_project.id,
}


LOG.info("Applying create_user ...")
user = find_user(
    user_def["name"], domain_id=user_def["domain_id"]
) or osc.identity.create_user(**user_def)

user_auth = {
    "auth_url": osc.auth["auth_url"],
    "username": user_def["name"],
    "password": SERVICE_OS_PASSWORD,
    "project_id": user_def["default_project_id"],
    "user_domain_id": user_def["domain_id"],
}

user_conn = openstack.connection.Connection(
    region_name=SERVICE_OS_REGION_NAME, auth=user_auth,
    interface='internal'
)
try:
    user_conn.identity.get_token()
except keystoneauth1.exceptions.http.Unauthorized:
    LOG.info(f"  Setting user {user_def['name']} password")
    osc.identity.update_user(user, password=SERVICE_OS_PASSWORD)
LOG.info(f"  Done [user={user.id}]")

for service_role in set(SERVICE_OS_ROLES.split(",") + [MEMBER_OS_ROLE]):
    role_def = {
        "name": service_role,
    }
    role = ensure_openstack_resource(
        osc.identity.find_role, osc.identity.create_role, role_def
    )
    osc.identity.assign_project_role_to_user(user_project, user, role)
{{ end }}
