#!/usr/bin/env python

import logging
import os
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
INTERNAL_DEFAULT_VOLUME_TYPE_NAME = '__DEFAULT__'

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


osc = openstack.connection.Connection(cloud=os.getenv("OS_CLOUD", "envvars"))


@retry_cloud_call(CLOUD_CALL_RETRIES)
def get_interna_default_volume_type():
    res = [x for x in osc.volume.types() if x.name == INTERNAL_DEFAULT_VOLUME_TYPE_NAME]
    if res:
        return res[0]

@retry_cloud_call(CLOUD_CALL_RETRIES)
def get_default_volume_type():
    res = osc.volume.get(url='/types/default')
    data = res.json()
    if 'volume_type' in data:
        return data['volume_type']


@retry_cloud_call(CLOUD_CALL_RETRIES)
def check_volumes_with_internal_default():
    res = [x for x in osc.volume.volumes(all_projects=True) if x.volume_type == INTERNAL_DEFAULT_VOLUME_TYPE_NAME]
    if res:
        LOG.error(f"The volumes with {INTERNAL_DEFAULT_VOLUME_TYPE_NAME} type exists: {[x.name for x in res]}")
        return True
    return False


internal_default_type = get_interna_default_volume_type()
default_volume_type = get_default_volume_type()

LOG.info(f"Checking if {INTERNAL_DEFAULT_VOLUME_TYPE_NAME} volume type exists.")
if internal_default_type:
    LOG.info(f"The {INTERNAL_DEFAULT_VOLUME_TYPE_NAME} volume type exists.")
    LOG.info(f"Checking if volumes with {INTERNAL_DEFAULT_VOLUME_TYPE_NAME} type exists...")
    if check_volumes_with_internal_default():
        LOG.error(f"Can't remove {INTERNAL_DEFAULT_VOLUME_TYPE_NAME} volume type as volumes with this type exists.")
        sys.exit(0)
    if default_volume_type and default_volume_type['name'] != internal_default_type.name:
        LOG.info(f"The default volume type exists: {default_volume_type['name']}")
        LOG.info(f"Removing {INTERNAL_DEFAULT_VOLUME_TYPE_NAME} volume type.")
        osc.volume.delete_type(internal_default_type)
else:
    LOG.info(f"The {INTERNAL_DEFAULT_VOLUME_TYPE_NAME} volume type does not exists.")
