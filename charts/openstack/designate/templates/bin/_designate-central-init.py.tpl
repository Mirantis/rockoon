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

import logging
import openstack
import os
import sys
from retry import retry

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger(__name__)


@retry(openstack.exceptions.SDKException, delay=1, tries=7, backoff=2, logger=LOG)
def get_project_id(project_name, domain_name):
    LOG.info(f"Getting project id of {domain_name}/{project_name} ...")
    domain_id = ost.identity.find_domain(domain_name)["id"]
    project_id = ost.identity.find_project(project_name, domain_id=domain_id)["id"]
    LOG.info("  Done [%s=%s]", project_name, project_id)
    return project_id


SERVICE_PROJECT_NAME = os.environ.get("SERVICE_PROJECT_NAME")
SERVICE_DOMAIN_NAME = os.environ.get("SERVICE_DOMAIN_NAME")
DESIGNATE_CENTRAL_CONF = "/tmp/pod-shared/designate-central.conf"

ost = openstack.connect()
service_project_id = get_project_id(SERVICE_PROJECT_NAME, SERVICE_DOMAIN_NAME)
with open(DESIGNATE_CENTRAL_CONF, "w") as conf:
    conf.write(
        f"[service:central]\nmanaged_resource_tenant_id = {service_project_id}\n"
    )
