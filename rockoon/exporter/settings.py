#    Copyright 2023 Mirantis, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import os

OSCTL_EXPORTER_CERTIFICATES_INFO_FILE = os.getenv(
    "OSCTL_EXPORTER_CERTIFICATES_INFO_FILE",
    "/etc/rockoon/exporter/certs_info.yaml",
)

# List of enabled collectors, when not set all collectors are enabled
OSCTL_EXPORTER_ENABLED_COLLECTORS = os.getenv(
    "OSCTL_EXPORTER_ENABLED_COLLECTORS",
    "osdpl_certificate,osdpl_credentials,osdpl_nova,osdpl_nova_audit,osdpl_ironic,osdpl_keystone,osdpl_heat,osdpl_glance,osdpl_manila,osdpl_cinder,osdpl_neutron,osdpl_octavia,osdpl_api,osdpl_aodh,osdpl_masakari,osdpl,osdpl_horizon",
).split(",")

# Number in seconds we allow for polling, when exceeds exporter is stopped.
# On big clouds with 500+ computes nova may take a while.
OSCTL_EXPORTER_MAX_POLL_TIMEOUT = int(
    os.getenv("OSCTL_EXPORTER_MAX_POLL_TIMEOUT", "900")
)

# Number of seconds we can wait for polling tasks before return cached result
# Should be lower than prometheus scrape_timeout which is 1m by default.
OSCTL_SCRAPE_TIMEOUT = int(os.getenv("OSCTL_SCRAPE_TIMEOUT", "45"))

OSCTL_EXPORTER_CA_CERT_PATH = os.getenv(
    "OSCTL_EXPORTER_CA_CERT_PATH",
    "/usr/local/share/ca-certificates/osdpl/ca.crt",
)

# Number of hours to consider Nova Audit report as up to date,
# if upon that time report is not updated, metric collection
# is considered failed.
OSCTL_EXPORTER_NOVA_AUDIT_TTL = int(
    os.getenv("OSCTL_EXPORTER_NOVA_AUDIT_TTL", "10")
)
