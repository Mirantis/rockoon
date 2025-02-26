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

from rockoon.exporter.collectors import base
from rockoon.exporter.collectors.base import OsdplMetricsCollector

from rockoon.exporter.collectors.certificates import (
    OsdplCertsMetricCollector,
)
from rockoon.exporter.collectors.credentials import (
    OsdplCredentialsMetricCollector,
)
from rockoon.exporter.collectors.openstack.nova import (
    OsdplNovaMetricCollector,
)
from rockoon.exporter.collectors.openstack.nova_audit import (
    OsdplNovaAuditMetricCollector,
)
from rockoon.exporter.collectors.openstack.ironic import (
    OsdplIronicMetricCollector,
)
from rockoon.exporter.collectors.openstack.heat import (
    OsdplHeatMetricCollector,
)
from rockoon.exporter.collectors.openstack.keystone import (
    OsdplKeystoneMetricCollector,
)
from rockoon.exporter.collectors.openstack.glance import (
    OsdplGlanceMetricCollector,
)
from rockoon.exporter.collectors.openstack.cinder import (
    OsdplCinderMetricCollector,
)
from rockoon.exporter.collectors.openstack.neutron import (
    OsdplNeutronMetricCollector,
)
from rockoon.exporter.collectors.openstack.octavia import (
    OsdplOctaviaMetricCollector,
)
from rockoon.exporter.collectors.openstack.aodh import (
    OsdplAodhMetricCollector,
)
from rockoon.exporter.collectors.openstack.api import (
    OsdplApiMetricCollector,
)
from rockoon.exporter.collectors.openstack.manila import (
    OsdplManilaMetricCollector,
)

from rockoon.exporter.collectors.osdpl import (
    OsdplMetricCollector,
)
from rockoon.exporter.collectors.openstack.masakari import (
    OsdplMasakariMetricCollector,
)

from rockoon.exporter.collectors.openstack.horizon import (
    OsdplHorizonMetricCollector,
)

__all__ = (
    OsdplMetricsCollector,
    OsdplCertsMetricCollector,
    OsdplCredentialsMetricCollector,
    OsdplNovaMetricCollector,
    OsdplNovaAuditMetricCollector,
    OsdplIronicMetricCollector,
    OsdplMetricCollector,
    OsdplHeatMetricCollector,
    OsdplKeystoneMetricCollector,
    OsdplGlanceMetricCollector,
    OsdplCinderMetricCollector,
    OsdplNeutronMetricCollector,
    OsdplOctaviaMetricCollector,
    OsdplAodhMetricCollector,
    OsdplApiMetricCollector,
    OsdplManilaMetricCollector,
    OsdplMasakariMetricCollector,
    OsdplHorizonMetricCollector,
)

registry = base.BaseMetricsCollector.registry
