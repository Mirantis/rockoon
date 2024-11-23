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

from rockoon.osctl.plugins.sosreport import base
from rockoon.osctl.plugins.sosreport.elastic import (
    ElasticLogsCollector,
)
from rockoon.osctl.plugins.sosreport.k8s import (
    K8sObjectsCollector,
)
from rockoon.osctl.plugins.sosreport.nova import (
    NovaObjectsCollector,
)
from rockoon.osctl.plugins.sosreport.neutron import (
    NeutronObjectsCollector,
)
from rockoon.osctl.plugins.sosreport.cinder import (
    CinderObjectsCollector,
)


__all__ = (
    ElasticLogsCollector,
    K8sObjectsCollector,
    NovaObjectsCollector,
    NeutronObjectsCollector,
    CinderObjectsCollector,
)

registry = base.BaseLogsCollector.registry
