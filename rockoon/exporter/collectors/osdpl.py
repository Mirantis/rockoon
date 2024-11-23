#!/usr/bin/env python3
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

from prometheus_client.core import InfoMetricFamily

from rockoon import utils
from rockoon.exporter.collectors import base


LOG = utils.get_logger(__name__)


class OsdplMetricCollector(base.BaseMetricsCollector):
    _name = "osdpl"
    _description = "OpenStack Deployment metrics"

    def init_families(self):
        return {
            "version": InfoMetricFamily(
                f"{self._name}_version",
                "Osdpl version information",
                labels=["osdpl"],
            )
        }

    def update_samples(self):
        self.set_samples(
            "version",
            [
                (
                    [self.osdpl.name],
                    {
                        "openstack_version": self.osdpl.obj["spec"][
                            "openstack_version"
                        ]
                    },
                )
            ],
        )

    @property
    def can_collect_data(self):
        return True
