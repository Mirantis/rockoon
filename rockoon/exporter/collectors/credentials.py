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

from datetime import datetime
from prometheus_client.core import GaugeMetricFamily

from rockoon import utils
from rockoon.osdplstatus import OpenStackDeploymentStatus
from rockoon.exporter.collectors import base

LOG = utils.get_logger(__name__)


class OsdplCredentialsMetricCollector(base.BaseMetricsCollector):
    _name = "osdpl_credentials"
    _description = "Info about OpenStack credentials"

    def init_families(self):
        return {
            "rotation_timestamp": GaugeMetricFamily(
                f"{self._name}_rotation_timestamp",
                f"{self._description}: rotation unix timestamp",
                labels=["type"],
            )
        }

    def update_samples(self):
        credentials_samples = []
        osdplst = OpenStackDeploymentStatus(
            self.osdpl.name, self.osdpl.namespace
        )
        for _type in ["admin", "service"]:
            ts = osdplst.get_credentials_rotation_status(_type).get(
                "timestamp"
            )
            if not ts:
                LOG.warning(
                    f"Rotation timestamp for {_type} credentials not found."
                )
                continue
            credentials_samples.append(
                (
                    [_type],
                    datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f").timestamp(),
                )
            )
        self.set_samples("rotation_timestamp", credentials_samples)

    @property
    def can_collect_data(self):
        return True
