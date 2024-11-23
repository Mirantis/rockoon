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

import keystoneauth1

from rockoon import utils
from rockoon.exporter.collectors import base
from rockoon import openstack_utils


LOG = utils.get_logger(__name__)


class OpenStackBaseMetricCollector(base.BaseMetricsCollector):
    # Service type to check for presence is catalog
    _os_service_types = []

    def __init__(self):
        super().__init__()
        self._oc = None

    @property
    def oc(self):
        # NOTE(vsaienko): if we got any exception during  update_samples
        # re initialize oc in this case.
        if not self.scrape_success or self._oc is None:
            try:
                self._oc = openstack_utils.OpenStackClientManager()
            except Exception as e:
                LOG.warning("Failed to initialize openstack client manager")
                LOG.exception(e)
        return self._oc

    @property
    def is_service_available(self):
        for service_type in self._os_service_types:
            try:
                for svc in self.oc.oc.identity.services(type=service_type):
                    return True
            except keystoneauth1.exceptions.http.Unauthorized:
                # NOTE(vsaienko): reset client and let it reinitiate on next run.
                self._oc = None
                raise
        LOG.info(f"Service not found for types {self._os_service_types}")
        return False

    @property
    def can_collect_data(self):
        if self.oc is None:
            return False
        if not self.is_service_available:
            return False
        return True
