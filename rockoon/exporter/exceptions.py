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


class OpenStackMetricExporter(Exception):
    """A generic OpenStack Metrics Exporter to be inherited from"""


class GatheringDataSkipped(OpenStackMetricExporter):
    def __init__(self, collector_name, message=None):
        super().__init__()
        if message is None:
            message = f"Skip gathering data for {collector_name}"
        self.message = message
