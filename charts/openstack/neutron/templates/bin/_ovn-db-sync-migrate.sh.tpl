#!/bin/bash

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

set -ex

ovn_db_host={{ tuple "ovn_db" "internal" . | include "helm-toolkit.endpoints.endpoint_host_lookup" }}
ovn_db_ip=$(dig ${ovn_db_host} +short)
ovn_db_proto={{ tuple "ovn_db" "internal" "sb" . | include "helm-toolkit.endpoints.keystone_endpoint_scheme_lookup" }}
ovn_db_nb_port={{ tuple "ovn_db" "internal" "nb" . | include "helm-toolkit.endpoints.endpoint_port_lookup" | quote }}
ovn_db_sb_port={{ tuple "ovn_db" "internal" "sb" . | include "helm-toolkit.endpoints.endpoint_port_lookup" | quote }}

neutron-ovn-db-sync-util --ovn-ovn_nb_connection=${ovn_db_proto}:${ovn_db_ip}:${ovn_db_nb_port} \
                         --ovn-ovn_sb_connection=${ovn_db_proto}:${ovn_db_ip}:${ovn_db_sb_port} \
                         --config-file /etc/neutron/neutron.conf \
                         --config-file /etc/neutron/plugins/ml2/ml2_conf.ini \
                         --ovn-neutron_sync_mode migrate
