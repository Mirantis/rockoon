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

{{- $envAll := . }}
set -ex

READINESS_FILE=/tmp/ovn_db_configurator_ready

rm -rf $READINESS_FILE

OVS_DB_SOCK="/run/openvswitch/db.sock"
OVN_CONTROLLER_PID="/run/openvswitch/ovn-controller.pid"
OVN_RUNDIR=/run/openvswitch/
HOST=$(hostname -s)

OVNSB_DB_PROTO={{ tuple "ovn_db" "internal" "sb" . | include "helm-toolkit.endpoints.keystone_endpoint_scheme_lookup" }}
OVNSB_DB_HOST={{ tuple "ovn_db" "discovery" . | include "helm-toolkit.endpoints.endpoint_host_lookup" }}
OVNSB_DB_PORT={{ tuple "ovn_db" "internal" "sb" . | include "helm-toolkit.endpoints.endpoint_port_lookup" | quote }}
OVNSB_DB=${OVNSB_DB_PROTO}:${OVNSB_DB_HOST}:${OVNSB_DB_PORT}

OVNNB_DB_PROTO={{ tuple "ovn_db" "internal" "nb" . | include "helm-toolkit.endpoints.keystone_endpoint_scheme_lookup" }}
OVNNB_DB_HOST={{ tuple "ovn_db" "discovery" . | include "helm-toolkit.endpoints.endpoint_host_lookup" }}
OVNNB_DB_PORT={{ tuple "ovn_db" "internal" "nb" . | include "helm-toolkit.endpoints.endpoint_port_lookup" | quote }}
OVNNB_DB=${OVNNB_DB_PROTO}:${OVNNB_DB_HOST}:${OVNNB_DB_PORT}

if [[ "${HOST}" == "openvswitch-ovn-db-0" ]]; then

    while ! ovn-nbctl --db ${OVNNB_DB} --no-leader-only show; do
        echo "OVN NB is not yet ready."
        sleep 5
    done

    while ! ovn-sbctl --db ${OVNSB_DB} --no-leader-only show; do
        echo "OVN SB is not yet ready."
        sleep 5
    done

    {{- range $opt,$val := $envAll.Values.conf.ovn_nb.NB_Global.options }}
    ovn-nbctl --db ${OVNNB_DB} --no-leader-only set NB_Global . options:{{ $opt }}={{ $val }}
    {{- end }}

    {{- range $opt,$val := $envAll.Values.conf.ovn_sb.SB_Global.options }}
    ovn-sbctl --db ${OVNSB_DB} --no-leader-only set SB_Global . options:{{ $opt }}={{ $val }}
    {{- end }}

fi

touch $READINESS_FILE

sleep infinity
