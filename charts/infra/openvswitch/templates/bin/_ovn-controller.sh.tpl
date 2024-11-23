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
COMMAND="${@:-start}"

OVS_DB_SOCK="/run/openvswitch/db.sock"
OVN_CONTROLLER_PID="/run/openvswitch/ovn-controller.pid"
OVN_RUNDIR=/run/openvswitch/

function start () {

  SYSTEM_ID=$(uuidgen)
  if [[ -f /var/lib/ovn/system-id.conf ]]; then
    SYSTEM_ID=$(cat /var/lib/ovn/system-id.conf)
  else
    echo ${SYSTEM_ID} > /var/lib/ovn/system-id.conf
  fi

  tunnel_interface={{ .Values.network.interface.tunnel }}
  if [[ -z $tunnel_interface ]]; then
    tunnel_interface=$(ip route show |grep default | awk '{print $5}')
  fi

  tunnel_ip_addr=$(ip -4 -o addr s "${tunnel_interface}" | awk '{ print $4; exit }' | awk -F '/' '{print $1}')
  OVNSB_DB_PROTO={{ tuple "ovn_db" "internal" "sb" . | include "helm-toolkit.endpoints.keystone_endpoint_scheme_lookup" }}
  OVNSB_DB_HOST={{ tuple "ovn_db" "internal" . | include "helm-toolkit.endpoints.endpoint_host_lookup" }}
  OVNSB_DB_PORT={{ tuple "ovn_db" "internal" "sb" . | include "helm-toolkit.endpoints.endpoint_port_lookup" | quote }}

  ovs-vsctl --db=unix:${OVS_DB_SOCK} --no-wait set Open_vSwitch . external-ids:ovn-remote=${OVNSB_DB_PROTO}:${OVNSB_DB_HOST}:${OVNSB_DB_PORT}
  ovs-vsctl --db=unix:${OVS_DB_SOCK} --no-wait set Open_vSwitch . external-ids:ovn-encap-ip=${tunnel_ip_addr}
  ovs-vsctl --db=unix:${OVS_DB_SOCK} --no-wait set Open_vSwitch . external-ids:system-id="$SYSTEM_ID"

  {{- range $option, $value := index .Values.conf "external-ids" }}
    {{- if $value }}
  ovs-vsctl --db=unix:${OVS_DB_SOCK} --no-wait set Open_vSwitch . external-ids:{{ $option }}={{ $value }}
    {{- end }}
  {{- end }}

  # in case ovn-bridge-mappings-back is found then there is migration in progress
  # so need to override original bridge mappings before controller start
  OVN_BRIDGE_MAPPINGS_BACKUP=$(ovs-vsctl  --db=unix:${OVS_DB_SOCK} --no-wait get Open_vSwitch . external_ids:ovn-bridge-mappings-back | sed 's/\"//g')
  if [[ -n $OVN_BRIDGE_MAPPINGS_BACKUP ]]; then
    echo "Found config for migration, overriding migration bridge"
    echo "Setting ovn bridge to br-migration"
    ovs-vsctl --db=unix:${OVS_DB_SOCK} --no-wait set Open_Vswitch . external-ids:ovn-bridge=br-migration

    echo "Overriding migration bridge mapping and creating temporary bridges"
    MIGRATION_BRIDGE_MAPPINGS=''
    for bm in ${OVN_BRIDGE_MAPPINGS_BACKUP//,/ }; do
        net=$(echo $bm | cut -d: -f1)
        bridge=$(echo $bm | cut -d: -f2)
        migration_br="migbr-${bridge}"
        migration_mapping="${net}:${migration_br}"
        if [[ -z ${MIGRATION_BRIDGE_MAPPINGS} ]]; then
            MIGRATION_BRIDGE_MAPPINGS="${migration_mapping}"
        else
            MIGRATION_BRIDGE_MAPPINGS="${MIGRATION_BRIDGE_MAPPINGS},${migration_mapping}"
        fi
        ovs-vsctl --db=unix:${OVS_DB_SOCK} --no-wait --may-exist add-br $migration_br
    done
    echo "Changing original bridge mappings ${OVN_BRIDGE_MAPPINGS_BACKUP} to ${MIGRATION_BRIDGE_MAPPINGS}"
    ovs-vsctl --db=unix:${OVS_DB_SOCK} --no-wait set Open_Vswitch . external-ids:ovn-bridge-mappings="${MIGRATION_BRIDGE_MAPPINGS}"
  fi

  exec /usr/bin/ovn-controller unix:${OVS_DB_SOCK} \
      -vconsole:emer \
      -vconsole:err \
      -vconsole:info \
      --pidfile=${OVN_CONTROLLER_PID}
}

function stop () {
  PID=$(cat $OVN_CONTROLLER_PID)
  rm -rf $OVN_CONTROLLER_PID
  kill $PID
}

$COMMAND
