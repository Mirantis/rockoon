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

OVN_VTEP_PID="/run/openvswitch/ovn-vtep.pid"

OVN_DB_IP=$(dig ${OVN_DB_HOST} +short)
OVNSB_DB_IP=$(dig ${OVNSB_DB_HOST} +short)
OVNSB_DB=${OVNSB_DB_PROTO}:${OVNSB_DB_IP}:${OVNSB_DB_PORT}

OVS_DB=${OVS_DB_PROTO}:${OVS_DB_HOST}:${OVS_DB_PORT}


function start () {
  exec /usr/bin/ovn-controller-vtep --vtep-db ${OVS_DB} --ovnsb-db ${OVNSB_DB} --pidfile ${OVN_VTEP_PID}
}

function stop () {
  PID=$(cat $OVN_VTEP_PID)
  kill $PID
}

$COMMAND
