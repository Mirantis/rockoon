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

OVNNB_DB=${OVNNB_DB_PROTO}:${OVNNB_DB_HOST}:${OVNNB_DB_PORT}
OVNSB_DB=${OVNSB_DB_PROTO}:${OVNSB_DB_HOST}:${OVNSB_DB_PORT}
OVN_NORTHD_PID="/run/openvswitch/ovn-northd.pid"
OVN_NORTHD_SOCK="/run/openvswitch/ovn-northd.sock"


function start () {
  exec /usr/bin/ovn-northd \
      -vconsole:emer \
      -vconsole:err \
      -vconsole:info \
      --monitor \
      --unixctl=${OVN_NORTHD_SOCK} \
      --ovnnb-db=${OVNNB_DB} \
      --ovnsb-db=${OVNSB_DB} \
      --pidfile=${OVN_NORTHD_PID}
}

function stop () {
  PID=$(cat $OVN_NORTHD_PID)
  kill $PID
}

$COMMAND
