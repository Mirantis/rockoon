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

# Mask permissions to files 416 dirs 0750
umask 0027

DEFAULT_INTERFACE_IP=($(python3 <<PYTHONCODE
import netifaces as ni
iface = ni.gateways()[ni.AF_INET][0]
address = ni.ifaddresses(iface[1])[ni.AF_INET][0]
print(f"{address['addr']}")
PYTHONCODE
))
ROUTER_ID=${DEFAULT_INTERFACE_IP}

mkdir -p /tmp/pod-shared
tee > /tmp/pod-shared/neutron-agent.ini << EOF
{{- if and ( empty .Values.conf.neutron.DEFAULT.host ) ( .Values.pod.use_fqdn.neutron_agent ) }}
[DEFAULT]
host = $(hostname --fqdn)
{{- end }}
EOF
if [[ -n $ROUTER_ID ]]; then
tee >> /tmp/pod-shared/neutron-agent.ini << EOF
[bgp]
bgp_router_id = $ROUTER_ID
EOF
fi
