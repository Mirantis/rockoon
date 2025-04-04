#!/bin/bash

{{/*
Copyright 2025 Mirantis Inc.

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

NODE_NAME=${NODE_NAME:-$(hostname -s)}
IC_PORT_NETWORK_NAME=${IC_PORT_NETWORK_NAME}
IC_PORT_NAME=irc-${NODE_NAME}
IC_PORT_DEVICE="o-irc0"

port_output=$(openstack port show ${IC_PORT_NAME} || /bin/true)

if ! echo "$port_output" |grep mac_address; then
    port_output=$(openstack port create --network ${IC_PORT_NETWORK_NAME} --device-owner ironic:conductor --host ${NODE_NAME} ${IC_PORT_NAME})
fi

IC_PORT_MAC=$(echo "$port_output" |awk '/mac_address/ {print $4}')
IC_PORT_ID=$(echo "$port_output" |awk '/ id / {print $4}')
IC_PORT_MTU=$(openstack network show -f value -c mtu ${IC_PORT_NETWORK_NAME})
IC_PORT_SUBNET_ID=$(openstack port show ${IC_PORT_ID} -f json -c fixed_ips | jq '.fixed_ips[0].subnet_id' | tr -d '"')
IC_PORT_NETMASK=$(openstack subnet show ${IC_PORT_SUBNET_ID} -f value -c cidr | awk -F '/' '{print $2}')
IC_PORT_IP_ADDR=$(openstack port show ${IC_PORT_ID} -f json -c fixed_ips | jq '.fixed_ips[0].ip_address' | tr -d '"')

cat <<EOF> /tmp/pod-shared/ic_port_env.conf
IC_PORT_NAME=${IC_PORT_NAME}
IC_PORT_DEVICE=${IC_PORT_DEVICE}
IC_PORT_MAC=${IC_PORT_MAC}
IC_PORT_ID=${IC_PORT_ID}
IC_PORT_MTU=${IC_PORT_MTU}
IC_PORT_IP_ADDR=${IC_PORT_IP_ADDR}
IC_PORT_NETMASK=${IC_PORT_NETMASK}
EOF
