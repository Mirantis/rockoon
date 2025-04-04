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

source /tmp/pod-shared/ic_port_env.conf

ovs-vsctl --no-wait show
ovs-vsctl --may-exist add-port br-int ${IC_PORT_DEVICE} \
        -- set Interface ${IC_PORT_DEVICE} type=internal \
        -- set Interface ${IC_PORT_DEVICE} external-ids:iface-status=active \
        -- set Interface ${IC_PORT_DEVICE} external-ids:attached-mac="${IC_PORT_MAC}" \
        -- set Interface ${IC_PORT_DEVICE} external-ids:iface-id="${IC_PORT_ID}" \
        -- set Interface ${IC_PORT_DEVICE} external-ids:skip_cleanup=true \
        -- set Interface ${IC_PORT_DEVICE} mtu_request=${IC_PORT_MTU}

ip link set dev ${IC_PORT_DEVICE} address ${IC_PORT_MAC} up
ip addr flush dev ${IC_PORT_DEVICE}
ip addr add ${IC_PORT_IP_ADDR}/${IC_PORT_NETMASK} dev ${IC_PORT_DEVICE}
