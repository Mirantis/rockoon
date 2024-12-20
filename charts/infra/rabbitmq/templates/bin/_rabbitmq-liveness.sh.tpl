#!/usr/bin/env bash

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

set -e

if [ -f /tmp/rabbit-disable-liveness-probe ]; then
   exit 0
else
   timeout 5 bash -c "true &>/dev/null </dev/tcp/${MY_POD_IP}/${PORT_AMPQ}"
   exec rabbitmqctl ping
fi
