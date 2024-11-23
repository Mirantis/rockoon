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

SSH_KEY_DIR=/var/lib/nova/ssh/
mkdir -p $SSH_KEY_DIR

IFS=','
HOST_KEY_OPT=()
for KEY_TYPE in $KEY_TYPES; do
    KEY_PATH=$SSH_KEY_DIR/ssh_host_${KEY_TYPE}_key
    if [[ ! -f "${KEY_PATH}" ]]; then
        ssh-keygen -q -t ${KEY_TYPE} -f ${KEY_PATH} -N ""
    fi
    HOST_KEY_OPT+=( -h "$KEY_PATH")
done
IFS=''
usermod -s /bin/rbash nova

# Create the PrivSep empty dir if necessary
if [ ! -d /run/sshd ]; then
  mkdir /run/sshd
  chmod 0755 /run/sshd
fi

exec /usr/sbin/sshd -f /etc/ssh/sshd_config -D -e "${HOST_KEY_OPT[@]}"
