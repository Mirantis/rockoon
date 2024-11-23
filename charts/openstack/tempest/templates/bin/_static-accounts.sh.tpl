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

set -x

STACK_NAME=${STACK_NAME:-tempest-static-accounts}
STACK_TEMPLATE=${STACK_TEMPLATE:-/tmp/static-accounts-heat-template.yaml}
STACK_CREATE_TIMEOUT=${STACK_CREATE_TIMEOUT:-600}
TEMPEST_DOMAIN_NAME=${TEMPEST_DOMAIN_NAME:-tempest}
GLANCE_BARBICAN_SECRET_UUID=${GLANCE_BARBICAN_SECRET_UUID:-}

# Manage domain
TEMPEST_DOMAIN_ID=$(openstack domain create --or-show --enable -f value -c id \
    --description="Service Domain for Tempest ${SERVICE_OS_DOMAIN_NAME}" \
    "${TEMPEST_DOMAIN_NAME}")

# Display domain
openstack domain show "${TEMPEST_DOMAIN_ID}"

status=$(openstack stack show $STACK_NAME -f value -c stack_status 2>&1)

function wait_for_stack {
    local timeout=$1
    local stack_name=$2
    local rval=0
    timeout $timeout bash -x <<EOF || rval=$?
      STATUS=""
      while ! echo \$STATUS |grep -q -e "UPDATE_COMPLETE" -e "CREATE_COMPLETE"; do
        sleep 15
        STATUS=\$(openstack stack show $stack_name -f value -c stack_status)
      done
EOF
    if [[ "$rval" != 0 ]]; then
      openstack stack show $stack_name
      echo "Stack create completion failed."
      exit $rval
    fi
}

function _get_heat_user_id {
    local id
    local heat_plugin_username={{ .Values.conf.tempest.heat_plugin.username | default "admin" }}
    local heat_plugin_user_domain={{ .Values.conf.tempest.heat_plugin.user_domain_id | default "default" }}
    id=$(openstack user show $heat_plugin_username --domain $heat_plugin_user_domain -f value -c id)
    echo $id
}

if echo $status |grep -q "not found"; then
  echo "The stack $STACK_NAME not found. Creating..."
  openstack stack create $STACK_NAME -t $STACK_TEMPLATE
fi

wait_for_stack $STACK_CREATE_TIMEOUT $STACK_NAME

openstack role add reader --user tempest-system-reader-manual --user-domain "${TEMPEST_DOMAIN_NAME}" --system all

cmd_args=""

heat_user_id=$(_get_heat_user_id)
if [[ -n "${heat_user_id}" ]]; then
    cmd_args="$cmd_args --user $heat_user_id"
fi

for user in $(openstack user list --domain $TEMPEST_DOMAIN_NAME -f value -c ID); do
    cmd_args="$cmd_args --user $user"
done

# NOTE(vsaienko): acl submit accepts only
glance_barbican_secret_href=$(openstack secret list -f value -c "Secret href" |grep $GLANCE_BARBICAN_SECRET_UUID)
openstack acl submit $glance_barbican_secret_href $cmd_args
