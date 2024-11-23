#!/bin/bash

set -e #x
RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$( cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common

function generate_globals {
  local mcp2_db_address=$(get_mcp2_external_ip mariadb)
  local mcp2_rabbitmq_notifications_address=$(get_mcp2_external_ip rabbitmq-external)
  local mcp1_heat_domain_name=$(salt $(get_first_active_minion -C "I@heat:server") pillar.get heat:server:stack_domain_admin --out json | jq -r '.[].stack_user_domain_name')
  local mcp1_heat_username=$(salt $(get_first_active_minion -C "I@heat:server") pillar.get heat:server:stack_domain_admin --out json | jq -r '.[].name')
  local mcp1_heat_username_password=$(salt $(get_first_active_minion -C "I@heat:server") pillar.get heat:server:stack_domain_admin --out json | jq -r '.[].password')

cat <<EOF > $RUN_DIR/cluster/migration/init.yml
parameters:
  _param:
    mcp2_rabbitmq_notifications_address: ${mcp2_rabbitmq_notifications_address}
    mcp1_heat_domain_name: ${mcp1_heat_domain_name}
    mcp1_heat_username: ${mcp1_heat_username}
    mcp1_heat_username_password: ${mcp1_heat_username_password}
EOF

  for component in $COMPONENTS_TO_MIGRATE; do
    local service_type=$(service_name_to_type $component)
    local mcp2_db_user=$(kubectl -n openstack get secrets generated-${service_type}-passwords -o jsonpath="{.data.database}" | base64 -d | jq ".user.username" | tr -d '"')
    local mcp2_db_password=$(kubectl -n openstack get secrets generated-${service_type}-passwords -o jsonpath="{.data.database}" | base64 -d | jq ".user.password" | tr -d '"')
    local mcp2_rabbitmq_notifications_component_username=$(kubectl -n openstack get secrets generated-${service_type}-passwords -o jsonpath="{.data.notifications}" | base64 -d | jq ".user.username" | tr -d '"')
    local mcp2_rabbitmq_notifications_component_password=$(kubectl -n openstack get secrets generated-${service_type}-passwords -o jsonpath="{.data.notifications}" | base64 -d | jq ".user.password" | tr -d '"')

    local mcp2_rabbitmq_component_username=$(kubectl -n openstack get secrets generated-${service_type}-passwords -o jsonpath="{.data.messaging}" | base64 -d | jq ".user.username" | tr -d '"')
    local mcp2_rabbitmq_component_password=$(kubectl -n openstack get secrets generated-${service_type}-passwords -o jsonpath="{.data.messaging}" | base64 -d | jq ".user.password" | tr -d '"')

cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
    mcp2_database_${component}_address: $mcp2_db_address
    mcp2_database_${component}_username: $mcp2_db_user
    mcp2_database_${component}_password: $mcp2_db_password
    mcp2_rabbitmq_notifications_${component}_username: $mcp2_rabbitmq_notifications_component_username
    mcp2_rabbitmq_notifications_${component}_password: $mcp2_rabbitmq_notifications_component_password
    mcp2_rabbitmq_${component}_username: $mcp2_rabbitmq_component_username
    mcp2_rabbitmq_${component}_password: $mcp2_rabbitmq_component_password
EOF

  done

  for component in $COMPONENTS_TO_MIGRATE; do
    # Skip keystone as it doesn't use messaging for inter service communications.
    if [[ "$component" == "keystone" ]]; then
      continue
    fi
    local mcp2_rabbitmq_component_address=$(get_mcp2_external_ip rabbitmq-$component-external)

cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
    mcp2_rabbitmq_${component}_address: $mcp2_rabbitmq_component_address
EOF

  done

  # Set mcp1 database parameters
  local mcp1_database_address=$(salt 'dbs01*' pillar.items _param:openstack_database_address --out json | jq '.[]|.[]' | tr -d '"')
cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
    mcp1_database_address: $mcp1_database_address
    mcp2_database_address: $mcp2_db_address
EOF

  for component in $COMPONENTS_TO_MIGRATE; do
    local mcp1_db_user=$(salt 'dbs01*' pillar.items _param:mysql_${component}_username --out json | jq '.[]|.[]' | tr -d '"')
    if ! is_set mcp1_db_user; then
      info "Username for $component is not set in _param:mysql_${component}_username, falling back to default user name."
      mcp1_db_user=$component
    fi

    local mcp1_db_password=$(salt 'dbs01*' pillar.items _param:mysql_${component}_password --out json | jq '.[]|.[]' | tr -d '"')
    die_if_not_set $LINENO mcp1_db_user "Cant get mcp1_db_password for $component"

cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
    mcp1_database_${component}_username: $mcp1_db_user
    mcp1_database_${component}_password: $mcp1_db_password
EOF
  done

  local mcp2_memcached_names_addresses
  mcp2_memcached_names_addresses=$(expose_mcp2_memcached)
  local mcp2_internal_domain_name
  mcp2_internal_domain_name=$(get_mcp2_internal_domain_name)
  # memcached
  # Use dns to make sure URL in mcp1 and mcp2 are the same
  for component in $COMPONENTS_TO_MIGRATE; do
    local service_type=$(service_name_to_type $component)
    local mcp2_memcached_component_secret_key=$(kubectl -n openstack get secrets generated-${service_type}-passwords -o jsonpath="{.data.memcached}" | base64 -d | tr -d '"')
cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
    mcp2_memcached_${component}_members:
EOF
    for name in $mcp2_memcached_names_addresses; do
cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
      - host: ${name%%_*}.openstack.svc.${mcp2_internal_domain_name}
        port: 11211
EOF
    done
cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
    mcp2_memcached_${component}_secret_key: $mcp2_memcached_component_secret_key
EOF
  done

  # get public cert from MCP2
  local mcp2_public_ca=$(kubectl -n openstack get secrets keystone-tls-public -o jsonpath='{.data.ca\.crt}' | base64 -d)

cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
    mcp2_public_ca: |
$(echo "$mcp2_public_ca" | sed 's/^/      /g')
EOF

  # Get nova parameters
  local mcp1_nova_ceph_libvirt_secret_uuid=$(salt $(get_first_active_minion -C "I@nova:compute") pillar.items nova:compute:ceph:secret_uuid --out json | jq '.[]|.[]' | tr -d '"')

cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
    mcp1_nova_ceph_libvirt_secret_uuid: ${mcp1_nova_ceph_libvirt_secret_uuid}
EOF

  # generate hosts part
  local mcp2_ingress_address=$(get_mcp2_external_ip ingress)
  local mcp2_public_domain_name=$(get_mcp2_public_domain_name)
  local mcp2_mariadb_address=$(get_mcp2_external_ip mariadb)

cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
    mcp2_public_domain_name: ${mcp2_public_domain_name}
EOF

cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
  linux:
    network:
      host:
        mcp2_mariadb_public_host:
          address: $mcp2_mariadb_address
          names:
          - mariadb.openstack.svc.${mcp2_internal_domain_name}
EOF
for name in $mcp2_memcached_names_addresses; do
cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
        mcp2_memcached_${name%%_*}_public_api_host:
          address: ${name##*_}
          names:
          - ${name%%_*}.openstack.svc.${mcp2_internal_domain_name}
EOF
done
cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
        mcp2_openstack_public_api_host:
          address: $mcp2_ingress_address
          names:
EOF
  for component in $COMPONENTS_TO_MIGRATE_PUBLIC_API; do
cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
          - ${component}.${mcp2_public_domain_name}
EOF
  done
  for component in $COMPONENTS_TO_MIGRATE; do
    for internal_service in $(get_service_subservices_internal_endpoints $component); do
      local internal_service_ip=$(get_mcp2_external_ip ${internal_service})
cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
        mcp2_${component}_${internal_service}_internal:
          address: $internal_service_ip
          names:
           - ${internal_service}.openstack.svc.${mcp2_internal_domain_name}
EOF
    done
  done
if [[ "$component" == "nova" ]]; then

cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
        mcp2_nova_dedicated_rabbit:
          address: $mcp2_rabbitmq_component_address
          names:
           - $(salt $(get_first_active_minion -C "I@nova:compute") cmd.run "nova-manage cell_v2 list_cells | grep cell1 | awk -F\"|\" '{print \$4}' | sed  \"s/.*@\(.*\):.*/\1/\"" --out json | jq '.[]' | tr -d '"')
EOF
fi

  #get mcp2 nodes
  local mcp2_nodes=$(kubectl get nodes -o wide | awk '{print $1" "$6}' | column -t | awk 'NR>1')
  echo  "$mcp2_nodes" | while read line; do
    local mcp2_node_name=$(echo "$line" | awk '{print $1}')
    local mcp2_node_ip=$(echo "$line" | awk '{print $2}')

cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
        ${mcp2_node_name}:
          address: ${mcp2_node_ip}
          names:
          - ${mcp2_node_name}
EOF
  done

  # get public cert from MCP2
  local mcp2_public_ca=$(kubectl -n openstack get secrets keystone-tls-public -o jsonpath='{.data.ca\.crt}' | base64 -d)

cat <<EOF >> $RUN_DIR/cluster/migration/init.yml
    system:
      ca_certificates:
        mcp2_public_ca: \${_param:mcp2_public_ca}
EOF
}

generate_globals
