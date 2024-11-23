#!/bin/bash

RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$( cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/database/functions

mkdir -p $DATABASE_DIR
for component in $COMPONENTS_TO_MIGRATE_DB; do
    info "Calling check_database_connection"
    check_database_connection $component $(get_mcp1_database_address) $(get_mcp1_database_username $component) $(get_mcp1_database_password $component)
    info "Calling get_database_size"
    get_database_size $component $(get_mcp1_database_address) $(get_mcp1_database_username $component) $(get_mcp1_database_password $component)
    info "Calling dump_openstack_component_dbs"
    dump_openstack_component_dbs $component
    info "Calling check_database_connection"
    check_database_connection $component $(get_mcp2_database_address) $(get_mcp2_database_username $component) $(get_mcp2_database_password $component)
    info "Calling drop_database_on_target"
    drop_database_on_target $component
    info "Calling import_openstack_component_dbs"
    import_openstack_component_dbs $component
done
