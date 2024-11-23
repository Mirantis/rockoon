#!/bin/bash

set -e #x
RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$( cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common
. $TOP_DIR/database/functions


function check_globals_set {
  info "Checking gloabl variables are set"
  local mcp1_database_address=$(get_mcp1_database_address)
  die_if_not_set $LINENO mcp1_database_address "Failed to get gloabl variable mcp1_database_address"
  info "Global variables are: OK"
}

refresh_pillars
check_globals_set
