#!/bin/bash

set -e #x
RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$( cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common
. $TOP_DIR/database/functions


refresh_pillars
info "Applying linux.network.host"
salt '*' state.apply linux.network.host --timeout=60
info "Applying linux.system.certificate"
salt '*' state.apply linux.system.certificate --timeout=60
