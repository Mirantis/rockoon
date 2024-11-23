#!/bin/bash

set -e #x
RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$( cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common


info "Generating global pillars..."
$TOP_DIR/model/01-prepare-globals.sh

if [[ ! -d $SAL_CLUSTER_ROOT/migration ]]; then
  info "Linking globals to cluster model $SAL_CLUSTER_ROOT"
  ln -s $TOP_DIR/model/cluster/migration/ $SAL_CLUSTER_ROOT/
fi

info "Globals are located in $TOP_DIR/model/cluster/migration/init.yml please include them to $SAL_CLUSTER_ROOT/infra/init.yml"
