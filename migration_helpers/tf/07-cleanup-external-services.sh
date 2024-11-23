#!/bin/bash

set -e #x

RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$( cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common

function get_services {
    echo "$(kubectl -n tf get svc -o name | cut -d/ -f 2 | grep external)"
}

EXTERNAL_SERVICES="$(get_services)"
for i in "${EXTERNAL_SERVICES}"; do
  kubectl -n tf delete svc $i
done