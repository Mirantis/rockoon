#!/bin/bash

set -e #x
RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$( cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common

function get_service_public_base_url_mcp1 {
  local service_name=$1
  echo "$(get_mcp1_public_endpoint):$(get_service_by name $service_name)"
}

function get_service_public_base_url_mcp2 {
  local service_name=$1
  echo "$(get_mcp2_public_endpoint $service_name)"
}

function get_check_url {
  local service_name="$1"
  local project="$2"
  local env="$3"

  echo "$(get_service_public_base_url_${env} $service_name)/$(get_check_endpoint $service_name $project)"
}

function check_api {
  local service="$1"
  local env=$2

  info "Checking access for $service in $env"
  info "Getting token from MCP1 keystone"
  local token_project=$(get_token_project)
  local token=$(echo -e "$token_project" | head -1)
  local project=$(echo -e "$token_project" | tail -1)
  info "Get token: $token project: $project"

  info "Getting endpoint for $service"
  url="$(get_check_url $service $project $env)"
  set -x
  curl --show-error -f -H "X-Auth-Token: $token" $url -k -L
  set +x
}

check_api $@
