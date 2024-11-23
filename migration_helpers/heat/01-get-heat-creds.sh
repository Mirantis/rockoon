#!/bin/bash -e
#
# THIS FILE IS GOING TO BE EXECUTED ON ANY CFG NODES (MCP1).
#
RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$(cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common

echo "
values:
  endpoints:
    identity:
      auth:
        heat_stack_user:
          domain_name: $(reclass -n $(hostname -f)  -o json | jq -r .parameters._param.mcp1_heat_domain_name)
          username: $(reclass -n $(hostname -f)  -o json | jq -r .parameters._param.mcp1_heat_username)
          password: $(reclass -n $(hostname -f)  -o json | jq -r .parameters._param.mcp1_heat_username_password)
"
