#!/bin/bash

set -e

RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$( cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common

function mcp2_import_cinder_backends_config {
    local backends_map=$(salt $(get_first_active_minion '-C I@cinder:volume') pillar.items cinder:volume:backend --out=json | jq '.[]|."cinder:volume:backend"')
    if [ "${backends_map}" == '{}' ]; then
        backends_map=$(salt $(get_first_active_minion '-C I@cinder:controller') pillar.items cinder:controller:backend --out=json | jq '.[]|."cinder:controller:backend"')
    fi

    # (dstremkouski): code to merge all configmap backends into general dict
    local resulting_map="${backends_map}"
    local resulting_volume_backends=""
    info "MCP1 gathering configmap backends from cinder:volumes:"
    local volume_backends_from_configmap=$(salt $(get_first_active_minion '-C I@cinder:volume') pillar.items cinder:volume:configmap:DEFAULT:enabled_backends --out=json | jq '.[]|."cinder:volume:configmap:DEFAULT:enabled_backends"' -r | tr ',' ' ')
    local backends_from_configmap_count=0
    for backend_from_configmap in ${volume_backends_from_configmap}; do
        if [ $(echo "${backends_map}" | jq "select(has(\"${backend_from_configmap}\")) | keys[]" -r)XX == "XX" ]; then
            info "MCP1 found extra backend configuration: ${backend_from_configmap}"
            backends_from_configmap_count=$((${backends_from_configmap_count}+1))
            local backend_map_from_configmap=$(salt $(get_first_active_minion '-C I@cinder:volume') pillar.items pillar.items cinder:volume:configmap:${backend_from_configmap} --out=json | jq ".[]| .\"cinder:volume:configmap:${backend_from_configmap}\"")
            resulting_map=$(jq --arg backend_from_configmap "${backend_from_configmap}" --argjson backend_map_from_configmap "${backend_map_from_configmap}" ". + {\"${backend_from_configmap}\": ${backend_map_from_configmap}}" <<< "${resulting_map}")
            if [ ${resulting_volume_backends}XX == "XX" ]; then
                resulting_volume_backends="${backend_from_configmap}"
            else
                resulting_volume_backends="${resulting_volume_backends},${backend_from_configmap}"
            fi
        fi
    done
    if [ ${backends_from_configmap_count} -gt 0 ]; then
        info "MCP1 New backends from cinder:controller to add: ${backends_from_configmap_count}"
    fi

    info "MCP1 gathering configmap backends from cinder:controller:"
    local controller_backends_from_configmap=$(salt $(get_first_active_minion '-C I@cinder:controller') pillar.items cinder:controller:configmap:DEFAULT:enabled_backends --out=json | jq '.[]|."cinder:controller:configmap:DEFAULT:enabled_backends"' -r | tr ',' ' ')
    local backends_from_configmap_count=0
    for backend_from_configmap in ${controller_backends_from_configmap}; do
        if [ $(echo "${backends_map}" | jq "select(has(\"${backend_from_configmap}\")) | keys[]" -r)XX == "XX" ]; then
            info "MCP1 found extra backend configuration: ${backend_from_configmap}"
            backends_from_configmap_count=$((${backends_from_configmap_count}+1))
            local backend_map_from_configmap=$(salt $(get_first_active_minion '-C I@cinder:controller') pillar.items pillar.items cinder:controller:configmap:${backend_from_configmap} --out=json | jq ".[]| .\"cinder:controller:configmap:${backend_from_configmap}\"")
            resulting_map=$(jq --arg backend_from_configmap "${backend_from_configmap}" --argjson backend_map_from_configmap "${backend_map_from_configmap}" ". + {\"${backend_from_configmap}\": ${backend_map_from_configmap}}" <<< "${resulting_map}")
            if [ ${resulting_volume_backends}XX == "XX" ]; then
                resulting_volume_backends="${backend_from_configmap}"
            else
                resulting_volume_backends="${resulting_volume_backends},${backend_from_configmap}"
            fi
        fi
    done
    if [ ${backends_from_configmap_count} -gt 0 ]; then
        info "MCP1 New backends from cinder:controller to add: ${backends_from_configmap_count}"
    fi

    # (dstremkouski): enabled_backends would be merged from resulting_map
    local resulting_volume_backends=$(echo "${resulting_map}" | jq 'keys|join(",")' -r)

    # (dstremkouski): cinder:volume:default_volume_type has priority over cinder:controller:default_volume_type
    local default_volume_type=$(salt $(get_first_active_minion '-C I@cinder:volume') pillar.get cinder:volume:default_volume_type --out=json | jq -r '.[]')
    if [ -z ${default_volume_type} ]; then
        default_volume_type=$(salt $(get_first_active_minion '-C I@cinder:controller') pillar.get cinder:controller:default_volume_type --out=json | jq -r '.[]')
    fi
    local default_volume_type_from_configmap=$(salt $(get_first_active_minion '-C I@cinder:controller') pillar.get cinder:controller:configmap:DEFAULT:default_volume_type --out=json | jq -r '.[]')
    if [ ! -z ${default_volume_type_from_configmap} ]; then
        default_volume_type="${default_volume_type_from_configmap}"
    fi
    local default_volume_type_from_configmap=$(salt $(get_first_active_minion '-C I@cinder:volume') pillar.get cinder:volume:configmap:DEFAULT:default_volume_type --out=json | jq -r '.[]')
    if [ ! -z ${default_volume_type_from_configmap} ]; then
        default_volume_type="${default_volume_type_from_configmap}"
    fi

    backends_map=${resulting_map}

    info "MCP1 backends map is:"
    info "${backends_map}"

    echo "${backends_map}" | jq -c --arg def_vol_type $default_volume_type --arg enabled_backends "${resulting_volume_backends}" \
                               '{"spec":
                                    {"services":
                                        {"block-storage":
                                            {"cinder":
                                                {"values":
                                                    {"conf":
                                                        {"backends":
                                                            (with_entries
                                                                (if .value.volume_driver == "cinder.volume.drivers.rbd.RBDDriver" then
                                                                    .value |=
                                                                        {volume_driver: "cinder.volume.drivers.rbd.RBDDriver",
                                                                         volume_backend_name: .backend,
                                                                         rbd_pool: .pool,
                                                                         rbd_user: .user,
                                                                         rbd_secret_uuid_fake: .secret_uuid,
                                                                         backend_host: (if .backend_host then .backend_host
                                                                                        elif .host then .host
                                                                                        else "" end)
                                                                        }
                                                                 else
                                                                     .
                                                                 end
                                                                )
                                                            ),
                                                            "cinder":
                                                               {"DEFAULT":
                                                                   {"enabled_backends": $enabled_backends,
                                                                    "default_volume_type": $def_vol_type,
                                                                    "volume_name_template": "volume-%s",
                                                                   }
                                                               }
                                                           }
                                                       }
                                                   }
                                               }
                                            }
                                        }
                                    }' > cinder_conf.json
    info "MCP2 resulting backends configuration:"
    info "$(cat cinder_conf.json | jq '.')"

    if [ "${1}" != '--dry-run' ]; then
        info "Applying MCP2 backends configuration. Openstack deployment object ${OPENSTACK_DEPLOYMENT_OBJECT_NAME} will be patched"
        kubectl -n openstack patch osdpl "${OPENSTACK_DEPLOYMENT_OBJECT_NAME}" --patch-file cinder_conf.json --type merge
    fi
}

mcp2_import_cinder_backends_config $@
