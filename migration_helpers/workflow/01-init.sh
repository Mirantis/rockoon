#!/bin/bash

function get_kubectl {
    curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.14.4/bin/linux/amd64/kubectl
    mv kubectl /usr/local/bin/
    chmod +x /usr/local/bin/kubectl
}

function install_requirements {
    apt -y update
    DEBIAN_FRONTEND=noninteractive apt -y install jq
}

install_requirements

if [[ ! -f /usr/local/bin/kubectl ]]; then
    get_kubectl
fi
