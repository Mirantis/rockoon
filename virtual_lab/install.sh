#!/bin/bash

set -ex

LOG_FILE=${LOG_FILE:-"/var/log/oc-virtual-lab.log"}

apt update -y
DEBIAN_FRONTEND=noninteractive apt install -y moreutils

exec > >(ts '[%Y-%m-%d %H:%M:%S]' | tee -a "${LOG_FILE}" )
exec 2> >(ts '[%Y-%m-%d %H:%M:%S]' | tee -a "${LOG_FILE}" >&2)

TOP_DIR="$(cd "$(dirname "$0")" && pwd)"

OPENSTACK_CONTROLLER_DIR=${OPENSTACK_CONTROLLER_DIR:-"${TOP_DIR}/../"}
INVENTORY_FILE=${INVENTORY_FILE:-"${OPENSTACK_CONTROLLER_DIR}/virtual_lab/ansible/inventory/single_node.yaml"}
HOSTNAME=$(hostname)

if [[ -z $(apt --installed -qq list python3-pip) ]]; then
    DEBIAN_FRONTEND=noninteractive apt install -y python3-pip
fi

if ! pip3 show ansible 2>&1 >/dev/null ; then
    PIP_BREAK_SYSTEM_PACKAGES=1 pip3 install ansible
fi

for collection in bodsch.core bodsch.scm; do
    if [[ $(ansible-galaxy collection list | grep -cw $collection) != 1 ]]; then
        ansible-galaxy collection install $collection
    fi
done

for role in cloudalchemy.coredns bodsch.k0s; do
    if [[ $(ansible-galaxy role list | grep -cw $role) != 1 ]]; then
        ansible-galaxy role install $role
    fi
done

cd "${OPENSTACK_CONTROLLER_DIR}/virtual_lab/ansible/"
sed -i "s/oc-virtual-lab-server-ctl-01/${HOSTNAME}/g" "${INVENTORY_FILE}"

ansible-playbook -i  "${INVENTORY_FILE}" k0s-install.yaml -vvv

mkdir -p /root/.kube; cp "$(dirname "${INVENTORY_FILE}")/artifacts/k0s-kubeconfig.yml" /root/.kube/config

ansible-playbook -i "${INVENTORY_FILE}" infra-install.yaml -vvv
ansible-playbook -i "${INVENTORY_FILE}" build-images.yaml -vvv
ansible-playbook -i "${INVENTORY_FILE}" oc-install.yaml -vvv
ansible-playbook -i "${INVENTORY_FILE}" oc-install.yaml -vvv --tags wait
ansible-playbook -i "${INVENTORY_FILE}" deployment-info.yaml
