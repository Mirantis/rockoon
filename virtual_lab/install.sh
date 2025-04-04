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

DEBIAN_FRONTEND=noninteractive apt install -y python3-pip

PIP_BREAK_SYSTEM_PACKAGES=1 pip3 install ansible

ansible-galaxy collection install bodsch.core
ansible-galaxy collection install bodsch.scm
ansible-galaxy role install bodsch.k0s
ansible-galaxy role install cloudalchemy.coredns

cd "${OPENSTACK_CONTROLLER_DIR}/virtual_lab/ansible/"
sed -i "s/oc-virtual-lab-server-ctl-01/${HOSTNAME}/g" "${INVENTORY_FILE}"

ansible-playbook -i  "${INVENTORY_FILE}" k0s-install.yaml -vvv

mkdir -p /root/.kube; cp "$(dirname "${INVENTORY_FILE}")/artifacts/k0s-kubeconfig.yml" /root/.kube/config

ansible-playbook -i "${INVENTORY_FILE}" infra-install.yaml -vvv
ansible-playbook -i "${INVENTORY_FILE}" build-images.yaml -vvv
ansible-playbook -i "${INVENTORY_FILE}" oc-install.yaml -vvv
ansible-playbook -i "${INVENTORY_FILE}" oc-install.yaml -vvv --tags wait
ansible-playbook -i "${INVENTORY_FILE}" deployment-info.yaml
