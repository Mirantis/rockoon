#!/bin/bash

export STACK_TEST_NETWORK_NAME=${STACK_TEST_NETWORK_NAME:-migrationStackNetwork}
export STACK_TEST_SUBNET_NAME=${STACK_TEST_SUBNET_NAME:-migrationStackSubnet}
export STACK_TEST_SUBNET_RANGE=${STACK_TEST_SUBNET_RANGE:-10.11.12.0/24}
export STACK_TEST_NAME=${STACK_TEST_NAME:-cirros-stack-migration}
export IMAGE_NAME=${IMAGE_NAME:-TestCirros-0.4.0}
export FLAVOR_NAME=${FLAVOR_NAME:-m1.tiny_test}

#wget https://binary.mirantis.com/openstack/bin/cirros/0.4.0/cirros-0.4.0-x86_64-disk.img
#openstack image create cirros-0.4.0-x86_64-disk --file cirros-0.4.0-x86_64-disk.img --disk-format qcow2 --container-format bare --public

openstack network create ${STACK_TEST_NETWORK_NAME}
openstack subnet create ${STACK_TEST_SUBNET_NAME} --network ${STACK_TEST_NETWORK_NAME} --subnet-range ${STACK_TEST_SUBNET_RANGE}

openstack stack create --template server_console.yaml --parameter "image=${IMAGE_NAME}" --parameter "flavor=${FLAVOR_NAME}" --parameter "network_name=${STACK_TEST_NETWORK_NAME}" ${STACK_TEST_NAME}
