#!/bin/bash
set -e
GIT_CREDS_ID=${GIT_CREDS_ID:-"mos-ci"}
OPENSTACK_SDK_REPO=${OPENSTACK_SDK_REPO:-"gerrit.mcp.mirantis.com:29418/packaging/sources/openstacksdk"}
OPENSTACK_SDK_REPO_BRANCH=${OPENSTACK_SDK_REPO_BRANCH:-"mcp/antelope"}

WORKDIR=$(pwd)
mkdir ${WORKDIR}/source_requirements/
git clone ssh://${GIT_CREDS_ID}@${OPENSTACK_SDK_REPO} ${WORKDIR}/source_requirements/openstacksdk
pushd ${WORKDIR}/source_requirements/openstacksdk/
git checkout $OPENSTACK_SDK_REPO_BRANCH
popd
