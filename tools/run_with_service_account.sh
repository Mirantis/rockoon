#!/bin/bash
set -e
set -o pipefail

source tools/get_service_account.sh

REPLICAS=`kubectl -n osh-system get deployment rockoon -o jsonpath='{.spec.replicas}' || echo 0`
if [ $REPLICAS -gt 0 ];
then
    echo "Found running OpenStack Operator inststance."
    echo "Please, scale down rockoon deployment using the following command:"
    echo "kubectl -n osh-system scale deployment rockoon --replicas 0"
    exit 1
fi

python3 tools/set-cluster-insecure.py $KUBECFG_FILE_NAME
echo using kube config file $KUBECFG_FILE_NAME
export KUBECONFIG=$KUBECFG_FILE_NAME
HELM_BINARY="https://binary.mirantis.com/openstack/bin/utils/helm/helm-v3.16.1-linux-amd64"

export NODE_IP=${NODE_IP:$(ip route get 4.2.2.1 | awk '{print $7}' | head -1)}
export OSCTL_POD_NETWORKS_DATA=${OSCTL_POD_NETWORKS_DATA:-'[{"cidr":"192.168.0.0/16"}]'}
export OS_CLIENT_CONFIG_FILE="/tmp/osctl-clouds.yaml"

if ! which helm3; then
    wget -O /usr/bin/helm3 $HELM_BINARY
    chmod +x /usr/bin/helm3
fi

. tools/fill_internal_svc_ips.sh

echo "Building helm charts and dependencies"
for req in $(ls -d charts/{openstack,infra}/*/); do pushd $req; helm3 dep up; popd; done > /dev/null 2>&1


available_controllers=(
    "-m rockoon.controllers.node"
    "-m rockoon.controllers.openstackdeployment"
    "-m rockoon.controllers.secrets"
    "-m rockoon.controllers.health"
    "-m rockoon.controllers.probe"
    "-m rockoon.controllers.maintenance"
    "-m rockoon.controllers.openstackdeploymentstatus"
    "-m rockoon.controllers.configmaps"
)

controllers="${available_controllers[*]}"

kopf run --dev -n openstack -P rockoon.osdpl --liveness=http://:8090/healthz $controllers
