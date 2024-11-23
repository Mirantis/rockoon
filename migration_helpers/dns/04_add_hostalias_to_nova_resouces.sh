#/bin/bash

RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$(cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common
. $TOP_DIR/database/functions

#modify deployments
for deployment in nova-api-osapi nova-api-metadata nova-conductor nova-consoleauth nova-novncproxy nova-placement-api nova-scheduler; do
resource_yaml=$(mktemp)
#write original resource yaml
kubectl get deployment ${deployment} -n openstack -o yaml > ${resource_yaml}
#add hostaliases to resource yaml
sed -i "/    spec:/r ${HOST_ALIAS_FILE}" ${resource_yaml}
#apply modified resource
kubectl apply -f ${resource_yaml}
done

#modify daemonsets
for daemonset in nova-compute-default; do
resource_yaml=$(mktemp)
#write original resource yaml
kubectl get ds ${daemonset} -n openstack -o yaml > ${resource_yaml}
#add hostaliases to resource yaml
sed -i "/    spec:/r ${HOST_ALIAS_FILE}" ${resource_yaml}
#apply modified resource
kubectl apply -f ${resource_yaml}
done
