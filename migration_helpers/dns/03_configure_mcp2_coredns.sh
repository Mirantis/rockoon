#/bin/bash

RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$(cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common
. $TOP_DIR/database/functions

#get mcp1 coredns service loadbalancer IP
lb_coredns_mcp1_ip=`kubectl get service coredns-mcp1-coredns -n ${COREDNS_NS} -o=jsonpath='{.status.loadBalancer.ingress[0].ip}'`
[[ -z "$lb_coredns_mcp1_ip" ]] && { echo "MCP1 coredns service loadbalancer IP not found. Check if helmbundle was installed successfully."; exit 1; }

#get mcp1 local domain
mcp1_local_domain=$(salt $(get_first_active_minion -C "I@keystone:server") pillar.get linux:system:domain --out json | jq -r '.[]')

#create temp files for service yaml and extra config
coredns_configmap_file=$(mktemp)
coredns_add_config=$(mktemp)

#populate extra config
cat << EOF >> $coredns_add_config
    ${mcp1_local_domain}:53 {
        errors
        cache 30
        forward . ${lb_coredns_mcp1_ip}
    }
EOF

#get mcp1 coredns config yaml
kubectl get configmap coredns -n kube-system -o yaml > $coredns_configmap_file

#add extra config  to mcp1 coredns yaml
sed -i "/kind: ConfigMap/e cat ${coredns_add_config}" $coredns_configmap_file

#apply configmap
kubectl apply -f $coredns_configmap_file

#restart coredns pods
kubectl -n kube-system delete pod -l k8s-app=kube-dns
