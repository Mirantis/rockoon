#/bin/bash

RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$(cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common
. $TOP_DIR/database/functions

function get_data_from_hosts_file {
cat /etc/hosts | grep ${mcp1_local_domain} | while read line; do
local mcp1_host_ip=`echo "${line}" | awk '{print $1}'`
local mcp1_host_fqdn=`echo "${line}" | awk '{print $2}'`
local mcp1_host_short=`echo "${line}" | awk '{print $3}'`

cat << EOF >> ${COREDNS_HELMBUNDLE_CR}
          ${mcp1_host_fqdn}.            IN      A       ${mcp1_host_ip}
EOF

cat<< EOF >> ${HOST_ALIAS_FILE}
      - hostnames:
        - ${mcp1_host_short}
        ip: ${mcp1_host_ip}
EOF
done
}

mcp1_local_domain=$(salt $(get_first_active_minion -C "I@keystone:server") pillar.get linux:system:domain --out json | jq -r '.[]')

cat<< EOF > ${HOST_ALIAS_FILE}
      hostAliases:
EOF

cat << EOF > ${COREDNS_HELMBUNDLE_CR}
apiVersion: lcm.mirantis.com/v1alpha1
kind: HelmBundle
metadata:
  name: coredns-mcp1
  namespace: osh-system
spec:
  repositories:
  - name: hub_stable
    url: https://binary.mirantis.com/kubernetes/helm/stable
  releases:
  - name: coredns-mcp1
    chart: hub_stable/coredns
    version: 1.10.1
    namespace: ${COREDNS_NS}
    values:
      isClusterService: false
      servers:
      - zones:
        - zone: .
          scheme: dns://
          use_tcp: false
        port: 53
        plugins:
        - name: cache
          parameters: 30
        - name: errors
        # Serves a /health endpoint on :8080, required for livenessProbe
        - name: health
        # Serves a /ready endpoint on :8181, required for readinessProbe
        - name: ready
        # Required to query kubernetes API for data
        - name: kubernetes
          parameters: cluster.local
        - name: loadbalance
          parameters: round_robin
        # Serves a /metrics endpoint on :9153, required for serviceMonitor
        - name: prometheus
          parameters: 0.0.0.0:9153
        - name: forward
          parameters: . /etc/resolv.conf
        - name: file
          parameters: /etc/coredns/mcp1.db ${mcp1_local_domain}
      serviceType: LoadBalancer
      zoneFiles:
      - filename: mcp1.db
        domain: ${mcp1_local_domain}
        contents: |
          ${mcp1_local_domain}.            IN      SOA     sns.dns.icann.org. noc.dns.icann.org. 2020161101 7200 3600 1209600 3600
          ${mcp1_local_domain}.            IN      NS      b.iana-servers.net.
          ${mcp1_local_domain}.            IN      NS      a.iana-servers.net.
EOF

get_data_from_hosts_file

