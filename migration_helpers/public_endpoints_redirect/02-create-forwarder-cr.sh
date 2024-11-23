#/bin/bash

RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$(cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common
. $TOP_DIR/database/functions

PORTS=$(echo -ne $(salt -C 'I@keystone:server:role:primary' cmd.run ". /root/keystonercv3; openstack endpoint list --interface public -f value -c "URL" | sed -r 's/.*:([0-9]+).*/\1/' | sort | uniq" --out json | jq '.[]' | tr -d '"')| grep -v $IGNORE_PUBLIC_PORTS)


cat << EOF > ${HELMBUNDLE_CR}
apiVersion: lcm.mirantis.com/v1alpha1
kind: HelmBundle
metadata:
  name: nginx-mcp1-forwarder
  namespace: ${HELMBUNDLE_NS}
spec:
  repositories:
  - name: nginx-forwarder
    url: http://binary.mirantis.com/kubernetes/helm/incubator/
  releases:
  - name: mcp1-forwarder
    chart: nginx-forwarder/nginx
    version: 6.0.2
    namespace: ${FORWARDER_NS}
    values:
      extraVolumes:
        - name: public-endpoints-tls
          secret:
            secretName: public-endpoints-tls
            defaultMode: 0444
      extraVolumeMounts:
        - name: public-endpoints-tls
          mountPath: /opt/bitnami/nginx/conf/public-endpoints-tls.crt
          subPath: tls.crt
          readOnly: true
        - name: public-endpoints-tls
          mountPath: /opt/bitnami/nginx/conf/public-endpoints-tls.key
          subPath: tls.key
          readOnly: true
        - name: public-endpoints-tls
          mountPath: /opt/bitnami/nginx/conf/public-endpoints-tls_ca.key
          subPath: ca.crt
          readOnly: true
      cloneStaticSiteFromGit:
        enabled: false
      service:
        ports:
EOF

for port in $PORTS; do
cat << EOF >> ${HELMBUNDLE_CR}
          - name: $(get_service_by port ${port})
            port: ${port}
            protocol: TCP
EOF
done

# Redirect for horizon
_horizon_port_tmp=8443
_horizon_port=$(salt prx01* pillar.items haproxy:proxy:listen:openstack_web:binds:port --out json | jq '.[][]')
cat << EOF >> ${HELMBUNDLE_CR}
          - name: horizon
            port: ${_horizon_port}
            protocol: TCP
            targetPort: ${_horizon_port_tmp}
EOF
# Redirect for novnc
_novnc_port=6080
cat << EOF >> ${HELMBUNDLE_CR}
          - name: novnc
            port: ${_novnc_port}
            protocol: TCP
EOF
cat << EOF >> ${HELMBUNDLE_CR}
      serverBlock: |-
        ssl_certificate     public-endpoints-tls.crt;
        ssl_certificate_key public-endpoints-tls.key;
EOF

for port in $PORTS; do
cat << EOF >> ${HELMBUNDLE_CR}
        server {
          listen 0.0.0.0:${port} ssl;
          location / {
            return 301 https://$(get_service_by port ${port}).${MCP2_PUBLIC_DOMAIN_NAME}\$request_uri;
          }
        }
EOF
done


cat << EOF >> ${HELMBUNDLE_CR}
        server {
          listen 0.0.0.0:${_horizon_port_tmp} ssl;
          location / {
            return 301 https://horizon.${MCP2_PUBLIC_DOMAIN_NAME}\$request_uri;
          }
        }
EOF

cat << EOF >> ${HELMBUNDLE_CR}
        server {
          listen 0.0.0.0:${_novnc_port} ssl;
          location / {
            return 301 https://novncproxy.${MCP2_PUBLIC_DOMAIN_NAME}\$request_uri;
          }
        }
EOF
