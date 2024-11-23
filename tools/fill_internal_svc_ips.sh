#!/bin/bash
set -e
set -o pipefail

SERVICES="cinder-api keystone-api glance-api nova-api neutron-server barbican-api designate-api octavia-api placement-api masakari-api heat-api"

HOSTS_FILE_IDENTIFIER="# Automatically set IP"

function get_svc_cluster_ip {
    local service=$1
    local namespace="${2:-openstack}"
    svc_ip=$(kubectl -n ${namespace} get svc $service -o jsonpath='{.spec.clusterIP}')
    echo $svc_ip
}

function get_svc_external_ip {
    local service=$1
    local namespace="${2:-openstack}"
    svc_ip=$(kubectl -n ${namespace} get svc $service -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    echo $svc_ip
}

sed -i "/${HOSTS_FILE_IDENTIFIER}/d" /etc/hosts

for service in $SERVICES; do
    svc_ip=$(get_svc_cluster_ip $service)
    echo "$service: $svc_ip"
    echo "$svc_ip ${service}.openstack.svc.cluster.local  $HOSTS_FILE_IDENTIFIER" >> /etc/hosts
done

svc_ip=$(get_svc_cluster_ip rockoon-exporter osh-system)
echo "rockoon-exporter: $svc_ip"
echo "$svc_ip rockoon-exporter.osh-system.svc.cluster.local  $HOSTS_FILE_IDENTIFIER" >> /etc/hosts

svc_ip=$(get_svc_cluster_ip grafana stacklight)
echo "grafana: $svc_ip"
echo "$svc_ip grafana.stacklight $HOSTS_FILE_IDENTIFIER" >> /etc/hosts

# Set public IPs
ingress_ip=$(get_svc_external_ip ingress openstack)
hosts=$(kubectl -n openstack get ingress | awk '/it.just.works/ {print $3}' | tr '\n' ' ')
echo "$ingress_ip $hosts $HOSTS_FILE_IDENTIFIER" >> /etc/hosts


# IAM data
iam_ip=$(get_svc_external_ip openstack-iam-keycloak-http iam)
echo "$iam_ip keycloak.it.just.works $HOSTS_FILE_IDENTIFIER" >> /etc/hosts

iam_extra_ip=$(get_svc_external_ip openstack-iam-keycloak-http iam-extra)
echo "$iam_extra_ip keycloak-extra.it.just.works $HOSTS_FILE_IDENTIFIER" >> /etc/hosts
