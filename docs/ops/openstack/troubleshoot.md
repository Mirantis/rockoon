# Troubleshooting

This section provides the general debugging instructions for your OpenStack on Kubernetes deployment. Start
your troubleshooting with the determination of the failing component that can include the Rockoon Operator,
Helm, a particular pod or service.

!!! note
    For Kubernetes cluster debugging and troubleshooting, refer to [Kubernetes official documentation: Troubleshoot clusters](https://kubernetes.io/docs/tasks/debug-application-cluster/debug-cluster/)

## Debugging the Helm releases

1. Log in to the `rockoon` pod, where the Helm v3 client is installed, or download the Helm v3 binary locally:
```bash
kubectl -n osh-system exec -it deployment/rockoon -- bash
```
2. Verify the Helm releases statuses:
```bash
helm3 --namespace openstack list --all
```
Example of output:
```bash
NAME                            NAMESPACE       REVISION        UPDATED                                 STATUS          CHART                           APP VERSION
etcd                            openstack       4               2021-07-09 11:06:25.377538008 +0000 UTC deployed        etcd-0.1.0-mcp-2735
ingress-openstack               openstack       4               2021-07-09 11:06:24.892822083 +0000 UTC deployed        ingress-0.1.0-mcp-2735
openstack-barbican              openstack       4               2021-07-09 11:06:25.733684392 +0000 UTC deployed        barbican-0.1.0-mcp-3890
openstack-ceph-rgw              openstack       4               2021-07-09 11:06:25.045759981 +0000 UTC deployed        ceph-rgw-0.1.0-mcp-2735
openstack-cinder                openstack       4               2021-07-09 11:06:42.702963544 +0000 UTC deployed        cinder-0.1.0-mcp-3890
openstack-designate             openstack       4               2021-07-09 11:06:24.400555027 +0000 UTC deployed        designate-0.1.0-mcp-3890
openstack-glance                openstack       4               2021-07-09 11:06:25.5916904   +0000 UTC deployed        glance-0.1.0-mcp-3890
openstack-heat                  openstack       4               2021-07-09 11:06:25.3998706   +0000 UTC deployed        heat-0.1.0-mcp-3890
openstack-horizon               openstack       4               2021-07-09 11:06:23.27538297  +0000 UTC deployed        horizon-0.1.0-mcp-3890
openstack-iscsi                 openstack       4               2021-07-09 11:06:37.891858343 +0000 UTC deployed        iscsi-0.1.0-mcp-2735            v1.0.0
openstack-keystone              openstack       4               2021-07-09 11:06:24.878052272 +0000 UTC deployed        keystone-0.1.0-mcp-3890
openstack-libvirt               openstack       4               2021-07-09 11:06:38.185312907 +0000 UTC deployed        libvirt-0.1.0-mcp-2735
openstack-mariadb               openstack       4               2021-07-09 11:06:24.912817378 +0000 UTC deployed        mariadb-0.1.0-mcp-2735
openstack-memcached             openstack       4               2021-07-09 11:06:24.852840635 +0000 UTC deployed        memcached-0.1.0-mcp-2735
openstack-neutron               openstack       4               2021-07-09 11:06:58.96398517  +0000 UTC deployed        neutron-0.1.0-mcp-3890
openstack-neutron-rabbitmq      openstack       4               2021-07-09 11:06:51.454918432 +0000 UTC deployed        rabbitmq-0.1.0-mcp-2735
openstack-nova                  openstack       4               2021-07-09 11:06:44.277976646 +0000 UTC deployed        nova-0.1.0-mcp-3890
openstack-octavia               openstack       4               2021-07-09 11:06:24.775069513 +0000 UTC deployed        octavia-0.1.0-mcp-3890
openstack-openvswitch           openstack       4               2021-07-09 11:06:55.271711021 +0000 UTC deployed        openvswitch-0.1.0-mcp-2735
openstack-placement             openstack       4               2021-07-09 11:06:21.954550107 +0000 UTC deployed        placement-0.1.0-mcp-3890
openstack-rabbitmq              openstack       4               2021-07-09 11:06:25.431404853 +0000 UTC deployed        rabbitmq-0.1.0-mcp-2735
openstack-tempest               openstack       2               2021-07-09 11:06:21.330801212 +0000 UTC deployed        tempest-0.1.0-mcp-3890
```

## Debugging the Rockoon Controller

The Rockoon Controller is running in several containers in the `rockoon-xxxx` pod in the
`osh-system` namespace.

To verify the status of the Rockoon Controller, run:
```bash
kubectl -n osh-system get pods
```

Example of a system response:
```bash
NAME                                  READY   STATUS    RESTARTS   AGE
rockoon-5c6947c996-vlrmv            5/5     Running     0          17m
rockoon-admission-f946dc8d6-6bgn2   1/1     Running     0          4h9m
rockoon-ensure-resources-5ls8k        0/1     Completed   0          4h12m
```

To verify the logs for the `osdpl` container, run:
```bash
kubectl -n osh-system logs -f <rockoon-xxxx> -c osdpl
```

## Some pods are stuck in `Init`

MOSK uses the Kubernetes entrypoint init container to resolve dependencies between objects. If the pod is stuck in Init:0/X, this pod may be waiting for its dependencies.

Verify the missing dependencies:
```bash
kubectl -n openstack logs -f placement-api-84669d79b5-49drw -c init
```

Example of a system response:
```bash
Entrypoint WARNING: 2020/04/21 11:52:50 entrypoint.go:72: Resolving dependency Job placement-ks-user in namespace openstack failed: Job Job placement-ks-user in namespace openstack is not completed yet .
Entrypoint WARNING: 2020/04/21 11:52:52 entrypoint.go:72: Resolving dependency Job placement-ks-endpoints in namespace openstack failed: Job Job placement-ks-endpoints in namespace openstack is not completed yet .
```
