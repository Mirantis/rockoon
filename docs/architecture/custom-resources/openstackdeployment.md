# OpenStackDeployment Custom Resource

Custom Kubernetes resource that describes OpenStack deployment.

```bash
kubectl get crd openstackdeployments.lcm.mirantis.com -o yaml
```

```bash
kubectl -n openstack get osdpl -o yaml
```

Example of OpenStackDeployment minimal configuration

```yaml
apiVersion: lcm.mirantis.com/v1alpha1
kind: OpenStackDeployment
metadata:
  annotations:
  name: osh-dev
  namespace: openstack
spec:
  features:
    glance:
      backends:
        file:
          pvcstore:
            default: true
            pvc:
              size: 10Gi
              storage_class_name: lvp-fake-root
    network_policies:
      enabled: false
    neutron:
      external_networks:
      - bridge: br-ex
        interface: veth-phy
        network_types:
        - flat
        physnet: physnet1
      floating_network:
        enabled: true
        physnet: physnet1
        subnet:
          gateway: 10.11.12.11
          pool_end: 10.11.12.200
          pool_start: 10.11.12.100
          range: 10.11.12.0/24
      tunnel_interface: ens3
    nova:
      images:
        backend: local
      live_migration_interface: ens3
    services: []
    ssl:
      public_endpoints:
        api_cert:
          value_from:
            secret_key_ref:
              key: api_cert
              name: osh-dev-hidden
        api_key:
          value_from:
            secret_key_ref:
              key: api_key
              name: osh-dev-hidden
        ca_cert:
          value_from:
            secret_key_ref:
              key: ca_cert
              name: osh-dev-hidden
  local_volume_storage_class: lvp-fake-root
  openstack_version: caracal
  persistent_volume_storage_class: lvp-fake-root
  preset: core
  public_domain_name: it.just.works
  size: single
```

## Main osdpl elements

Main elements of OpenStackDeployment custom resource

- `spec.openstack_version`: Specifies the OpenStack release to deploy
- `spec.preset`: String that specifies the name of the preset, a predefined configuration for the OpenStack cluster. A preset includes:
    * A set of enabled services that includes virtualization, bare metal management, secret management, and others
    * Major features provided by the services, such as VXLAN encapsulation of the tenant traffic
- `spec.size`: String that specifies the size category for the OpenStack cluster. The size category defines the internal configuration
  of the cluster such as the number of replicas for service workers and timeouts, etc.
  The list of supported sizes include:
    * `single`: single node installation
    * `tiny`: for approximately 10 OpenStack Compute nodes
    * `small`:  for approximately 50 OpenStack Compute nodes
    * `medium`: for approximately 300+ OpenStack Compute nodes  
- `spec.public_domain_name`: Specifies the public DNS name for OpenStack services. This is a base DNS name that must be accessible and
  resolvable by API clients of your OpenStack cloud. It will be present in the OpenStack endpoints as presented by the OpenStack Identity
  service catalog. The TLS certificates used by the OpenStack services (see below) must also be issued to this DNS name. 
- `spec.features`: Contains the top-level collections of settings for the OpenStack deployment that potentially target several OpenStack services.
  The section where the customizations should take place.

## Handling sensitive information

The `OpenStackDeployment` custom resource enables you to securely store sensitive fields in [Kubernetes secrets](https://kubernetes.io/docs/concepts/configuration/secret/).
To do that, verify that the reference secret is present in the same namespace as the `OpenStackDeployment`
object and the `openstack.lcm.mirantis.com/osdpl_secret` label is set to `true`. The list of fields that can be
hidden from `OpenStackDeployment` is limited and defined by the `OpenStackDeployment` schema.

For example, to hide spec:features:ssl:public_endpoints:api_cert, use the following structure:

```yaml
spec:
  features:
    ssl:
      public_endpoints:
        api_cert:
          value_from:
            secret_key_ref:
              key: api_cert
              name: osh-dev-hidden
```
