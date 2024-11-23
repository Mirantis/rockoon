# Access OpenStack

## CLI

You can use the built-in admin CLI client and execute the openstack commands from a dedicated pod deployed in the `openstack` namespace:

```bash
kubectl -n openstack exec -it deployment/keystone-client -- bash
```

To obtain admin credentials run:

```bash
kubectl -n openstack exec -it deployment/keystone-client -- bash
cat /etc/openstack/clouds.yaml
```

## Horizon

1. Get IP address of ingress service
```bash
kubectl -n openstack get svc ingress -o jsonpath='{.status.loadBalancer.ingress[].ip}'
```
2. Update local `/etc/hosts` file to point public domain to ingress external IP
```bash
10.172.1.100 aodh.it.just.works barbican.it.just.works cinder.it.just.works cloudformation.it.just.works designate.it.just.works glance.it.just.works gnocchi.it.just.works heat.it.just.works horizon.it.just.works keystone.it.just.works metadata.it.just.works neutron.it.just.works nova.it.just.works novncproxy.it.just.works octavia.it.just.works placement.it.just.works spiceproxy.it.just.works
```
4. Stup `sshuttle` to services external IPs
```bash
sshuttle -r ubuntu@172.16.250.153 10.172.1.0/24
```
3. Access to Horizon through web browser [https://horizon.it.just.works](https://horizon.it.just.works)
