# Customize images

OpenStack Controller has default built in images that were verified against different
production configurations. However it may be needed to inclide additional patches
into openstack code or 3rd party software.

OpenStack images are built with help of [Loci](https://github.com/openstack/loci).
Please refer to its documentation to get more detail about build process.

To inject a custom image create configmap with `<openstackdeployment-name>-artifacts` name
in `openstack` namespace and folling data structure:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: osh-dev-artifacts
  namespace: openstack
data:
  caracal: |
    libvirt: docker-dev-kaas-virtual.mcp.mirantis.com/general/libvirt:6.0.0-focal-20221028120749
  antelope: |
    libvirt: docker-dev-kaas-virtual.mcp.mirantis.com/general/libvirt:6.0.0-focal-20221028120749
```
