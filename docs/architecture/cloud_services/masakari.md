# Instance High Availability service (OpenStack Masakari)

This article describes operations with Instance High Availability (Instance HA).

The Instance High Availability service (OpenStack Masakari) allows cloud users
to ensure that their instances are automatically evacuated from a failed
hypervisor. It provides several types of monitoring services:

* `Instance monitor` — checks the liveness of instance processes.
* `Introspective instance monitor` — improves instance high availability within
  OpenStack environments by monitoring and identifying system-level failures
  through the QEMU Guest Agent.
* `Host monitor` — checks the liveness of compute hosts and runs as part of the
  Node Controller in Rockoon.

The `introspective instance monitor` is disabled by default and must be
explicitly enabled in the Masakari configuration.

### **Enabling the Instance HA service**

To enable the Instance HA service your need to add `instance-ha` to the service
list in [OpenStackDeployment](../custom-resources/openstackdeployment.md) custom
resource:

```
spec:
  features:
    services:
      - instance-ha
```

### **Enabling introspective instance monitor**

To enable the introspective instance monitor in the Masakari service, update the
`spec:features:masakari:monitors:introspective` section in
[OpenStackDeployment](../custom-resources/openstackdeployment.md) custom resource:

```
spec:
  features:
    masakari:
      monitors:
        introspective:
          enabled: true
```
