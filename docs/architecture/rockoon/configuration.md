# Configuration

The OpenStack Controller enables you to modify its configuration at runtime without restarting. MOSK stores the controller configuration
in the `openstack-controller-config` `ConfigMap` in the osh-system namespace of your cluster.

To retrieve the OpenStack Controller configuration `ConfigMap`, run:

```bash
kubectl get configmaps openstack-controller-config -o yaml
```

Example of OpenStackController configuration

```yaml
apiVersion: v1
data:
  extra_conf.ini: |
    [maintenance]
    respect_nova_az = false
kind: ConfigMap
metadata:
  annotations:
    openstackdeployments.lcm.mirantis.com/skip_update: "true"
  name: openstack-controller-config
  namespace: osh-system
```

```ini
[osctl]
# The number of seconds to wait for all component from application becomes ready
wait_application_ready_timeout = 1200

# The number of seconds to sleep between checking application ready attempts
wait_application_ready_delay = 10

# The amount of time to wit for flapping node
node_not_ready_flapping_timeout = 120

[helmbundle]
# The number of seconds to wait for values set in manifest are propagated to child objects.
manifest_enable_timeout = 600

# The number of seconds between attempts to check that values were applied.
manifest_enable_delay = 10

# The number of seconds to wait for values are removed from manifest and propagated to child objects.
manifest_disable_timeout = 600

# The number of seconds between attempts to check that values were removed from release.
manifest_disable_delay = 10

# The number of seconds to wait for kubernetes object removal
manifest_purge_timeout = 600

# The number of seconds between attempts to check that kubernetes object is removed
manifest_purge_delay = 10

# The number of seconds to pause for helmbundle changes
manifest_apply_delay = 10

# The number of seconds to run for helm command
helm_cmd_timeout = 120

[maintenance]
# number of instances to migrate concurrently
instance_migrate_concurrency = 1

# max number of compute nodes we allow to update in parallel
nwl_parallel_max_compute = 30

# max number of gateway nodes we allow to update in parallel
nwl_parallel_max_gateway = 1

# respect nova AZs, when set to true parallel update is allowed only for computes in same AZ
respect_nova_az = True

# flag to skip instance check on host before proceeding with node removal. By default is False
# which means that node removal will be blocked unless at least 1 instance exists on host.
ndr_skip_instance_check = False

# flag to skip volume check on host before proceeding with node removal. By default is False
# which means that node removal will be blocked unless at least 1 volume exists on host.
# Volume is tied to specific host only for LVM backend.
ndr_skip_volume_check = False
```