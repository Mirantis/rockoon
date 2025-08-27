# Configuration Openstack with Masakari

This article describes how to configure Instance High Availability service with Openstack CLI.
Before continuing please make sure that the Masakari and its components are enabled in the
system as it described in the [article](../../../architecture/cloud_services/masakari.md)

### **Group compute nodes into segments**

The segment object is a logical grouping of compute nodes into zones also known as availability
zones. The segment object enables the cloud operator to list, create, show details for, update,
and delete segments.

To create a segment named `allcomputes` with service_type = `compute`, and recovery_method = `auto`, run:

```shell
openstack segment create allcomputes auto compute
```

### **Create hosts under segments**

The host object represents compute service hypervisors. A host belongs to a segment. The host can
be any kind of virtual machine that has compute service running on it. The host object enables the
operator to list, create, show details for, update, and delete hosts.

To create a host under a given segment:

1. Obtain the hypervisor hostname:
```shell
openstack hypervisor list
```
2. Create the host under previously created segment.
```shell
openstack segment host create \
    <hypervisor hostname> \
    compute \
    SSH \
    <segment>
```
where:
    * `<hypervisor hostname>` - hostname from the command's result on step 1.
    * `<segment>` - name or UUID of existing segment, created in previous section

For example:
```shell
openstack segment host create \
    test-host-1 \
    compute \
    SSH \
    b8b0d7ca-1088-49db-a1e2-be004522f3d1

```

### **Requirements for the introspective instance monitor**

For the introspective instance monitor to work correctly, the following conditions must be met:

1. The images used to create the virtual machines have the `hw_qemu_guest_agent=yes` property set.
To set it, you must run the command:
```shell
openstack image set --property hw_qemu_guest_agent=yes Ubuntu-18.04
```
where `Ubuntu-18.04` is the name of the image for which you want to set the property.
2. Virtual machines must be created with the `HA_Enabled=True` property set
```shell
openstack server create --flavor <FLAVOR> \
                        --image <IMAGE> \
                        --network <NETWORK> \
                        --property HA_Enabled=True \
                        <SERVER_NAME>
```
3. QEMU Guest Agent must be installed in the virtual machine after it is launched.
