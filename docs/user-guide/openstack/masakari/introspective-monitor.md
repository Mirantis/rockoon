# Introspective instance monitor configuration and test

This section describes how to test the `introspective instance monitor`.

**1\. Enable the introspective instance monitor**

To deploy Masakari and enable the introspective instance monitor refer to
[Instance HA documentation](../../../architecture/cloud_services/masakari.md)

**2\. Wait for the deployment to complete**

Wait for the `OpenStackDeploymentStatus` object reaches the **APPLIED** state and all
applications are **healthy**. Please refer to
[OpenStackDeploymentStatus Custom Resource](../../../architecture/custom-resources/openstackdeploymentstatus.md)
for more information.

**3\. Create RSA keys for the test instance**

Generate an RSA key pair for the test instance you will create in the next step,
and copy the public key to the `keystone-client` pod.

```shell
ssh-keygen -C '' -N '' -f test_key
keystone_pod=$(kubectl --namespace openstack get pod -l application=keystone,component=client --output jsonpath='{.items[0].metadata.name}')
kubectl cp test_key.pub openstack/${keystone_pod}:/tmp/
```

**4\. Access the keystone-client pod**

Enter the `keystone-client` pod to perform OpenStack operations:

```shell
kubectl --namespace openstack exec -ti deployment/keystone-client -- bash
```

**5\. Configure OpenStack for Masakari service**

Inside the pod, run:

```shell
SEGMENT_UUID=$(openstack segment create allcomputes auto compute -f value -c uuid 2>/dev/null)
for host in $(openstack hypervisor list -f value -c "Hypervisor Hostname" 2>/dev/null); do \
    openstack segment host create ${host} compute SSH ${SEGMENT_UUID}; \
done
openstack image set --property hw_qemu_guest_agent=yes Ubuntu-18.04
```
For more information about the commands executed, please refer to the
[user guide](masakari-configuration.md)

**6\. Create a test instance**

Still inside the pod, execute:

```shell
openstack keypair create --public-key /tmp/test_key.pub test_key
openstack network create test_net
openstack subnet create test_subnet --network test_net --subnet-range 192.0.2.0/24 --allocation-pool start=192.0.2.2,end=192.0.2.20
openstack router create test_router
openstack router set test_router --external-gateway public
openstack router add subnet test_router test_subnet
openstack security group create test_sg
openstack security group rule create test_sg --remote-ip 0.0.0.0/0
openstack floating ip create --floating-ip-address 10.11.12.119 public
openstack server create --image Ubuntu-18.04 --flavor m1.small --key-name test_key --network test_net --security-group test_sg --property HA_Enabled=True test_server
openstack server add floating ip test_server 10.11.12.119
```

**7\. Connect to the test instance**

Exit the `keystone-client` pod and connect to the new instance using its floating IP and the RSA private key created in step 3:

```shell
ssh -l ubuntu -i test_key 10.11.12.119
```

**8\. Install and verify QEMU guest agent**

On the instance, run:

```shell
sudo apt update
sudo apt install qemu-guest-agent
systemctl status qemu-guest-agent
```

**9\. Test Masakari functionality**

To simulate a system crash, stop the `qemu-guest-agent` service on the instance:

```shell
sudo systemctl stop qemu-guest-agent
```

Within approximately **40 seconds**, Masakari should detect the issue and restart the instance.
