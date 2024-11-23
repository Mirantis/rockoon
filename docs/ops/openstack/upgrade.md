# Upgrade OpenStack

This section provides instructions on how to upgrade OpenStack to a major version with help of
OpenStack Controller.

1. To start the OpenStack upgrade, change the value of the `spec:openstack_version` parameter in the `OpenStackDeployment` object to the target OpenStack release.
   After you change the value of the `spec:openstack_version` parameter, the OpenStack Controller initializes the upgrade process.

2. Verify the upgrade status
   ```bash
   kubectl -n openstack get osdplst
   ```
   Example of output
   ```bash
   NAME      OPENSTACK VERSION   CONTROLLER VERSION   STATE     LCM PROGRESS   HEALTH   MOSK RELEASE
   osh-dev   antelope             0.17.2.dev250        APPLYING   1/11          13/15 
   ```
   When upgrade finishes, the `STATE` field should display `APPLIED`:
   ```bash
   kubectl -n openstack get osdplst
   NAME      OPENSTACK VERSION   CONTROLLER VERSION   STATE     LCM PROGRESS   HEALTH   MOSK RELEASE
   osh-dev   caracal             0.17.2.dev250        APPLIED   11/11          15/15
   ```
   
3. Verify the Upgrade
   * Verify that OpenStack is healthy and operational. All OpenStack components in the `health` group in the
     [OpenStackDeploymentStatus](../../../architecture/custom-resources/openstackdeploymentstatus/) CR should be in the `Ready` state.
   * Verify the workability of your OpenStack deployment by running Tempest against the OpenStack cluster as described in [Run Tempest tests](./tempest.md).
