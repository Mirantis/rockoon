# Run tempest tests

The OpenStack Integration Test Suite (Tempest), is a set of integration tests to be run against a live OpenStack
environment. This section instructs you on how to verify the workability of your OpenStack deployment using
Tempest.

To verify an OpenStack deployment using Tempest:

1. Add `tempest` to `spec:features:services` in `OpenStackDeployment` custom resource.
2. Wait until Tempest is ready. The Tempest tests are launched by the `openstack-tempest-run-tests` job. To
   keep track of the tests execution, run:
   ```bash
   kubectl -n openstack logs -l application=tempest,component=run-tests
   ```
3. Get the Tempest results. The Tempest results can be stored in a `pvc-tempest` PersistentVolumeClaim (PVC).
   To get them from a PVC, use:
   ```bash
   # Run pod and mount pvc to it
   cat <<EOF | kubectl apply -f -
   apiVersion: v1
   kind: Pod
   metadata:
     name: tempest-test-results-pod
     namespace: openstack
   spec:
     nodeSelector:
       openstack-control-plane: enabled
     volumes:
       - name: tempest-pvc-storage
         persistentVolumeClaim:
           claimName: pvc-tempest
     containers:
       - name: tempest-pvc-container
         image: ubuntu
         command: ['sh', '-c', 'sleep infinity']
         volumeMounts:
           - mountPath: "/var/lib/tempest/data"
             name: tempest-pvc-storage
   EOF
   ```

To rerun tempest:

1. Remove `tempest` from the list of enabled services.
2. Wait until Tempest jobs are removed.
3. Add `tempest` back to the list of the enabled services.
