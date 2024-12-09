from rockoon import kube
from rockoon.tests.functional import base
from rockoon.tests.functional import waiters


class BaseFunctionalNodeMaintenanceTestCase(base.BaseFunctionalTestCase):
    def setUp(self):
        super().setUp()
        # Required for tags
        self.ocm.oc.compute.default_microversion = "2.90"

    def set_node_annotations(self, node, annotations):
        node.reload()
        node_annotations = node.annotations
        node_annotations.update(annotations)
        node.obj["metadata"]["annotations"] = node_annotations
        node.update()

    def set_node_instance_migration_mode(self, node, mode):
        orig_migration_mode = node.annotations.get(
            "openstack.lcm.mirantis.com/instance_migration_mode", None
        )
        self.set_node_annotations(
            node, {"openstack.lcm.mirantis.com/instance_migration_mode": mode}
        )
        self.addCleanup(
            self.set_node_annotations,
            node,
            {
                "openstack.lcm.mirantis.com/instance_migration_mode": orig_migration_mode
            },
        )

    def delete_nmr(self, host, wait=True):
        nmr = kube.find(kube.NodeMaintenanceRequest, host, silent=True)
        if nmr and nmr.exists():
            self.logger.info(f"Removing nwl for {host}")
            nmr.delete()
            if wait:
                waiters.wait_k8s_obj_absent(nmr)
        else:
            self.logger.info(f"The nwl for {host} not found")

    def create_nmr(self, host, scope):
        nmr = kube.dummy(kube.NodeMaintenanceRequest, host)
        nmr.obj["spec"] = {"scope": scope, "nodeName": host}
        nmr.create()
        self.addCleanup(self.delete_nmr, host)

    def server_add_tags(self, server_id, tags):
        self.ocm.oc.compute.put(
            f"/servers/{server_id}/tags", json={"tags": tags}
        )
