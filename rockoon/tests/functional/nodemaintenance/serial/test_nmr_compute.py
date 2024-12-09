import pytest

from rockoon import kube

from rockoon.tests.functional.nodemaintenance import base
from rockoon.tests.functional import waiters


class TestNodeMaintenanceMigrationModes(
    base.BaseFunctionalNodeMaintenanceTestCase
):
    """Test class to check maintenance mode on compute

    Setup check:
      * Make sure all nwls are active
      * Make sure we do not have nmr
      * Make sure we do not have instances

    """

    def setUp(self):
        super().setUp()
        self.servers = []

        # Tags require 2.26 compute microversion, pin to yoga
        self.ocm.oc.compute.default_microversion = "2.90"

        # Wait nwl for all hosts are in active state
        for node in kube.Node.objects(self.kube_api):
            nwl_name = f"openstack-{node.name}"
            nwl = kube.find(kube.NodeWorkloadLock, nwl_name, silent=True)
            if not nwl or not nwl.exists():
                continue
            waiters.wait_nwl_state(nwl, "active")
            nmr = kube.find(
                kube.NodeMaintenanceRequest, node.name, silent=True
            )
            self.assertIsNone(nmr)

        # Wait no instances is present on the host
        for cmp_svc in self.ocm.oc.compute.services(binary="nova-compute"):
            waiters.wait_compute_is_empty(self.ocm.oc, cmp_svc.host)

        # Wait all compute services are up and enabled
        for cmp_svc in self.ocm.oc.compute.services(binary="nova-compute"):
            waiters.wait_compute_service_state(
                self.ocm.oc, cmp_svc.host, "up", "enabled"
            )

        srv0 = self.server_create()
        self.servers.append(srv0)
        host = self.ocm.oc.get_server(srv0.id)["compute_host"]
        srv1 = self.server_create(availability_zone=f"nova:{host}")
        self.servers.append(srv1)

        self.k8s_node = kube.find(kube.Node, host)
        self.k8s_nwl = kube.find(
            kube.NodeWorkloadLock, f"openstack-{self.k8s_node.name}"
        )

    def tearDown(self):
        super().tearDown()
        for srv in self.servers:
            self.server_delete(srv)

    def test_compute_node_migration_mode_skip(self):
        """Test maintenance for compute in skip mode

        1. Create 2 instances on same compute host
        2. Set openstack.lcm.mirantis.com/instance_migration_mode=skip on compute
        3. Create nmr
        4. Wait nwl become inactive
        5. Check instances are not migrated

        """

        host = self.k8s_node.name
        self.set_node_instance_migration_mode(self.k8s_node, "skip")

        # Create nmr
        self.logger.info(f"Creating nodemaintenance request for node {host}")
        self.create_nmr(host, "os")

        # Wait nwl is inactive
        self.logger.info(
            f"Waiting nodeworkloadlock is inactive for host: {host}"
        )
        waiters.wait_nwl_state(self.k8s_nwl, "inactive")
        waiters.wait_compute_service_state(
            self.ocm.oc, host, "up", "disabled", timeout=10
        )

        # Check instances not migrated
        self.logger.info(
            f"Check that instances are still running on old computes host."
        )
        for srv in self.servers:
            srv_host = self.ocm.oc.get_server(srv.id)["compute_host"]
            self.assertEqual(host, srv_host, f"Server {srv.id} host changed.")
        self.delete_nmr(host)

    def test_compute_node_migration_mode_live(self):
        """Test maintenance for compute in live mode

        Requirements:
        * At least 2 compute nodes

        1. Create 2 instances on same compute host
        2. Set openstack.lcm.mirantis.com/instance_migration_mode=live on compute
        3. Create nmr
        4. Wait nwl become inactive
        5. Check instances are migrated

        """
        if len(list(self.ocm.oc.compute.hypervisors())) < 2:
            pytest.skip("Test require more than 2 compute hosts.")

        host = self.k8s_node.name
        self.set_node_instance_migration_mode(self.k8s_node, "live")

        # Create nmr
        self.logger.info(f"Creating nodemaintenance request for node {host}")
        self.create_nmr(host, "os")

        # Wait nwl is inactive
        self.logger.info(
            f"Waiting nodeworkloadlock is inactive for host: {host}"
        )
        waiters.wait_nwl_state(self.k8s_nwl, "inactive")
        waiters.wait_compute_service_state(
            self.ocm.oc, host, "up", "disabled", timeout=10
        )

        # Check instances not migrated
        self.logger.info(
            f"Check that instances are still running on old computes host."
        )
        for srv in self.servers:
            srv_host = self.ocm.oc.get_server(srv.id)["compute_host"]
            self.assertNotEqual(
                host, srv_host, f"Server {srv.id} host changed."
            )
        self.delete_nmr(host)

    def test_compute_node_migration_mode_manual(self):
        """Test maintenance for compute in manual mode

        1. Create 2 instances on same compute host
        2. Set openstack.lcm.mirantis.com/instance_migration_mode=manual on compute
        3. Create nmr
        4. Ensure timeout exception occurs during wait nwl become inactive
        5. Check instances are not migrated

        """
        host = self.k8s_node.name
        self.set_node_instance_migration_mode(self.k8s_node, "manual")

        # Create nmr
        self.logger.info(f"Creating nodemaintenance request for node {host}")
        self.create_nmr(host, "os")

        # Wait nwl is inactive
        self.logger.info(
            f"Waiting nodeworkloadlock is inactive for host: {host}"
        )
        with pytest.raises(TimeoutError):
            waiters.wait_nwl_state(self.k8s_nwl, "inactive")
        waiters.wait_compute_service_state(
            self.ocm.oc, host, "up", "disabled", timeout=10
        )

        # Check instances not migrated
        self.logger.info(
            f"Check that instances are still running on old computes host."
        )
        for srv in self.servers:
            srv_host = self.ocm.oc.get_server(srv.id)["compute_host"]
            self.assertEqual(host, srv_host, f"Server {srv.id} host changed.")
        self.delete_nmr(host)

    def test_compute_node_migration_mode_manual_instance_override_on_all(self):
        """Test maintenance for compute in manual mode with instance specific settings

        Requirements:
        * At least 2 compute nodes

        1. Create 2 instances on same compute host, both with tag
           openstack.lcm.mirantis.com:maintenance_action=poweroff
        2. Set openstack.lcm.mirantis.com/instance_migration_mode=manual on compute
        3. Create nmr
        4. Wait nwl become inactive
        5. Check instances are not migrated

        """

        host = self.k8s_node.name
        for srv in self.servers:
            self.server_add_tags(
                srv.id,
                ["openstack.lcm.mirantis.com:maintenance_action=poweroff"],
            )

        self.set_node_instance_migration_mode(self.k8s_node, "manual")

        # Create nmr
        self.logger.info(f"Creating nodemaintenance request for node {host}")
        self.create_nmr(host, "os")

        # Wait nwl is inactive
        self.logger.info(
            f"Waiting nodeworkloadlock is inactive for host: {host}"
        )
        waiters.wait_nwl_state(self.k8s_nwl, "inactive")
        waiters.wait_compute_service_state(
            self.ocm.oc, host, "up", "disabled", timeout=10
        )

        # Check instances not migrated
        self.logger.info(
            f"Check that instances are still running on old computes host."
        )
        for srv in self.servers:
            srv_host = self.ocm.oc.get_server(srv.id)["compute_host"]
            self.assertEqual(host, srv_host, f"Server {srv.id} host changed.")
        self.delete_nmr(host)

    def test_compute_node_migration_mode_manual_instance_override_on_some(
        self,
    ):
        """Test maintenance for compute in skip mode and one of instances with specific configuration

        1. Create 2 instances on same compute host. One of instances contains tag
           openstack.lcm.mirantis.com:maintenance_action=live which should block nmr handling.
        2. Set openstack.lcm.mirantis.com/instance_migration_mode=skip on compute
        3. Create nmr
        4. Ensure timeout exception occurs during wait nwl become inactive
        5. Check instances with tag maintenance_action=live is not migrated.
           Check instance without tags is migrated

        """
        if len(list(self.ocm.oc.compute.hypervisors())) < 2:
            pytest.skip("Test require more than 2 compute hosts.")

        host = self.k8s_node.name
        self.server_add_tags(
            self.servers[0].id,
            ["openstack.lcm.mirantis.com:maintenance_action=notify"],
        )

        self.set_node_instance_migration_mode(self.k8s_node, "skip")

        # Create nmr
        self.logger.info(f"Creating nodemaintenance request for node {host}")
        self.create_nmr(host, "os")

        # Wait nwl is inactive
        self.logger.info(
            f"Waiting nodeworkloadlock is inactive for host: {host}"
        )
        with pytest.raises(TimeoutError):
            waiters.wait_nwl_state(self.k8s_nwl, "inactive")
        waiters.wait_compute_service_state(
            self.ocm.oc, host, "up", "disabled", timeout=10
        )

        # Check instances not migrated
        self.logger.info(
            f"Check that instances are still running on old computes host."
        )
        for srv in self.servers:
            srv_host = self.ocm.oc.get_server(srv.id)["compute_host"]
            self.assertEqual(host, srv_host, f"Server {srv.id} host changed.")
        self.delete_nmr(host)
