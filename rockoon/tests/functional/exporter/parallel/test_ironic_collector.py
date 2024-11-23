import pytest
import unittest

from rockoon.exporter import constants
from rockoon.tests.functional.exporter import base


@pytest.mark.xdist_group("exporter-ironic")
class IronicCollectorFunctionalTestCase(base.BaseFunctionalExporterTestCase):
    scrape_collector = "osdpl_ironic"

    def setUp(self):
        super().setUp()
        if not self.is_service_enabled("baremetal"):
            raise unittest.SkipTest("Baremetal service is not enabled")

    def test_total_nodes_metric_present(self):
        metric = self.get_metric("osdpl_ironic_nodes")
        self.assertIsNotNone(metric)
        self.assertEqual(1, len(metric.samples))

    def test_total_nodes_value(self):
        metric_name = "osdpl_ironic_nodes"
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        baremetal_nodes = len(list(self.ocm.oc.baremetal.nodes()))
        self.assertEqual(baremetal_nodes, metric.samples[0].value)

        self.assertCountEqual(
            [],
            metric.samples[0].labels.keys(),
        )

    def test_ironic_node_info(self):
        """Information about baremetal nodes in the cluster.

        **Steps**

        #. Get `osdpl_ironic_node_info` metric with initial number
        #. Add additional baremetal node
        #. Check that new baremetal node appear in the samples
        #. Check that new baremetal node appears with exact labels in the samples
        #. Remove baremetal node
        #. Check baremetal node dissappear from the samples
        """
        metric_name = "osdpl_ironic_node_info"
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        baremetal_nodes = list(self.ocm.oc.baremetal.nodes())
        self.assertEqual(
            len(metric.samples),
            len(baremetal_nodes),
            "The initial number of baremetal nodes is not correct.",
        )

        node = self.baremetal_node_create()
        metric_after_create_node = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            len(metric_after_create_node.samples),
            len(baremetal_nodes) + 1,
            "The number of nodes after node create is not correct.",
        )
        samples = self.filter_metric_samples(
            metric_after_create_node, {"uuid": node["uuid"]}
        )
        self.assertCountEqual(
            ["uuid", "name"],
            samples[0].labels.keys(),
        )
        self.assertEqual(
            node["uuid"],
            samples[0].labels["uuid"],
            "The baremetal node metric label uuid is not correct.",
        )
        self.assertEqual(
            node["name"] or "None",
            samples[0].labels["name"],
            "The baremetal node metric label name is not correct.",
        )

        self.delete_baremetal_node(node["uuid"], wait=True)
        metric_after_delete_node = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            len(metric_after_delete_node.samples),
            len(baremetal_nodes),
            "The number of nodes after node delete is not correct.",
        )

    def test_ironic_node_maintenance(self):
        """Check maintenance status of the baremetal nodes in the cluster.

        **Steps**

        #. Add additional baremetal node
        #. Check current maintenance status
        #. Set node in maintenance
        #. Check that maintenance status metric has changed
        #. Remove baremetal node
        """
        metric_name = "osdpl_ironic_node_maintenance"
        node = self.baremetal_node_create()
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        samples = self.filter_metric_samples(metric, {"uuid": node["uuid"]})
        self.baremetal_node_maintenance_set(node["uuid"])
        metric_after_maintenance_set = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        after_set_samples = self.filter_metric_samples(
            metric_after_maintenance_set, {"uuid": node["uuid"]}
        )
        self.assertNotEqual(
            samples[0].value,
            after_set_samples[0].value,
            f"Maintenance status of the node:{node['name']} is not changed.",
        )
        self.assertEqual(
            1,
            after_set_samples[0].value,
            f"Maintenance status of the node:{node['name']} is not correct.",
        )
        self.delete_baremetal_node(node["uuid"], wait=True)

    def test_ironic_node_provision_state(self):
        """Check provision state of the baremetal nodes in the cluster.

        **Steps**

        #. Add additional baremetal node
        #. Check current provision state
        #. Set provision state "manageable"
        #. Check that provision state metric has changed
        #. Remove baremetal node
        """
        metric_name = "osdpl_ironic_node_provision_state"
        test_provision_state = {
            "arg": "manage",
            "state": "manageable",
        }
        node = self.baremetal_node_create()
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        samples = self.filter_metric_samples(metric, {"uuid": node["uuid"]})
        self.baremetal_node_set_provision_state(
            node["uuid"], test_provision_state["arg"]
        )
        metric_after_pr_state_set = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        after_set_samples = self.filter_metric_samples(
            metric_after_pr_state_set, {"uuid": node["uuid"]}
        )
        self.assertNotEqual(
            samples[0].value,
            after_set_samples[0].value,
            f"Provision state of the node:{node['name']} is not changed.",
        )
        self.assertEqual(
            constants.BAREMETAL_NODE_PROVISION_STATE.get(
                test_provision_state["state"]
            ),
            after_set_samples[0].value,
            f"Provision state of the node:{node['name']} is not correct.",
        )
        self.delete_baremetal_node(node["uuid"], wait=True)
