import pytest
import unittest
from uuid import uuid4

from rockoon import constants
from rockoon.tests.functional.exporter import base
from packaging.version import Version

RESOURCES = {"VCPU": 1, "MEMORY_MB": 64, "DISK_GB": 1}


@pytest.mark.xdist_group("exporter-compute-network")
class NovaAuditCollectorFunctionalTestCase(
    base.BaseFunctionalExporterTestCase
):
    scrape_collector = "osdpl_nova_audit"
    known_metrics = {
        # "osdpl_nova_audit_orphaned_allocations": {"labels": []},
        # "osdpl_nova_audit_resource_provider_orphaned_allocations": {
        #    "labels": ["resource_provider"]
        # },
        # "osdpl_nova_audit_resource_provider_orphaned_resources": {
        #    "labels": ["resource_provider", "resource_class"]
        # },
    }

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if Version(cls.osdpl.obj["status"]["version"]) < Version("0.17.1"):
            raise unittest.SkipTest(
                "This nova audit tests require rockoon version "
                "0.17.1 and greater"
            )
        openstack_version = cls.osdpl.obj["spec"]["openstack_version"]
        if (
            constants.OpenStackVersion[openstack_version]
            < constants.OpenStackVersion["antelope"]
        ):
            raise unittest.SkipTest(
                "Skip nova audit collector checking for releases lower than Antelope"
            )
        rp = list(cls.ocm.oc.placement.resource_providers())[0]
        cls.placement_rp_data = {"uuid": rp["id"]}
        cls.rp_resources_metric_labels = {}
        for res_class in RESOURCES.keys():
            cls.rp_resources_metric_labels[res_class] = {
                "resource_provider": cls.placement_rp_data["uuid"],
                "resource_class": res_class,
            }
        cls.rp_allocations_metric_labels = {
            "resource_provider": cls.placement_rp_data["uuid"]
        }
        # metrics related to resource providers doesn't exist,
        # when no orphaned allocations found, so creating one
        cls._create_fake_allocation()
        cls.cronjob_run("nova-placement-audit", wait=True)

    def _get_allocations_metrics(self):
        metrics = {}
        for m in [
            "osdpl_nova_audit_orphaned_allocations",
            "osdpl_nova_audit_resource_provider_orphaned_allocations",
            "osdpl_nova_audit_resource_provider_orphaned_resources",
        ]:
            metrics[m] = self.get_metric_after_refresh(
                m, self.scrape_collector
            )
        return metrics

    @classmethod
    def _create_fake_allocation(cls):
        allocation = cls.consumer_allocation_create(
            str(uuid4()),
            cls.placement_rp_data["uuid"],
            RESOURCES,
        )
        return allocation

    def _delete_allocation(self, allocation):
        self.consumer_allocation_delete(allocation["consumer_id"])

    def test_orphaned_allocations(self):
        """Test orphaned allocations related metrics.

        **Steps:**

        #. Get initial values for orphaned allocations related metrics
        #. Create new orphaned allocation and get metrics after creation
        #. Calculate and check metrics values increased after allocation creation
        #. Delete created orphaned allocation and get metrics after deletion
        #. Check metrics returned to initial values after allocation deletion

        """
        # Get initial metrics
        initial_metrics = self._get_allocations_metrics()
        initial_orphaned_allocations = (
            initial_metrics["osdpl_nova_audit_orphaned_allocations"]
            .samples[0]
            .value
        )
        initial_rp_orphaned_allocations = self.filter_metric_samples(
            initial_metrics[
                "osdpl_nova_audit_resource_provider_orphaned_allocations"
            ],
            self.rp_allocations_metric_labels,
        )[0].value
        initial_orphaned_resources = {}
        for res_class, res_value in RESOURCES.items():
            initial_orphaned_resources[res_class] = self.filter_metric_samples(
                initial_metrics[
                    "osdpl_nova_audit_resource_provider_orphaned_resources"
                ],
                self.rp_resources_metric_labels[res_class],
            )[0].value

        # Create new orphaned allocation and get metrics after creation
        allocation = self._create_fake_allocation()
        self.cronjob_run("nova-placement-audit", wait=True)
        after_create_metrics = self._get_allocations_metrics()
        orphaned_allocations_after_create = (
            after_create_metrics["osdpl_nova_audit_orphaned_allocations"]
            .samples[0]
            .value
        )
        orphaned_rp_allocations_after_create = self.filter_metric_samples(
            after_create_metrics[
                "osdpl_nova_audit_resource_provider_orphaned_allocations"
            ],
            self.rp_allocations_metric_labels,
        )[0].value

        # Calculate and check metrics values increased after allocation creation
        expected_orphaned_allocations = initial_orphaned_allocations + 1
        expected_rp_orphaned_allocations = initial_rp_orphaned_allocations + 1
        expected_resources = {}
        for res_class, res_value in RESOURCES.items():
            expected_resources[res_class] = (
                initial_orphaned_resources[res_class] + res_value
            )
        self.assertEqual(
            orphaned_allocations_after_create,
            expected_orphaned_allocations,
            "Orphaned allocations in cluster after allocation creation. "
            f"Current value: {orphaned_allocations_after_create}. "
            f"Expected value: {expected_orphaned_allocations}.",
        )
        self.assertEqual(
            orphaned_rp_allocations_after_create,
            expected_rp_orphaned_allocations,
            f"Orphaned allocations on resource provider {self.placement_rp_data['uuid']} "
            "after allocation creation. "
            f"Current value: {orphaned_rp_allocations_after_create}. "
            f"Expected value: {expected_rp_orphaned_allocations}.",
        )
        for res_class, res_value in RESOURCES.items():
            orphaned_resource_after_create = self.filter_metric_samples(
                after_create_metrics[
                    "osdpl_nova_audit_resource_provider_orphaned_resources"
                ],
                self.rp_resources_metric_labels[res_class],
            )[0].value
            self.assertEqual(
                orphaned_resource_after_create,
                expected_resources[res_class],
                f"Resource {res_class} on resource provider {self.placement_rp_data['uuid']} "
                "after allocation creation. "
                f"Current value: {orphaned_resource_after_create}"
                f"Expected value: {expected_resources[res_class]}",
            )
        # Delete created orphaned allocation and get metrics after deletion
        self._delete_allocation(allocation)
        self.cronjob_run("nova-placement-audit", wait=True)
        after_delete_metrics = self._get_allocations_metrics()
        orphaned_allocations_after_delete = (
            after_delete_metrics["osdpl_nova_audit_orphaned_allocations"]
            .samples[0]
            .value
        )
        orphaned_rp_allocations_after_delete = self.filter_metric_samples(
            after_delete_metrics[
                "osdpl_nova_audit_resource_provider_orphaned_allocations"
            ],
            self.rp_allocations_metric_labels,
        )[0].value

        # Check metrics returned to initial values after allocation deletion
        self.assertEqual(
            orphaned_allocations_after_delete,
            initial_orphaned_allocations,
            "Orphaned allocations in cluster after allocation deletion. "
            f"Current value: {orphaned_allocations_after_delete}. "
            f"Expected value: {initial_orphaned_allocations}.",
        )
        self.assertEqual(
            orphaned_rp_allocations_after_delete,
            initial_rp_orphaned_allocations,
            f"Orphaned allocations on resource provider {self.placement_rp_data['uuid']} "
            "after allocation deletion. "
            f"Current value: {orphaned_rp_allocations_after_delete}. "
            f"Expected value: {initial_rp_orphaned_allocations}.",
        )
        for res_class, res_value in RESOURCES.items():
            orphaned_resource_after_delete = self.filter_metric_samples(
                after_delete_metrics[
                    "osdpl_nova_audit_resource_provider_orphaned_resources"
                ],
                self.rp_resources_metric_labels[res_class],
            )[0].value
            self.assertEqual(
                orphaned_resource_after_delete,
                initial_orphaned_resources[res_class],
                f"Resource {res_class} on resource provider {self.placement_rp_data['uuid']} "
                "after allocation deletion. "
                f"Current value: {orphaned_resource_after_delete}"
                f"Expected value: {initial_orphaned_resources[res_class]}",
            )
