from parameterized import parameterized
import pytest
import unittest

from retry import retry

from rockoon.tests.functional.exporter import base
from rockoon.tests.functional import data_utils
from rockoon.tests.functional.base import LOG
from rockoon.tests.functional import config

CONF = config.Config()


class NovaCollectorFunctionalTestCase(base.BaseFunctionalExporterTestCase):
    known_metrics = {
        "osdpl_nova_service_state": {"labels": ["binary", "host", "zone"]},
        "osdpl_nova_service_status": {"labels": ["binary", "host", "zone"]},
        "osdpl_nova_instances": {"labels": []},
        "osdpl_nova_active_instances": {"labels": []},
        "osdpl_nova_error_instances": {"labels": []},
        "osdpl_nova_verify_resize_instances": {"labels": []},
        # "osdpl_nova_instance_status": {
        #     "labels": ["name", "id", "status"]
        # },
        "osdpl_nova_hypervisor_instances": {"labels": ["host", "zone"]},
        # "osdpl_nova_aggregate_hosts": {"labels": ["name"]},
        # "osdpl_nova_host_aggregate_info": {"labels": ["hosts", "name"]},
        "osdpl_nova_availability_zone_info": {"labels": ["zone"]},
        "osdpl_nova_availability_zone_hosts": {"labels": ["zone"]},
        "osdpl_nova_availability_zone_instances": {"labels": ["zone"]},
        # "osdpl_nova_aggregate_instances": {"osdpl_nova_aggregate_instances": ["name"]},
        "osdpl_nova_hypervisor_vcpu": {"labels": ["host", "zone"]},
        "osdpl_nova_hypervisor_vcpu_used": {"labels": ["host", "zone"]},
        "osdpl_nova_hypervisor_vcpu_free": {"labels": ["host", "zone"]},
        "osdpl_nova_hypervisor_vcpu_allocation_ratio": {
            "labels": ["host", "zone"]
        },
        "osdpl_nova_hypervisor_disk_gb": {"labels": ["host", "zone"]},
        "osdpl_nova_hypervisor_disk_gb_used": {"labels": ["host", "zone"]},
        "osdpl_nova_hypervisor_disk_gb_free": {"labels": ["host", "zone"]},
        "osdpl_nova_hypervisor_disk_gb_allocation_ratio": {
            "labels": ["host", "zone"]
        },
        "osdpl_nova_hypervisor_memory_mb": {"labels": ["host", "zone"]},
        "osdpl_nova_hypervisor_memory_mb_used": {"labels": ["host", "zone"]},
        "osdpl_nova_hypervisor_memory_mb_free": {"labels": ["host", "zone"]},
        "osdpl_nova_hypervisor_memory_mb_allocation_ratio": {
            "labels": ["host", "zone"]
        },
        # "osdpl_nova_aggregate_vcpu": {"labels": ["name"]},
        # "osdpl_nova_aggregate_vcpu_used": {"labels": ["name"]},
        # "osdpl_nova_aggregate_vcpu_free": {"labels": ["name"]},
        # "osdpl_nova_aggregate_disk_gb": {"labels": ["name"]},
        # "osdpl_nova_aggregate_disk_gb_used": {"labels": ["name"]},
        # "osdpl_nova_aggregate_disk_gb_free": {"labels": ["name"]},
        # "osdpl_nova_aggregate_memory_mb": {"labels": ["name"]},
        # "osdpl_nova_aggregate_memory_mb_used": {"labels": ["name"]},
        # "osdpl_nova_aggregate_memory_mb_free": {"labels": ["name"]},
        "osdpl_nova_availability_zone_vcpu_used": {"labels": ["zone"]},
        "osdpl_nova_availability_zone_vcpu_free": {"labels": ["zone"]},
        "osdpl_nova_availability_zone_disk_gb": {"labels": ["zone"]},
        "osdpl_nova_availability_zone_disk_gb_used": {"labels": ["zone"]},
        "osdpl_nova_availability_zone_disk_gb_free": {"labels": ["zone"]},
        "osdpl_nova_availability_zone_memory_mb": {"labels": ["zone"]},
        "osdpl_nova_availability_zone_memory_mb_used": {"labels": ["zone"]},
        "osdpl_nova_availability_zone_memory_mb_free": {"labels": ["zone"]},
    }

    def setUp(self):
        super().setUp()
        self.compute_svc = self.ocm.compute_get_services(binary=None)
        self.compute_number = len(self.compute_svc)

    def test_service_state(self):
        metric = self.get_metric("osdpl_nova_service_state")
        self.assertIsNotNone(metric)
        self.assertEqual(self.compute_number, len(metric.samples))
        self.assertCountEqual(
            ["host", "zone", "binary"],
            metric.samples[0].labels.keys(),
        )

    def test_service_status(self):
        metric = self.get_metric("osdpl_nova_service_status")
        self.assertIsNotNone(metric)
        self.assertEqual(self.compute_number, len(metric.samples))
        self.assertCountEqual(
            ["host", "zone", "binary"],
            metric.samples[0].labels.keys(),
        )

    @parameterized.expand(
        [
            ("osdpl_nova_hypervisor_vcpu_allocation_ratio", "VCPU"),
            ("osdpl_nova_hypervisor_disk_gb_allocation_ratio", "DISK_GB"),
            ("osdpl_nova_hypervisor_memory_mb_allocation_ratio", "MEMORY_MB"),
        ]
    )
    def test_osdpl_nova_hypervisor_allocation_ratio(
        self, metric_name, resource
    ):
        """Hypervisor allocation_ratio for different resources."""

        metric = self.get_metric(metric_name)
        self.hypervisors = list(self.ocm.oc.placement.resource_providers())
        for hypervisor in self.hypervisors:
            for sample in metric.samples:
                if hypervisor.name.split(".")[0] == sample.labels.get("host"):
                    value = self.get_allocation_ratio(hypervisor.id, resource)
                    self.assertEqual(
                        sample.value,
                        value,
                        f"The allocation ratio for {resource} in exporter's metrics is not correct",
                    )


@pytest.mark.xdist_group("exporter-compute-network")
class NovaInstancesCollectorInstancesFunctionalTestCase(
    base.BaseFunctionalExporterTestCase
):
    scrape_collector = "osdpl_nova"

    def test_nova_instances(self):
        """Total number of instances in the cluster."""

        metric = self.get_metric_after_refresh(
            "osdpl_nova_instances", self.scrape_collector
        )
        servers = self.ocm.compute_get_all_servers()
        self.assertEqual(
            int(metric.samples[0].value),
            len(servers),
            f"Current numbers of servers in exporter's metric are {int(metric.samples[0].value)}."
            f"Expected numbers of servers: {len(servers)}.",
        )

    def test_nova_active_instances(self):
        """Total number of instances in the active state in the cluster.

        **Steps:**

        #. Get exporter metric "osdpl_nova_active_instances" with initial number
        of instances in the active state in the cluster
        #. Create additional test instance in active state
        #. Check that number of active instances was changed in metrics
        #. Delete additional test instance
        #. Check that number of active instances decreased in response from exporter

        """
        metric_name = "osdpl_nova_active_instances"
        initial_metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        initial_active_servers = self.ocm.compute_get_all_servers(
            status="ACTIVE"
        )
        self.assertEqual(
            int(initial_metric.samples[0].value),
            len(initial_active_servers),
            f"Current numbers of active servers in exporter's metric are {int(initial_metric.samples[0].value)}."
            f"Expected numbers of active servers: {len(initial_active_servers)}.",
        )

        active_server = self.server_create()
        active_metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        active_servers = self.ocm.compute_get_all_servers(status="ACTIVE")
        self.assertEqual(
            int(active_metric.samples[0].value),
            len(active_servers),
            f"Current numbers of active servers in exporter's metrics are {int(initial_metric.samples[0].value)}."
            f"Expected numbers of active servers: {len(active_servers)}.",
        )

        self.server_delete(active_server)
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            int(metric.samples[0].value),
            len(active_servers) - 1,
            f"Current numbers of active servers in exporter's metrics are {int(initial_metric.samples[0].value)}."
            f"Expected numbers of active servers: {len(active_servers) - 1}.",
        )

    def test_nova_error_instances(self):
        """Total number of instances in the error state in the cluster.

        **Steps:**

        #. Get exporter metric "osdpl_nova_error_instances"  with initial number
        of instances in the error state in the cluster
        #. Create additional test instance in active state
        #. Reset the state of test server to 'error'
        #. Check that number of error instances was changed in response from exporter

        """
        metric_name = "osdpl_nova_error_instances"
        initial_metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        initial_error_servers = self.ocm.compute_get_all_servers(
            status="ERROR"
        )
        self.assertEqual(
            int(initial_metric.samples[0].value),
            len(initial_error_servers),
            f"Current numbers of error servers in exporter's metrics are {int(initial_metric.samples[0].value)}."
            f"Expected numbers of error servers: {len(initial_error_servers)}.",
        )

        error_server = self.server_create()
        self.server_reset_state(error_server, "error")
        error_servers = self.ocm.compute_get_all_servers(status="ERROR")
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )

        self.assertEqual(
            int(metric.samples[0].value),
            len(error_servers),
            f"Current numbers of error servers in exporter's metrics are {int(metric.samples[0].value)}."
            f"Expected numbers of error servers: {len(error_servers)}.",
        )

    def test_nova_verify_resize_instances(self):
        """Total number of instances in VERIFY_RESIZE status.

        **Steps**

        #. Get exporter metric `osdpl_nova_verify_resize_instances` with initial value
        #. Create test instance
        #. Resize instance and wait until it reaches VERIFY_RESIZE status
        #. Check that number of VERIFY_RESIZE instances increased in exporter metrics
        #. Confirm resize and delete test instance
        #. Check that number of VERIFY_RESIZE instances decreased in exporter metrics
        """
        if (
            self.osdpl.obj["spec"]["features"]
            .get("nova", {})
            .get("images", {})
            .get("backend")
            == "lvm"
        ):
            raise unittest.SkipTest("Resize is not supported on LVM backend.")

        metric_name = "osdpl_nova_verify_resize_instances"

        initial_metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        initial_servers = self.ocm.compute_get_all_servers(
            status="VERIFY_RESIZE"
        )

        self.assertEqual(
            int(initial_metric.samples[0].value),
            len(initial_servers),
            f"Current number of VERIFY_RESIZE servers in exporter's metrics is "
            f"{int(initial_metric.samples[0].value)}. "
            f"Expected number of VERIFY_RESIZE servers: {len(initial_servers)}.",
        )
        # Create a server with a smaller flavor to test resize
        flavor_id = self.get_flavor_id(CONF.TEST_FLAVOR_TINY_NAME)
        resize_flavor_id = self.get_flavor_id(CONF.TEST_FLAVOR_NAME)
        server = self.server_create(flavorRef=flavor_id)
        self.resize_server(server, resize_flavor_id)

        metric_after_resize = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        servers_after_resize = self.ocm.compute_get_all_servers(
            status="VERIFY_RESIZE"
        )

        self.assertEqual(
            int(metric_after_resize.samples[0].value),
            len(servers_after_resize),
            f"Current number of VERIFY_RESIZE servers in exporter's metrics is "
            f"{int(metric_after_resize.samples[0].value)}. "
            f"Expected number of VERIFY_RESIZE servers: {len(servers_after_resize)}.",
        )

        self.server_delete(server)

        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            int(metric.samples[0].value),
            len(servers_after_resize) - 1,
            f"Current number of VERIFY_RESIZE servers in exporter's metrics is "
            f"{int(metric.samples[0].value)}. "
            f"Expected number of VERIFY_RESIZE servers: {len(servers_after_resize) - 1}.",
        )

    def test_instance_status(self):
        """Check that instance_status metric appears when VM is in VERIFY_RESIZE status.

        **Steps:**

        #. Create a test instance
        #. Get initial samples for metric `osdpl_nova_instance_status`
        #. Check that metric doesn't have sample for the test instance
        #. Resize test instance
        #. Refresh metric and check that a new sample with the VM's name, id and status appears
        #. Delete the test instance
        #. Refresh metric and check that the sample disappears
        """
        metric_name = "osdpl_nova_instance_status"

        # Create a server with a smaller flavor to test resize
        flavor_id = self.get_flavor_id(CONF.TEST_FLAVOR_TINY_NAME)
        resize_flavor_id = self.get_flavor_id(CONF.TEST_FLAVOR_NAME)
        server = self.server_create(flavorRef=flavor_id)
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        labels = {
            "id": server["id"],
            "name": server["name"],
            "status": server["status"].lower(),
        }
        samples = self.filter_metric_samples(metric, labels)
        self.assertEqual(
            len(samples),
            0,
            f"Instance_status metric contain sample for VM {server['name']}",
        )

        self.resize_server(server, resize_flavor_id)
        server = self.ocm.oc.get_server(server.id)
        labels = {
            "id": server["id"],
            "name": server["name"],
            "status": server["status"].lower(),
        }
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        samples = self.filter_metric_samples(metric, labels)
        self.assertEqual(
            len(samples),
            1,
            f"Instance_status metric does not contain sample for VM {server['name']}",
        )
        self.assertCountEqual(
            ["name", "id", "status"],
            samples[0].labels.keys(),
        )
        self.server_delete(server)
        metric_after_delete = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        deleted_samples = self.filter_metric_samples(
            metric_after_delete, labels
        )
        self.assertEqual(
            len(deleted_samples),
            0,
            f"Instance_status metric sample for VM {server['name']} still exists after deletion",
        )


@pytest.mark.xdist_group("exporter-compute-network")
class NovaAvailabilityZonesTestCase(base.BaseFunctionalExporterTestCase):
    scrape_collector = "osdpl_nova"

    def setUp(self):
        super().setUp()
        self.metrics_initial = self.get_collector_metrics(
            self.scrape_collector
        )
        aggregate_name = data_utils.rand_name()
        self.aggregate = self.aggregate_create(
            name=aggregate_name,
        )

    def test_nova_availability_zone_info(self):
        """Information about availability zones in the cluster.

        **Steps**

        #. Get `osdpl_nova_availability_zone_info` metric with initial number
        #. Add additional availability zone
        #. Check that new availablity zone appear in the samples
        #. Remove availability zone
        #. Check availability zone dissappear from the samples
        """
        metric_name = "osdpl_nova_availability_zone_info"
        azs = list(self.ocm.oc.compute.availability_zones())
        initial_metric = self.get_metric(metric_name, self.metrics_initial)
        self.assertEqual(
            len(initial_metric.samples),
            len(azs),
            "The initial number of availability zones is not correct.",
        )
        self.ocm.oc.compute.update_aggregate(
            self.aggregate["id"], availability_zone=self.aggregate["name"]
        )
        metric_after_create = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )

        # NOTE(vsienko): empty az is not show on API LP: 2045888
        expected_azs = len(azs)
        self.assertEqual(
            len(metric_after_create.samples),
            expected_azs,
            "The number of availability zones after create is not correct.",
        )

        self.aggregate_delete(self.aggregate["id"])

        metric_after_delete = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )

        self.assertEqual(
            len(metric_after_delete.samples),
            len(azs),
            "The number of availability zones after delete is not correct.",
        )


@pytest.mark.xdist_group("exporter-compute-network")
class NovaAggregatesTestCase(base.BaseFunctionalExporterTestCase):
    scrape_collector = "osdpl_nova"

    def setUp(self):
        super().setUp()
        aggregate_name = data_utils.rand_name()
        self.aggregate = self.aggregate_create(
            name=aggregate_name,
        )

    def _test_osdpl_nova_aggregate_hosts(
        self, metric_name, aggregate_name, expected_num, phase
    ):
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        samples = self.filter_metric_samples(metric, {"name": aggregate_name})
        self.assertEqual(
            int(samples[0].value),
            expected_num,
            f"{phase}: The number of hosts in aggregate is not correct.",
        )

    def _test_osdpl_nova_aggregate_hosts_info(
        self, metric_name, expected_num, phase, metric_labels=None
    ):
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        if metric_labels == None:
            metric_labels = {"name": self.aggregate["name"]}

        samples = self.filter_metric_samples(metric, metric_labels)
        self.assertEqual(
            len(samples),
            expected_num,
            f"{phase}: The number of hosts in aggregate is not correct.",
        )

    def test_osdpl_nova_aggregate_hosts(self):
        """Information about aggregate hosts mapping

        **Steps**

        #. Add aggregate
        #. Check we do not have hosts reported in the metric
        #. Add host to aggregate
        #. Check host appear in the metric
        #. Remove host from host aggregate
        #. Check host dissapear from the metric
        """
        metric_name = "osdpl_nova_aggregate_hosts"
        self._test_osdpl_nova_aggregate_hosts(
            metric_name, self.aggregate["name"], 0, "Initial"
        )

        aggregate_compute = [
            x for x in self.ocm.oc.compute.services(binary="nova-compute")
        ][0]["host"]
        self.aggregate_add_host(self.aggregate["id"], aggregate_compute)

        self._test_osdpl_nova_aggregate_hosts(
            metric_name, self.aggregate["name"], 1, "After create"
        )

        self.aggregate_remove_host(self.aggregate["id"], aggregate_compute)
        self._test_osdpl_nova_aggregate_hosts(
            metric_name, self.aggregate["name"], 0, "After delete"
        )

    def test_osdpl_nova_host_aggregate_info(self):
        """Information about host aggregate mapping

        **Steps**

        #. Check initial info about host aggregate in the metric
        #. Create aggregate and add host to created aggregate
        #. Check info about created aggregate appears in the metric
        #. Remove host from host aggregate
        #. Check host dissapears from the metric
        """
        metric_name = "osdpl_nova_host_aggregate_info"

        self._test_osdpl_nova_aggregate_hosts_info(metric_name, 0, "Initial")

        aggregate_compute = [
            x for x in self.ocm.oc.compute.services(binary="nova-compute")
        ][0]["host"]
        self.aggregate_add_host(self.aggregate["id"], aggregate_compute)

        self._test_osdpl_nova_aggregate_hosts_info(
            metric_name,
            1,
            "After create",
            metric_labels={
                "name": self.aggregate["name"],
                "host": aggregate_compute,
            },
        )

        self.aggregate_remove_host(self.aggregate["id"], aggregate_compute)

        self._test_osdpl_nova_aggregate_hosts_info(
            metric_name, 0, "After delete"
        )


@pytest.mark.xdist_group("exporter-compute-network")
class NovaResourcesStatsTestCase(base.BaseFunctionalExporterTestCase):
    scrape_collector = "osdpl_nova"

    def setUp(self):
        super().setUp()
        self.resources = [
            "instances",
            "vcpu",
            "vcpu_used",
            "vcpu_free",
            "disk_gb",
            "disk_gb_used",
            "disk_gb_free",
            "memory_mb",
            "memory_mb_used",
            "memory_mb_free",
        ]

        self.aggregate = None
        compute_services = self.ocm.oc.compute.services(binary="nova-compute")
        filtered_services = [
            service
            for service in compute_services
            if service.get("availability_zone") == "nova"
            and "nova-compute-ironic" not in service["host"]
            and len(self.ocm.compute_get_all_servers(host=service["host"]))
            == 0
        ]
        if not filtered_services:
            raise unittest.SkipTest(
                "There are no nova compute hosts available for aggregate"
            )

        self.aggregate_compute = filtered_services[0]["host"]
        self.server = None

    def tearDown(self):
        if self.server:
            self.server_delete(self.server)
        super().tearDown()

    def get_resource_metrics_values(self, resource_type, labels):
        metrics = self.get_collector_metrics(self.scrape_collector)
        res = {}
        for resource in self.resources:
            metric_name = f"osdpl_nova_{resource_type}_{resource}"
            metric = self.get_metric(metric_name, metrics)
            res[resource] = self.filter_metric_samples(metric, labels)[0].value
        return res

    @retry(AssertionError, tries=3, delay=5, logger=LOG)
    def check_resource_metrics_values(
        self, resource_type, labels, resources_expected, message
    ):
        LOG.debug(f"Checking {resource_type} {labels} metrics values")
        resources_actual = self.get_resource_metrics_values(
            resource_type, labels
        )
        self.assertDictEqual(
            resources_expected,
            resources_actual,
            message,
        )

    def _test_osdpl_nova_resource_metrics(self, resource_type):
        """Check osdpl_nova_<resource_type>_<resource> metrics

        Check resources:
            "instances"
            "vcpu"
            "vcpu_used"
            "vcpu_free"
            "disk_gb"
            "disk_gb_used"
            "disk_gb_free"
            "memory_mb"
            "memory_mb_used"
            "memory_mb_free"

        #. Check initial samples. For hypervisors should be present, for az/aggregates should be absent.
        #. Create aggregate with availability zone.
        #. Get initial metrics.
        #. Create server in AZ.
        #. Check metrics are changed comparing to initial
        #. Remove server
        #. Check metric samples back to initial
        #. Remove host from aggregate
        """
        aggregate_name = data_utils.rand_name()
        labels = {"name": aggregate_name}
        if resource_type == "availability_zone":
            labels = {"zone": aggregate_name}
        elif resource_type == "hypervisor":
            labels = {
                "zone": aggregate_name,
                "host": self.aggregate_compute,
            }

        mecrics_no_resources = self.get_collector_metrics(
            self.scrape_collector
        )
        for resource in self.resources:
            metric_name = f"osdpl_nova_{resource_type}_{resource}"
            metric = self.get_metric(metric_name, mecrics_no_resources)
            samples = self.filter_metric_samples(metric, labels)
            self.assertEqual(
                len(samples),
                0,
                f"Metric {metric_name} samples with {labels} is invalid.",
            )

        self.aggregate = self.aggregate_create(
            name=aggregate_name,
            availability_zone=aggregate_name,
        )

        self.aggregate_add_host(self.aggregate["id"], self.aggregate_compute)
        resources_initial = self.get_resource_metrics_values(
            resource_type, labels
        )

        self.server = self.server_create(
            availability_zone=self.aggregate["name"]
        )
        server = self.ocm.oc.compute.get_server(self.server["id"])
        flavor = server["flavor"]
        resource_expected_changes = {
            "instances": 1,
            "vcpu": 0,
            "vcpu_used": flavor["vcpus"],
            "vcpu_free": flavor["vcpus"] * -1,
            "disk_gb": 0,
            "disk_gb_used": flavor["disk"] + flavor["ephemeral"],
            "disk_gb_free": (flavor["disk"] + flavor["ephemeral"]) * -1,
            "memory_mb": 0,
            "memory_mb_used": flavor["ram"],
            "memory_mb_free": flavor["ram"] * -1,
        }

        resources_after_create = self.get_resource_metrics_values(
            resource_type, labels
        )

        resources_expected = {}
        for resource in self.resources:
            resources_expected[resource] = (
                resources_initial[resource]
                + resource_expected_changes[resource]
            )
        self.assertDictEqual(
            resources_after_create,
            resources_expected,
            "Some of resources is not changed correctly after creating server.",
        )

        self.server_delete(self.server)
        self.check_resource_metrics_values(
            resource_type,
            labels,
            resources_initial,
            "Some of resources is not changed correctly after server removal.",
        )

        self.aggregate_remove_hosts(self.aggregate["id"])
        self.aggregate_delete(self.aggregate["id"])
        mecrics_no_resources = self.get_collector_metrics(
            self.scrape_collector
        )
        for resource in self.resources:
            metric_name = f"osdpl_nova_{resource_type}_{resource}"
            metric = self.get_metric(metric_name, mecrics_no_resources)
            samples = self.filter_metric_samples(metric, labels)
            self.assertEqual(
                len(samples),
                0,
                f"Metric {metric_name} samples with {labels} is invalid after aggregate removal.",
            )

    @parameterized.expand(
        [("availability_zone"), ("aggregate"), ("hypervisor")]
    )
    def test_osdpl_nova_resources(self, resource_type):
        self._test_osdpl_nova_resource_metrics(resource_type)
