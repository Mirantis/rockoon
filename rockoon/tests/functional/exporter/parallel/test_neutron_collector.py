import ipaddress
import time
import unittest

import pytest

from rockoon.exporter import constants
from rockoon.tests.functional.exporter import base
from rockoon.tests.functional import config

CONF = config.Config()


@pytest.mark.xdist_group("exporter-compute-network")
class NeutronCollectorFunctionalTestCase(base.BaseFunctionalExporterTestCase):
    scrape_collector = "osdpl_neutron"

    known_metrics = {
        "osdpl_neutron_networks": {"labels": []},
        "osdpl_neutron_subnets": {"labels": []},
        "osdpl_neutron_down_ports": {"labels": []},
        "osdpl_neutron_active_ports": {"labels": []},
        "osdpl_neutron_ports": {"labels": []},
        "osdpl_neutron_routers": {"labels": []},
        "osdpl_neutron_floating_ips": {"labels": ["state"]},
        "osdpl_neutron_agent_state": {"labels": ["host", "zone", "binary"]},
    }

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        bundle = cls.network_bundle_create()
        cls.network = bundle["network"]
        cls.subnet = bundle["subnet"]
        cls.router = bundle["router"]
        cls.servers = []
        if not cls.is_ovn_enabled():
            cls.known_metrics["osdpl_neutron_zone_routers"] = {"labels": []}
            cls.known_metrics["osdpl_neutron_availability_zone_info"] = {
                "labels": ["zone", "resource"]
            }

    def test_neutron_agents_state(self):
        """State of neutron agents in the cluster."""

        metric = self.get_metric("osdpl_neutron_agent_state")
        self.assertEqual(
            len(list(self.ocm.network_get_agents())), len(metric.samples)
        )
        self.assertCountEqual(
            ["host", "zone", "binary"],
            metric.samples[0].labels.keys(),
        )

    def test_neutron_networks(self):
        """Total number of networks in the cluster.


        **Steps:**

        #. Get exporter metric "osdpl_neutron_networks"  with initial number
        of networks in the cluster
        #. Check that number of networks is equal for OS and exporter
        #. Create additional test network
        #. Check that number of networks was changed in response from exporter
        #. Delete the created network
        #. Check that number of networks was changed in response from exporter

        """
        metric_name = "osdpl_neutron_networks"
        metric = self.get_metric(metric_name)
        networks = list(self.ocm.oc.network.networks())
        self.assertEqual(
            int(metric.samples[0].value),
            len(networks),
            "The initial number of networks is not correct.",
        )
        network = self.network_create()
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            int(metric.samples[0].value),
            len(networks) + 1,
            "The number of networks after network create is not correct.",
        )
        self.network_delete(network)
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            int(metric.samples[0].value),
            len(networks),
            "The number of networks after network delete is not correct.",
        )

    def test_neutron_subnets(self):
        """Total number of subnets in the cluster.


        **Steps:**

        #. Get exporter metric "osdpl_neutron_subnets"  with initial number
        of subnets in the cluster
        #. Check that number of subnets is equal for OS and exporter
        #. Create additional test subnet
        #. Check that number of subnets was changed in response from exporter
        #. Delete the created subnet
        #. Check that number of subnets was changed in response from exporter

        """
        metric_name = "osdpl_neutron_subnets"
        metric = self.get_metric(metric_name)
        subnets = list(self.ocm.oc.network.subnets())
        self.assertEqual(
            int(metric.samples[0].value),
            len(subnets),
            "The initial number of subnets is not correct.",
        )
        subnet = self.subnet_create(
            cidr="192.168.0.0/24", network_id=self.network["id"]
        )
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            int(metric.samples[0].value),
            len(subnets) + 1,
            "The number of subnets after subnet create is not correct.",
        )
        self.subnet_delete(subnet)
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            int(metric.samples[0].value),
            len(subnets),
            "The number of subnets after subnet delete is not correct.",
        )

    def check_fips_metrics(self, total, associated, not_associated, phase):
        metric_name = "osdpl_neutron_floating_ips"
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        not_associated_metric = self.filter_metric_samples(
            metric, {"state": "not_associated"}
        )
        associated_metric = self.filter_metric_samples(
            metric, {"state": "associated"}
        )
        total_fips = int(self.sum_metric_samples(metric))
        self.assertEqual(
            total_fips,
            total,
            f"{phase}: The numbner of Fips is not correct",
        )

        self.assertEqual(
            not_associated_metric[0].value,
            not_associated,
            f"{phase}: The numbner of not associated FIPs is not correct.",
        )

        self.assertEqual(
            associated_metric[0].value,
            associated,
            f"{phase}: The numbner of associated FIPs is not correct.",
        )
        self.assertEqual(
            associated_metric[0].value + not_associated_metric[0].value,
            total,
            f"{phase}: The summ of associated and not associated does not match expected total.",
        )

    def test_neutron_floating_ips(self):
        """Total number FIPs


        **Steps:**

        #. Get exporter metric "osdpl_neutron_floating_ips"  with initial number
        of fips in the cluster
        #. Check that number of fips is equal for OS and exporter
        #. Create additional test fip
        #. Check that number of not_associated fips was changed in response from exporter
        #. Associate FIP with port
        #. Check that number associated fips increased

        """
        fips = len(self.ocm.oc.list_floating_ips())
        fips_associated = self.floating_ips_associated()

        self.check_fips_metrics(
            fips, fips_associated, fips - fips_associated, "Initial"
        )

        fip = self.floating_ip_create(CONF.PUBLIC_NETWORK_NAME)

        fips = fips + 1
        self.check_fips_metrics(
            fips, fips_associated, fips - fips_associated, "Create"
        )

        fixed_ips = [{"subnet_id": self.subnet["id"]}]
        port = self.port_create(self.network["id"], fixed_ips=fixed_ips)
        self.ocm.network_floating_ip_update(
            fip["id"], data={"port_id": port["id"]}
        )

        self.check_fips_metrics(
            fips, fips_associated + 1, fips - fips_associated - 1, "Associate"
        )

    def test_neutron_routers(self):
        """Total number of routers in the cluster."""
        metric_name = "osdpl_neutron_routers"
        initial_metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        routers = list(self.ocm.oc.network.routers())
        self.assertEqual(
            int(initial_metric.samples[0].value),
            len(routers),
            "The initial number of routers is not correct",
        )

        router = self.router_create()
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            int(metric.samples[0].value),
            len(routers) + 1,
            "The number of routers after router create is not correct.",
        )

        self.router_delete(router)
        metric_after_delete_router = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            int(metric_after_delete_router.samples[0].value),
            len(routers),
            "The number of routers after router delete is not correct.",
        )

    def test_neutron_zone_routers(self):
        """Total number of routers in the availability zone."""
        metric_name = "osdpl_neutron_zone_routers"
        if self.is_ovn_enabled():
            raise unittest.SkipTest("OVN does have default AZ configured")
        initial_metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        availability_zone = initial_metric.samples[0].labels["zone"]
        routers = self.routers_availability_zones(availability_zone)
        self.assertEqual(
            int(initial_metric.samples[0].value),
            len(routers),
            "The initial number of routers is not correct",
        )

        bundle = self.network_bundle_create()
        router = bundle["router"]
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            int(metric.samples[0].value),
            len(routers) + 1,
            "The number of routers after router create is not correct.",
        )

        self.router_delete(router["id"])
        metric_after_delete_router = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            int(metric_after_delete_router.samples[0].value),
            len(routers),
            "The number of routers after router delete is not correct.",
        )


@pytest.mark.xdist_group("exporter-compute-network")
class NeutronPortsTestCase(base.BaseFunctionalExporterTestCase):
    scrape_collector = "osdpl_neutron"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.network = cls.network_create()

    def _test_osdpl_neutron_ports(self, metric_name, expected_num, phase):
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            int(metric.samples[0].value),
            expected_num,
            f"{phase}: The number of ports in the cluster is not correct.",
        )

    def test_neutron_ports(self):
        """Total number of ports in the cluster.

        **Steps:**

        #. Get exporter metric "osdpl_neutron_ports" with initial number
        of ports in the cluster
        #. Check that number of ports is equal to OS and exporter
        #. Create additional port
        #. Check that total number of ports was changed in response from exporter
        #. Delete the created port
        #. Check that total number of ports was changed in response from exporter

        """
        metric_name = "osdpl_neutron_ports"
        ports = list(self.ocm.oc.network.ports())
        self._test_osdpl_neutron_ports(metric_name, len(ports), "Initial")

        port = self.port_create(self.network["id"])
        self._test_osdpl_neutron_ports(
            metric_name, len(ports) + 1, "After create"
        )

        self.port_delete(port)
        self._test_osdpl_neutron_ports(metric_name, len(ports), "After delete")

    def test_neutron_down_ports(self):
        """Total number of ports in DOWN status in the cluster.

        **Steps:**

        #. Get exporter metric "osdpl_neutron_down_ports" with initial number
        of ports in DOWN status in the cluster
        #. Check that number of ports in DOWN status is equal to OS and exporter
        #. Create additional port in DOWN status
        #. Check that number of ports in DOWN status was changed in response from exporter
        #. Delete the created port
        #. Check that number of ports in DOWN status was changed in response from exporter

        """
        metric_name = "osdpl_neutron_down_ports"
        down_ports = self.get_ports_by_status("DOWN")
        self._test_osdpl_neutron_ports(metric_name, len(down_ports), "Initial")

        down_port = self.port_create(self.network["id"])
        self._test_osdpl_neutron_ports(
            metric_name, len(down_ports) + 1, "After create"
        )

        self.port_delete(down_port)
        self._test_osdpl_neutron_ports(
            metric_name, len(down_ports), "After delete"
        )

    def test_neutron_active_ports(self):
        """Total number of ports in ACTIVE status in the cluster.

        **Steps:**

        #. Get exporter metric "osdpl_neutron_active_ports" with initial number
        of ports in ACTIVE status in the cluster
        #. Check that number of ports in ACTIVE status is equal to OS and exporter
        #. Create additional port, attach to server and track the status change from DOWN to ACTIVE
        #. Check that number of ports in ACTIVE status was changed in response from exporter
        #. Delete the created port
        #. Check that number of ports in ACTIVE status was changed in response from exporter

        """
        metric_name = "osdpl_neutron_active_ports"
        active_ports = self.get_ports_by_status("ACTIVE")
        self._test_osdpl_neutron_ports(
            metric_name, len(active_ports), "Initial"
        )

        # Gateway IP in this scenario for the subnet set to None
        # to avoid creating an additional gateway port).
        # enable_dhcp=False sets the default behavior of not enabling DHCP
        # for the subnet and not creating unnecessary ports in tests
        expected_ports_after_create = len(active_ports) + 1
        # When portprober is enabled 2 additional ports are added per subnet
        if self.neturon_portprober_enabled:
            expected_ports_after_create = expected_ports_after_create + 2
        subnet = self.subnet_create(
            cidr=CONF.TEST_SUBNET_RANGE,
            network_id=self.network["id"],
            gateway_ip=None,
            enable_dhcp=False,
        )
        fixed_ips = [{"subnet_id": subnet["id"]}]
        port = self.port_create(self.network["id"], fixed_ips=fixed_ips)
        self.server_create(networks=[{"port": port.id}])

        self._test_osdpl_neutron_ports(
            metric_name, expected_ports_after_create, "After create"
        )

        self.port_delete(port)
        self._test_osdpl_neutron_ports(
            metric_name, expected_ports_after_create - 1, "After delete"
        )

    def test_neutron_error_ports(self):
        """Total number of ports in ERROR status in the cluster."""

        metric_name = "osdpl_neutron_error_ports"
        metric = self.get_metric(metric_name)
        error_ports = self.get_ports_by_status("ERROR")
        self.assertEqual(int(metric.samples[0].value), len(error_ports))


class NeutronAvailabilityZoneTestCase(base.BaseFunctionalExporterTestCase):
    def test_neutron_availability_zone_info(self):
        """Information about neutron availability zones in the cluster.

        **Steps**

        #. Get `osdpl_neutron_availability_zone_info` metric
        #. Get info about neutron's availability zones from OS
        #. Compare exporter's metrics and info from OS
        """
        metric_name = "osdpl_neutron_availability_zone_info"
        if self.is_ovn_enabled():
            raise unittest.SkipTest("OVN does have default AZ configured")
        neutron_az = list(self.ocm.oc.network.availability_zones())
        metric = self.get_metric(metric_name)

        self.assertEqual(
            len(metric.samples),
            len(neutron_az),
            "The initial number of neutrone's availability zones is not correct.",
        )

        for availability_zone in neutron_az:
            labels = {
                "resource": availability_zone.resource,
                "zone": availability_zone.name,
            }
            samples = self.filter_metric_samples(metric, labels)
            self.assertDictEqual(
                samples[0].labels,
                labels,
                "The info about AZ in exporter's metrics is not correct.",
            )
            self.assertEqual(
                samples[0].value,
                1.0,
                "The info about AZ in exporter's metrics is not correct.",
            )


@pytest.mark.xdist_group("exporter-compute-network")
class NeutronIPsCapacityTestCase(base.BaseFunctionalExporterTestCase):
    scrape_collector = "osdpl_neutron"
    collect_metrics_tag = constants.NEUTRON_NETWORK_IP_METRICS_TAG
    known_metrics = {
        "osdpl_neutron_network_total_ips": {
            "labels": ["network_name", "network_id"]
        },
        "osdpl_neutron_network_free_ips": {
            "labels": ["network_name", "network_id"]
        },
        "osdpl_neutron_subnet_total_ips": {
            "labels": [
                "network_name",
                "network_id",
                "subnet_name",
                "subnet_id",
            ]
        },
        "osdpl_neutron_subnet_free_ips": {
            "labels": [
                "network_name",
                "network_id",
                "subnet_name",
                "subnet_id",
            ]
        },
    }

    def setUp(self):
        super().setUp()
        if self.osdpl.obj["spec"]["preset"] == "compute-tf":
            raise unittest.SkipTest(
                "Tungsten Fabric doesn't support neutron IP's capacity "
                "metrics collection"
            )

    def get_total_ips_in_subnet(self, subnet):
        """Total number of IP addresses in a subnet."""
        subnet_ip = ipaddress.IPv4Network(subnet["cidr"], strict=False)
        # Reserved addresses for network, broadcast, gateway address
        reserved_addresses = 3
        return subnet_ip.num_addresses - reserved_addresses

    def get_allocated_ports_in_subnet(self, subnet):
        """Count the number of allocated ports in a subnet."""
        fixed_ips = f"subnet_id={subnet['id']}"
        ports = list(
            self.ocm.oc.network.ports(
                fixed_ips=fixed_ips,
            )
        )
        return len(ports)

    def test_neutron_network_capacity_default_networks(self):
        """Validate that all default networks are present in the metrics.

        **Steps**

        #. Get all networks that are router:external and flat or vlan
        #. Fetch all samples for osdpl_neutron_network_total_ips
        #  and osdpl_neutron_network_free_ips metric
        #. Ensure that all default networks exist in the samples
        """
        metrics_to_check = [
            "osdpl_neutron_network_total_ips",
            "osdpl_neutron_network_free_ips",
        ]
        default_networks = list(
            self.ocm.oc.network.networks(
                is_router_external=True,
                provider_network_type=["vlan", "flat"],
            )
        )
        metrics = self.get_collector_metrics(self.scrape_collector)
        for metric_name in metrics_to_check:
            metric = self.get_metric(metric_name, metrics)
            for network in default_networks:
                labels = {"network_id": network["id"]}
                samples = self.filter_metric_samples(metric, labels)
                self.assertEqual(
                    1,
                    len(samples),
                    f"Network:{network} is missing in the metric {metric_name} samples.",
                )

    def test_neutron_network_capacity_tags(self):
        """Validate that networks with collect tag are present in the metrics.

        **Steps**

        #. Create test network without tag
        #. Check that no samples exists with the test network
        #. Assign tag to the test network
        #. Verify that tagged network appears in the metric samples
        """
        metrics_to_check = [
            "osdpl_neutron_network_total_ips",
            "osdpl_neutron_network_free_ips",
        ]
        network = self.network_create()
        labels = {"network_id": network["id"]}
        metrics = self.get_collector_metrics(self.scrape_collector)
        for metric_name in metrics_to_check:
            metric = self.get_metric(metric_name, metrics)
            samples = self.filter_metric_samples(metric, labels)
            self.assertEqual(
                0,
                len(samples),
                f"The untagged network:{network} appears in the metric {metric_name} samples.",
            )
        self.ocm.oc.network.set_tags(network, [self.collect_metrics_tag])
        metrics = self.get_collector_metrics(self.scrape_collector)
        for metric_name in metrics_to_check:
            metric = self.get_metric(metric_name, metrics)
            samples = self.filter_metric_samples(metric, labels)
            self.assertEqual(
                1,
                len(samples),
                f"Network:{network} is missing in the metric {metric_name} samples.",
            )

    def test_neutron_subnet_capacity_tags(self):
        """Validate that subnets with collect tag are present in the metrics.

        **Steps**

        #. Create test subnets, both with and without collect tag
        #. Verify that only tagged subnet appears in the metric samples
        """
        metrics_to_check = [
            "osdpl_neutron_subnet_total_ips",
            "osdpl_neutron_subnet_free_ips",
        ]
        network = self.network_create()
        subnet_with_tag = self.subnet_create(
            cidr=CONF.TEST_SUBNET_RANGE, network_id=network["id"]
        )
        self.ocm.oc.network.set_tags(
            subnet_with_tag, [self.collect_metrics_tag]
        )
        subnet_without_tag = self.subnet_create(
            cidr=CONF.TEST_SUBNET_RANGE_ALT, network_id=network["id"]
        )
        metrics = self.get_collector_metrics(self.scrape_collector)
        for metric_name in metrics_to_check:
            metric = self.get_metric(metric_name, metrics)
            samples = self.filter_metric_samples(
                metric, {"subnet_id": subnet_without_tag["id"]}
            )
            self.assertEqual(
                0,
                len(samples),
                f"The untagged subnet:{subnet_without_tag} appears in the metric {metric_name} samples.",
            )
            samples = self.filter_metric_samples(
                metric, {"subnet_id": subnet_with_tag["id"]}
            )
            self.assertEqual(
                1,
                len(samples),
                f"Subnet:{subnet_with_tag} is missing in the metric {metric_name} samples.",
            )

    def test_neutron_network_capacity_values(self):
        """Verify that the network metrics contain the exact IP capacity values.

        **Steps**

        #. Create test network with the collect metrics tag
        #. Add two subnets
        #. Count ip capacity and number of allocated ports of this subnets
        #. Ensure that the network metrics contain correct values
        #. Add port to the test subnet
        #. Check metrics values after port creation
        """
        metric_name_total_ips = "osdpl_neutron_network_total_ips"
        metric_name_free_ips = "osdpl_neutron_network_free_ips"
        network = self.network_create()
        labels = {"network_id": network["id"]}
        self.ocm.oc.network.set_tags(network, [self.collect_metrics_tag])

        subnet_cidrs = [CONF.TEST_SUBNET_RANGE, CONF.TEST_SUBNET_RANGE_ALT]
        subnets = []
        for cidr in subnet_cidrs:
            subnet = self.subnet_create(cidr=cidr, network_id=network["id"])
            subnets.append(subnet)
        # Wait for Neutron initialize the service ports in the subnets.
        time.sleep(10)
        expected_total_ips = 0
        expected_free_ips = 0
        for subnet in subnets:
            total_ips = self.get_total_ips_in_subnet(subnet)
            allocated_ports = self.get_allocated_ports_in_subnet(subnet)
            free_ips = total_ips - allocated_ports
            expected_total_ips += total_ips
            expected_free_ips += free_ips

        metrics = self.get_collector_metrics(self.scrape_collector)
        metric_total_ips = self.get_metric(metric_name_total_ips, metrics)
        samples_total_ips = self.filter_metric_samples(
            metric_total_ips, labels
        )
        self.assertEqual(
            expected_total_ips,
            samples_total_ips[0].value,
            f"Total IPs for network {network['id']} is incorrect.",
        )
        metric_free_ips = self.get_metric(metric_name_free_ips, metrics)
        samples_free_ips = self.filter_metric_samples(metric_free_ips, labels)
        self.assertEqual(
            expected_free_ips,
            samples_free_ips[0].value,
            f"Free IPs for network {network['id']} is incorrect.",
        )

        fixed_ips = [{"subnet_id": subnets[0]["id"]}]
        self.port_create(network["id"], fixed_ips=fixed_ips)
        metric_after_add_port = self.get_metric_after_refresh(
            metric_name_total_ips, self.scrape_collector
        )
        samples_total_ips = self.filter_metric_samples(
            metric_after_add_port, labels
        )
        self.assertEqual(
            expected_total_ips,
            samples_total_ips[0].value,
            f"Total IPs for network {network['id']} after port creation is incorrect.",
        )
        metric_after_add_port = self.get_metric_after_refresh(
            metric_name_free_ips, self.scrape_collector
        )
        samples_free_ips = self.filter_metric_samples(
            metric_after_add_port, labels
        )
        self.assertEqual(
            expected_free_ips - 1,
            samples_free_ips[0].value,
            f"Free IPs for network {network['id']} after port creation is incorrect.",
        )

    def test_neutron_subnet_capacity_values(self):
        """Verify that the subnet metrics contain the exact IP capacity values.

        **Steps**

        #. Create test subnet with the collect metrics tag
        #. Count ip capacity and number of allocated ports of this subnet
        #. Ensure that the subnet metrics contain correct values
        #. Add port to the test subnet
        #. Check metrics values after port creation
        """
        metric_name_total_ips = "osdpl_neutron_subnet_total_ips"
        metric_name_free_ips = "osdpl_neutron_subnet_free_ips"
        network = self.network_create()
        subnet = self.subnet_create(
            cidr=CONF.TEST_SUBNET_RANGE, network_id=network["id"]
        )
        self.ocm.oc.network.set_tags(subnet, [self.collect_metrics_tag])
        labels = {"subnet_id": subnet["id"]}
        # Wait for Neutron to initialize the service ports in the subnet.
        time.sleep(10)
        expected_total_ips = self.get_total_ips_in_subnet(subnet)
        allocated_ports = self.get_allocated_ports_in_subnet(subnet)
        expected_free_ips = expected_total_ips - allocated_ports

        metrics = self.get_collector_metrics(self.scrape_collector)
        metric_total_ips = self.get_metric(metric_name_total_ips, metrics)
        samples_total_ips = self.filter_metric_samples(
            metric_total_ips, labels
        )
        self.assertEqual(
            expected_total_ips,
            samples_total_ips[0].value,
            f"Total IPs for subnet {subnet['id']} is incorrect.",
        )
        metric_free_ips = self.get_metric(metric_name_free_ips, metrics)
        samples_free_ips = self.filter_metric_samples(metric_free_ips, labels)
        self.assertEqual(
            expected_free_ips,
            samples_free_ips[0].value,
            f"Free IPs for subnet {subnet['id']} is incorrect.",
        )
        fixed_ips = [{"subnet_id": subnet["id"]}]
        self.port_create(network["id"], fixed_ips=fixed_ips)
        metric_after_add_port = self.get_metric_after_refresh(
            metric_name_total_ips, self.scrape_collector
        )
        samples_total_ips = self.filter_metric_samples(
            metric_after_add_port, labels
        )
        self.assertEqual(
            expected_total_ips,
            samples_total_ips[0].value,
            f"Total IPs for subnet {subnet['id']} after port creation is incorrect.",
        )
        metric_after_add_port = self.get_metric_after_refresh(
            metric_name_free_ips, self.scrape_collector
        )
        samples_free_ips = self.filter_metric_samples(
            metric_after_add_port, labels
        )
        self.assertEqual(
            expected_free_ips - 1,
            samples_free_ips[0].value,
            f"Free IPs for subnet {subnet['id']} after port creation is incorrect.",
        )
