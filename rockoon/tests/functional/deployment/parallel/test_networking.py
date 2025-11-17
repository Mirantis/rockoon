import pytest
import logging

import unittest

from lxml import objectify

from rockoon.tests.functional import (
    base,
    config,
    ssh_utils,
    test_utils,
)
from rockoon import kube

LOG = logging.getLogger(__name__)
CONF = config.Config()


@pytest.mark.xdist_group("exporter-compute-network")
class TestSriovFunctionalBaseTestCase(base.BaseFunctionalTestCase):
    """Check sriov ports functionality

    ---- fip network -----
                       |
                    ( router )
                       |
    --------- network A -----------------
            |                 |
          (vmA1[node1])    (vmA2[node2])
             vmA1_fip        vmA2_fip

    * Test vmA1 has sriov interface type hostdev in
      libvirt domain xml
    * Test can ssh to fip of vmA1
    * Test vmA2 can ping vmA1 via tenant ip
    """

    netA_sriov_vnic_type = "direct"
    netA_sriov_interface_type = "hostdev"
    netA_type = "vlan"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.sriov_nodes = []
        for label, n in cls.osdpl.obj["spec"].get("nodes", {}).items():
            if (
                n.get("features", {})
                .get("neutron", {})
                .get("sriov", {})
                .get("enabled", False)
            ):
                label_value, label_key = label.split("::")
                nodes = [
                    n.name
                    for n in kube.resource_list(
                        kube.Node,
                        selector={label_value: label_key},
                    )
                ]
                cls.sriov_nodes.extend(nodes)
        if not cls.sriov_nodes:
            raise unittest.SkipTest(
                "Skip running sriov tests, as sriov nodes are not configured in osdpl"
            )
        cls.image = cls.ocm.oc.get_image(CONF.UBUNTU_TEST_IMAGE_NAME)
        cls.flavor = cls.ocm.oc.compute.find_flavor("m1.tiny_test")["id"]
        bundle = cls.network_bundle_create(provider_network_type=cls.netA_type)
        LOG.debug("Creating SSH keypair")
        cls.ssh_keys = ssh_utils.generate_keys()
        public_key = "ssh-rsa " + cls.ssh_keys["public"]
        cls.keypair = cls.create_keypair(public_key=public_key)
        cls.netA = bundle["network"]
        cls.vmA1, cls.vmA1_ip, cls.vmA1_fip = cls.create_test_server(
            "vmA1",
            cls.netA,
            availability_zone=f"nova:{cls.sriov_nodes[0]}",
            binding_vnic_type=cls.netA_sriov_vnic_type,
        )
        if len(cls.sriov_nodes) > 1:
            cls.vmA2, cls.vmA2_ip, cls.vmA2_fip = cls.create_test_server(
                "vmA2",
                cls.netA,
                availability_zone=f"nova:{cls.sriov_nodes[1]}",
                binding_vnic_type=cls.netA_sriov_vnic_type,
            )

    @classmethod
    def create_test_server(
        cls, base_name, network, availability_zone=None, binding_vnic_type=None
    ):
        name = f"{network.name}-{base_name}"
        port = cls.port_create(
            name=f"{name}-port",
            network_id=network.id,
            binding_vnic_type=binding_vnic_type,
        )
        ip = port["fixed_ips"][0]["ip_address"]
        server = cls.server_create(
            name=name,
            imageRef=cls.image.id,
            flavorRef=cls.flavor,
            networks=[{"port": port.id}],
            availability_zone=availability_zone,
            keypair=cls.keypair["id"],
        )
        floating_ip = cls.floating_ip_create(CONF.PUBLIC_NETWORK_NAME)
        cls.update_floating_ip(floating_ip.id, port.id)
        return server, ip, floating_ip["floating_ip_address"]

    def verify_instance_interface_type(self, vm, interface_type):
        host = vm.compute_host
        libvirt_pod = self.libvirt_pod(host)
        domain_obj = objectify.fromstring(
            (
                libvirt_pod.exec(
                    ["virsh", "dumpxml", vm.instance_name],
                    container="libvirt",
                    raise_on_error=True,
                )["stdout"]
            )
        )
        # TODO(mkarpin): Add ability to filter interfaces by mac or id
        int_type = domain_obj.devices.interface[0].attrib.get("type")
        assert (
            int_type == interface_type
        ), f"{vm.name} expected interface type {interface_type} but has {int_type}"

    def verify_l3_connectivity(
        self,
        source_ip,
        private_key,
        destination_ip,
        conn_expected=True,
        timeout=15,
    ):

        remote = self.ssh_instance(source_ip, private_key)
        res = remote.check_call("ip route")
        LOG.debug("Routing table on %s is %s", source_ip, res.stdout_str)

        cmd = "ping %s -c4 -w4" % destination_ip
        success_substring = " bytes from %s" % destination_ip

        def ping_remote():
            res = remote.execute(cmd)
            output = res.stdout_str
            LOG.debug(
                "Got output %s while pinging %s",
                res.stdout_str,
                destination_ip,
            )
            if conn_expected:
                return success_substring in output
            else:
                return success_substring not in output

        # NOTE(vsaienko): we may lost couple of pings due to missing ARPs
        # so do several retries to get stable output.
        res = test_utils.call_until_true(ping_remote, timeout, 1)
        self.assertTrue(res)

    def _check_connectivity_vmA2_vmA1(self):
        LOG.info(
            f"Checking L3 connectivity from server {self.vmA2.name} to {self.vmA1.name}"
        )
        self.verify_l3_connectivity(
            self.vmA2_fip, self.ssh_keys["private"], self.vmA1_ip
        )

    def _check_connectivity_vmA1_fip(self):
        LOG.info(f"Checking server {self.vmA1.name} with fip {self.vmA1_fip}")
        self.ssh_instance(self.vmA1_fip, self.ssh_keys["private"])

    def _check_instance_interface_type_vmA1(self):
        LOG.info(f"Checking server {self.vmA1.name} interface type")
        self.verify_instance_interface_type(
            self.vmA1, self.netA_sriov_interface_type
        )

    def _check_instance_interface_type_vmA2(self):
        LOG.info(f"Checking server {self.vmA2.name} interface type")
        self.verify_instance_interface_type(
            self.vmA2, self.netA_sriov_interface_type
        )

    def test_instance_interface_type_vmA1(self):
        self._check_instance_interface_type_vmA1()

    def test_instance_interface_type_vmA2(self):
        self._check_instance_interface_type_vmA2()

    def test_connectivity_vmA1_fip(self):
        self._check_connectivity_vmA1_fip()

    def test_connectivity_vmA2_vmA1(self):
        if len(self.sriov_nodes) < 2:
            self.skipTest(
                "Skip running inter hosts sriov tests, as not enough sriov nodes are found"
            )
        self._check_connectivity_vmA2_vmA1()
