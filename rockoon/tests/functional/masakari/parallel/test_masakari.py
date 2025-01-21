import logging
import time
import pytest

from rockoon.tests.functional import config, waiters, ssh_utils
from rockoon.tests.functional.masakari.base import BaseMasakariTestCase

LOG = logging.getLogger(__name__)
CONF = config.Config()


@pytest.mark.xdist_group("masakari")
class MasakariIntrospectiveInstanceMonitorTestCases(BaseMasakariTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.flavor = cls.ocm.oc.compute.find_flavor("m1.tiny_test")["id"]
        cls.image = cls.ocm.oc.get_image(CONF.UBUNTU_TEST_IMAGE_NAME)

        LOG.debug("Create Masakari segment")
        cls.ms_segment = cls.create_masakari_segment()

        LOG.debug("Create network resources")
        cls.network = cls.network_create()
        cls.subnet = cls.subnet_create(
            cidr=CONF.TEST_SUBNET_RANGE, network_id=cls.network["id"]
        )
        router = cls.ocm.oc.network.find_router(CONF.EXTERNAL_ROUTER)
        cls.add_interface_to_router(router["id"], subnet_id=cls.subnet["id"])

    def setUp(self):
        fixed_ips = [{"subnet_id": self.subnet["id"]}]
        self.port = self.port_create(
            self.network["id"],
            fixed_ips=fixed_ips,
            is_port_security_enabled=False,
        )
        floating_ip = self.floating_ip_create(CONF.PUBLIC_NETWORK_NAME)
        self.update_floating_ip(floating_ip.id, self.port.id)

        LOG.debug("Create SSH keypair")
        self.ssh_keys = ssh_utils.generate_keys()
        public_key = "ssh-rsa " + self.ssh_keys["public"]
        self.keypair = self.create_keypair(public_key=public_key)

    def test_masakari_introspective_monitor(self):
        """Verify Masakari introspective instance monitor

        #. Set the Ubuntu image property hw_qemu_guest_agent='yes'
        #. Boot an instance with SSH access
        #. Add the instance's host to the Masakari segment
        #. SSH into the instance and install the qemu-guest-agent
        #. Retrieve the initial reboot count of the instance
        #. Stop the qemu-guest-agent to simulate an instance crash
        #. Verify the Masakari notification after stopping the qemu-guest-agent
        #. Verify that the instance was rebooted once after stopping the qemu-guest
        #. Verify that the instance is running
        #. Verify the qemu-guest-agent status
        """
        LOG.debug("Set the Ubuntu image property hw_qemu_guest_agent='yes'")
        self.update_image_property(self.image, {"hw_qemu_guest_agent": "yes"})

        LOG.debug("Boot an instance with SSH access")
        server = self.server_create(
            imageRef=self.image.id,
            flavorRef=self.flavor,
            networks=[{"port": self.port.id}],
            metadata={"HA_Enabled": "True"},
            keypair=self.keypair["id"],
        )

        LOG.debug("Add the instance's host to the Masakari segment")
        self.segment_add_host(server.compute_host, self.ms_segment.uuid)

        LOG.debug("SSH into the instance and install the qemu-guest-agent")
        ssh = self.ssh_instance(server.public_v4, self.ssh_keys["private"])
        self.install_qemu_guest_agent(ssh)
        time.sleep(30)

        LOG.debug("Retrieve the initial reboot count of the instance")
        start_timestamp = int(time.time())
        initial_reboot_count = self.get_servers_reboot_count(
            server.public_v4, self.ssh_keys["private"]
        )

        LOG.debug("Stop the qemu-guest-agent to simulate an instance crash")
        ssh.check_call("systemctl stop qemu-guest-agent")
        time.sleep(30)

        LOG.debug(
            "Verify the Masakari notification after stopping the qemu-guest-agent"
        )
        waiters.wait_masakari_notification(
            self.get_notification_list,
            server.id,
            start_timestamp=start_timestamp,
            notification_type="VM",
            status="finished",
            event="QEMU_GUEST_AGENT_ERROR",
        )

        LOG.debug(
            "Verify that the instance was rebooted once after stopping the qemu-guest"
        )
        reboot_count = self.get_servers_reboot_count(
            server.public_v4, self.ssh_keys["private"]
        )
        self.assertEqual(
            reboot_count,
            initial_reboot_count + 1,
            f"The instance was rebooted more than 1 time: {reboot_count}",
        )

        LOG.debug("Verify that the instance is running")
        waiters.wait_for_server_status(self.ocm, server, status="ACTIVE")

        LOG.debug("Verify the qemu-guest-agent status")
        ssh = self.ssh_instance(server.public_v4, self.ssh_keys["private"])
        ssh.check_call("systemctl status qemu-guest-agent")
