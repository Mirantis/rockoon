import logging
import unittest

from rockoon.tests.functional import base, config, data_utils


LOG = logging.getLogger(__name__)
CONF = config.Config()


class BaseMasakariTestCase(base.BaseFunctionalTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not cls.is_service_enabled("instance-ha"):
            raise unittest.SkipTest("Masakari is not deployed")

    @classmethod
    def is_introspective_monitor_enabled(cls):
        return (
            cls.osdpl.obj["spec"]["features"]
            .get("masakari", {})
            .get("monitors", {})
            .get("introspective", {})
            .get("enabled", False)
        )

    @classmethod
    def create_masakari_segment(
        cls, recovery_method="auto", service_type="compute", name=None
    ):
        if name is None:
            name = data_utils.rand_name(postfix="masakari-segment")
        segment = cls.ocm.oc.instance_ha.create_segment(
            name=name,
            recovery_method=recovery_method,
            service_type=service_type,
        )
        cls.addClassCleanup(cls.delete_masakari_segment, segment["uuid"])
        return segment

    @classmethod
    def delete_masakari_segment(cls, segment_uuid):
        cls.ocm.oc.instance_ha.delete_segment(segment_uuid)

    def segment_add_host(
        self, host_name, segment_id, type="compute", control_attributes="SSH"
    ):
        self.addCleanup(self.segment_delete_host, host_name, segment_id)
        return self.ocm.oc.instance_ha.create_host(
            segment_id,
            name=host_name,
            type=type,
            control_attributes=control_attributes,
        )

    def segment_delete_host(self, host_name, segment_id):
        self.ocm.oc.instance_ha.delete_host(host_name, segment_id)

    def get_notification_list(self):
        return list(self.ocm.oc.instance_ha.notifications())

    def get_servers_reboot_count(self, ip, private_key):
        ssh = self.ssh_instance(ip, private_key)
        res = ssh.check_call("journalctl --list-boots")
        num_reboots = len(res.stdout)
        return num_reboots

    def install_qemu_guest_agent(self, ssh):
        ssh.check_call("apt-get update")
        ssh.check_call("apt-get install -y qemu-guest-agent")
        ssh.check_call("systemctl restart qemu-guest-agent")
        ssh.check_call("systemctl status qemu-guest-agent")
