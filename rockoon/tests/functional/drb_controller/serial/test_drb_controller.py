import base64
import time
import pytest
import logging
from statistics import mean

from rockoon.tests.functional.drb_controller import base
from rockoon.tests.functional import config
from rockoon.tests.functional import waiters

CONF = config.Config()
LOG = logging.getLogger(__name__)


@pytest.mark.xdist_group("drb-controller")
class DRBControllerTestCase(base.BaseFunctionalDRBControllerTestCase):
    def setUp(self):
        super().setUp()
        self.wait_for_nodes_load_stabilization()
        self.host_load = self.get_node_loads()
        self.load_threshold = mean(self.host_load.values()) + 10
        LOG.debug(f"Node load threshold is {self.load_threshold}")

    def test_balancing_instances_migrate_any_mode(self):
        """Test DRB-controller basic behaviour with default mode (migrateAny: true)
        **Steps:**
        #. Create DRB Config with migrateAny: true (default) mode
        #. Launch 2 instances on the host
           - first doesn't have tag and immediately
           starts loading the CPU
           - second one does nothing and doesn't have tag
        #. Check after some time that second instance migrates
        to the another host
        """
        self.create_drb_config(self.load_threshold)

        self.flavor = self.flavor_create(vcpus=2)

        self.server_with_load = self.server_create(
            flavorRef=self.flavor["id"],
            config_drive=True,
            user_data=base64.b64encode(
                self.CPU_LOAD_SCRIPT.encode("utf-8")
            ).decode("utf-8"),
        )

        self.addCleanup(self.server_delete, self.server_with_load)

        host = self.ocm.oc.get_server(self.server_with_load.id)["compute_host"]

        self.server = self.server_create(
            availability_zone=f"nova:{host}",
        )

        self.addCleanup(self.server_delete, self.server)

        waiters.wait_for_instance_migration(
            self.ocm,
            self.server,
        )

        self._check_instance_status(self.server_with_load, host)

    def test_balancing_instances_migrate_any_overloaded_node(self):
        """Test DRB-controller behaviour with default mode (migrateAny: true)
         when node is overloaded .
        **Steps:**
        #. Create DRB Config with migrateAny: true (default) mode
        #. Launch instance on the host that doesn't have tags and
        immediately starts loading the CPU
        #. Check after some time that instance doesn't migrate to
        another host because node is overloaded
        """

        self.create_drb_config(self.load_threshold)

        self.server_with_load = self.server_create(
            flavorRef=self.flavor["id"],
            config_drive=True,
            user_data=base64.b64encode(
                self.CPU_LOAD_SCRIPT.encode("utf-8")
            ).decode("utf-8"),
        )

        host = self.ocm.oc.get_server(self.server_with_load.id)["compute_host"]

        self.addCleanup(self.server_delete, self.server_with_load)

        time.sleep(CONF.SERVER_LIVE_MIGRATION_TIMEOUT)

        self._check_instance_status(self.server_with_load, host)

    def test_balancing_instances_migrate_any_non_drb_tag(self):
        """Test DRB-controller behaviour with default mode (migrateAny: true)
        and instance with non-drb tag.
        **Steps:**
        #. Create DRB Config with migrateAny: true (default) mode
        #. Launch first instance on the host that doesn't have tags and
        immediately starts loading the CPU
        #. Launch second instance that does nothing
        #. Launch third instance that does nothing and has non-drb tag
        #. Check after some time that second instance migrates to
        another host
        """

        self.create_drb_config(self.load_threshold)

        self.server_with_load = self.server_create(
            flavorRef=self.flavor["id"],
            config_drive=True,
            user_data=base64.b64encode(
                self.CPU_LOAD_SCRIPT.encode("utf-8")
            ).decode("utf-8"),
        )

        host = self.ocm.oc.get_server(self.server_with_load.id)["compute_host"]

        self.addCleanup(self.server_delete, self.server_with_load)

        self.server = self.server_create(
            availability_zone=f"nova:{host}",
        )

        self.addCleanup(self.server_delete, self.server)

        self.server_with_non_drb_tag = self.server_create(
            availability_zone=f"nova:{host}",
            tags=[self.EXCLUDE_TAG],
        )

        self.addCleanup(self.server_delete, self.server_with_non_drb_tag)

        waiters.wait_for_instance_migration(self.ocm, self.server)

        self._check_instance_status(self.server_with_load, host)

        self._check_instance_status(self.server_with_non_drb_tag, host)

    def test_balancing_instances_migrate_any_non_drb_and_drb_tags(self):
        """Test DRB-controller behaviour with default mode (migrateAny: true)
        and instances with non-drb tag and drb-tag.
        **Steps:**
        #. Create DRB Config with migrateAny: true (default) mode
        #. Launch first instance on the host that doesn't have tags and
        immediately starts loading the CPU
        #. Launch second instance that does nothing and has drb-tag
        #. Launch third instance that does nothing and has non-drb tag
        #. Check after some time that second instance with drb-tag
        migrates to another host
        """

        self.create_drb_config(self.load_threshold)

        self.server_with_load = self.server_create(
            flavorRef=self.flavor["id"],
            config_drive=True,
            user_data=base64.b64encode(
                self.CPU_LOAD_SCRIPT.encode("utf-8")
            ).decode("utf-8"),
        )

        self.addCleanup(self.server_delete, self.server_with_load)

        host = self.ocm.oc.get_server(self.server_with_load.id)["compute_host"]

        self.server_with_drb_tag = self.server_create(
            availability_zone=f"nova:{host}",
            tags=[self.INCLUDE_TAG],
        )

        self.addCleanup(self.server_delete, self.server_with_drb_tag)

        self.server_with_non_drb_tag = self.server_create(
            availability_zone=f"nova:{host}",
            tags=[self.EXCLUDE_TAG],
        )

        self.addCleanup(self.server_delete, self.server_with_non_drb_tag)

        waiters.wait_for_instance_migration(self.ocm, self.server_with_drb_tag)

        self._check_instance_status(self.server_with_load, host)

        self._check_instance_status(self.server_with_non_drb_tag, host)

    def test_balancing_instances_migrate_any_false_non_dbr_tag(self):
        """Test DRB-controller behaviour with migrateAny: false mode
        **Steps:**
        #. Create DRB Config with migrateAny: false mode
        #. Launch first instance on the host that doesn't have tag and
        immediately starts loading the CPU
        #. Launch second instance that does nothing
        #. Launch third instance that does nothing and has non-drb tag
        #. Check after some time that all instances doesn't migrate
        to another host
        """

        self.create_drb_config(self.load_threshold, migrate_any=False)

        self.server_with_load = self.server_create(
            flavorRef=self.flavor["id"],
            config_drive=True,
            user_data=base64.b64encode(
                self.CPU_LOAD_SCRIPT.encode("utf-8")
            ).decode("utf-8"),
        )

        host = self.ocm.oc.get_server(self.server_with_load.id)["compute_host"]

        self.addCleanup(self.server_delete, self.server_with_load)

        self.server = self.server_create(
            availability_zone=f"nova:{host}",
        )

        self.addCleanup(self.server_delete, self.server)

        self.server_with_non_drb_tag = self.server_create(
            availability_zone=f"nova:{host}",
            tags=[self.EXCLUDE_TAG],
        )

        self.addCleanup(self.server_delete, self.server_with_non_drb_tag)

        time.sleep(CONF.SERVER_LIVE_MIGRATION_TIMEOUT)

        self._check_instance_status(self.server_with_load, host)

        self._check_instance_status(self.server, host)

        self._check_instance_status(self.server_with_non_drb_tag, host)

    def test_balancing_instances_migrate_any_false_drb_tag(self):
        """Test DRB-controller behaviour with migrateAny: false mode and
        instance with drb_tag
        **Steps:**
        #. Create DRB Config with migrateAny: false mode
        #. Launch first instance on the host that doesn't have tag and
        immediately starts loading the CPU
        #. Launch a second instance that does nothing and has drb tag
        #. Launch a third instance that does nothing
        #. Check after some time that instance with drb-tag migrates
        to another host
        """

        self.create_drb_config(self.load_threshold, migrate_any=False)

        self.server_with_load = self.server_create(
            flavorRef=self.flavor["id"],
            user_data=base64.b64encode(
                self.CPU_LOAD_SCRIPT.encode("utf-8")
            ).decode("utf-8"),
            config_drive=True,
        )

        self.addCleanup(self.server_delete, self.server_with_load)

        host = self.ocm.oc.get_server(self.server_with_load.id)["compute_host"]

        self.server_with_drb_tag = self.server_create(
            availability_zone=f"nova:{host}",
            tags=[self.INCLUDE_TAG],
        )

        self.addCleanup(self.server_delete, self.server_with_drb_tag)

        self.server = self.server_create(
            availability_zone=f"nova:{host}",
        )

        self.addCleanup(self.server_delete, self.server)

        waiters.wait_for_instance_migration(
            self.ocm,
            self.server_with_drb_tag,
        )

        self._check_instance_status(self.server, host)

        self._check_instance_status(self.server_with_load, host)
