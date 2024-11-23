from parameterized import parameterized
import pytest

from rockoon import constants as const
from rockoon.exporter import constants
from rockoon.tests.functional.exporter import base
from rockoon.tests.functional import waiters as wait
from rockoon.tests.functional import config


CONF = config.Config()


@pytest.mark.xdist_group("exporter-volume")
class CinderCollectorFunctionalTestCase(base.BaseFunctionalExporterTestCase):
    scrape_collector = "osdpl_cinder"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

    known_metrics = {
        "osdpl_cinder_volumes": {"labels": []},
        "osdpl_cinder_volumes_size": {"labels": []},
        "osdpl_cinder_zone_volumes": {"labels": []},
        "osdpl_cinder_snapshots": {"labels": []},
        "osdpl_cinder_snapshots_size": {"labels": []},
        "osdpl_cinder_pool_total_capacity": {"labels": ["name"]},
        "osdpl_cinder_pool_free_capacity": {"labels": ["name"]},
        "osdpl_cinder_pool_allocated_capacity": {"labels": ["name"]},
    }

    def _test_cinder_volumes(self, metric_name, expected_value, phase):
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            int(metric.samples[0].value),
            expected_value,
            f"{phase}: Number of volumes is not correct.",
        )

    @classmethod
    def openstack_version(cls, version=None):
        if version is None:
            version = cls.osdpl.obj["spec"]["openstack_version"]
        return const.OpenStackVersion[version.lower()].value

    def test_osdpl_cinder_volumes(self):
        """Total number of volumes in the cluster."""

        metric_name = "osdpl_cinder_volumes"
        volumes = len(list(self.ocm.oc.volume.volumes(all_tenants=True)))
        self._test_cinder_volumes(metric_name, volumes, "Before create")

        # Create one test volume
        created_volume = self.volume_create()
        self._test_cinder_volumes(metric_name, volumes + 1, "After create")

        # Delete volume and check that the volumes metric is changed
        self.volume_delete(created_volume)
        self._test_cinder_volumes(metric_name, volumes, "After delete")

    def _test_cinder_volumes_size(self, expected_value, phase):
        metric_name = "osdpl_cinder_volumes_size"
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            int(metric.samples[0].value),
            expected_value,
            f"{phase}: The total volume's size in bytes is not correct.",
        )

    def test_osdpl_cinder_volumes_size(self):
        """Total volumes size in the cluster."""

        volumes_size = self.get_volumes_size()
        self._test_cinder_volumes_size(volumes_size, "Before create")

        # Create one test volume
        created_volume = self.volume_create(size=1)
        self._test_cinder_volumes_size(
            volumes_size + 1 * constants.Gi, "After create"
        )

        # Delete volume and check that a volume_size metric has changed
        self.volume_delete(created_volume)
        self._test_cinder_volumes_size(volumes_size, "After delete")

    def _test_volume_snapshots_count(self, expected_value, phase):
        metric_name = "osdpl_cinder_snapshots"
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            int(metric.samples[0].value),
            expected_value,
            "{phase}: The number of snapshots is not correct.",
        )

    def test_volume_snapshots(self):
        """Total number of volume snapshots in the cluster."""

        snapshots = len(list(self.ocm.oc.volume.snapshots(all_tenants=True)))
        self._test_volume_snapshots_count(snapshots, "Before create")

        # Create one test volume and one volume snapshot
        volume = self.volume_create()
        snapshot = self.volume_snapshot_create(volume)
        self._test_volume_snapshots_count(snapshots + 1, "After create")

        # Delete Volume's snapshot and check that a volume's snapshot metric is changed
        self.snapshot_volume_delete(snapshot, wait=True)
        self._test_volume_snapshots_count(snapshots, "After delete")

    def _test_volume_snapshots_size(self, expected_value, phase):
        metric_name = "osdpl_cinder_snapshots_size"
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            int(metric.samples[0].value),
            expected_value,
            "{phase}: The number of snapshots size is not correct.",
        )

    def test_volume_snapshots_size(self):
        """Total size of volume snapshots in the cluster."""

        snapshots_size = self.get_volume_snapshots_size()
        self._test_volume_snapshots_size(snapshots_size, "Before create")

        # Create one test volume and one volume snapshot
        volume = self.volume_create()
        snapshot = self.volume_snapshot_create(volume)
        self._test_volume_snapshots_size(
            snapshots_size + 1 * constants.Gi, "After create"
        )

        # Delete Volume's snapshot and check that a volume's snapshot metric is changed
        self.snapshot_volume_delete(snapshot, wait=True)
        self._test_volume_snapshots_size(snapshots_size, "After delete")

    @parameterized.expand(
        [
            ("osdpl_cinder_pool_free_capacity"),
            ("osdpl_cinder_pool_total_capacity"),
            ("osdpl_cinder_pool_allocated_capacity"),
        ]
    )
    def test_osdpl_cinder_pool_samples_count(self, metric_name):
        total_pools = len(list(self.ocm.oc.volume.backend_pools()))
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            len(metric.samples),
            total_pools,
            "The number of samples for {metric_name} is not correct.",
        )

    def _test_cinder_pool_metric(
        self, metric_name, pool_name, expected_value, phase
    ):
        """
        Checks that sample for specific metric is equal to expected value
        """
        associated_metric = self.filter_metric_samples(
            self.get_metric_after_refresh(metric_name, self.scrape_collector),
            {"name": pool_name},
        )
        self.assertEqual(
            associated_metric[0].value,
            expected_value,
            f"{phase}: The expected value for {metric_name} for pool "
            f"{pool_name} is not correct.",
        )

    def test_openstack_cinder_pool_total_capacity(self):
        """Total capacity in bytes of cinder backend pools in environment."""

        metric_name = "osdpl_cinder_pool_total_capacity"
        for pool in self.ocm.oc.volume.backend_pools():
            pool_name = pool["name"]
            capacity = pool["capabilities"].get("total_capacity_gb") * (
                constants.Gi
            )

            self._test_cinder_pool_metric(
                metric_name, pool_name, capacity, "Before create"
            )
            timestamp = self.get_cinder_pool_timestamp(pool_name)
            self.volume_create(size=5, image=CONF.CIRROS_TEST_IMAGE_NAME)
            wait.wait_cinder_pool_updated(
                self.get_cinder_pool_timestamp, pool_name, timestamp
            )
            self._test_cinder_pool_metric(
                metric_name, pool_name, capacity, "After create"
            )

    @parameterized.expand(
        [
            # ("empty", None, 5),
            ("3Gb", CONF.UBUNTU_TEST_IMAGE_NAME, 3),
        ]
    )
    def test_openstack_cinder_pool_free_capacity(
        self, _, image_name, volume_size
    ):
        """Free capacity in bytes of cinder backend pools in environment."""
        metric_name = "osdpl_cinder_pool_free_capacity"

        if self.openstack_version() <= self.openstack_version("queens"):
            self.skipTest("Disabled for Queens and older")

        create_timeout = (
            CONF.VOLUME_MEDIUM_CREATE_TIMEOUT if image_name else None
        )

        def get_capacity_bytes(_pool: dict):
            return _pool["capabilities"].get("free_capacity_gb") * constants.Gi

        # wait until all cinder pool timestamps updated
        pools = list(self.ocm.oc.volume.backend_pools())
        timestamp = max(
            _pool["capabilities"].get("timestamp") for _pool in pools
        )
        for pool in pools:
            pool_name = pool["name"]
            wait.wait_cinder_pool_updated(
                self.get_cinder_pool_timestamp, pool_name, timestamp
            )

        # Create volume and check metrics
        volume = self.volume_create(
            size=volume_size,
            image=image_name,
            timeout=create_timeout,
        )
        volume_pool = self.get_pool_by_volume(volume)
        wait.wait_cinder_pool_updated(
            self.get_cinder_pool_timestamp, volume_pool["name"]
        )

        for pool in list(self.ocm.oc.volume.backend_pools()):
            pool_name = pool["name"]
            capacity_current = get_capacity_bytes(pool)
            # Check metric for each pool
            self._test_cinder_pool_metric(
                metric_name,
                pool_name,
                capacity_current,
                f"After create volume with size {volume_size} Gb ",
            )

        # Remove a test volume
        self.volume_delete(volume)
        wait.wait_cinder_pool_updated(
            self.get_cinder_pool_timestamp, volume_pool["name"]
        )

        for pool in list(self.ocm.oc.volume.backend_pools()):
            pool_name = pool["name"]

            capacity_current = get_capacity_bytes(pool)
            self._test_cinder_pool_metric(
                metric_name,
                pool_name,
                capacity_current,
                "After remove volume",
            )

    def test_openstack_cinder_pool_allocated_capacity(self):
        """Allocated capacity in bytes of cinder backend pools in environment."""

        if self.openstack_version() <= self.openstack_version("queens"):
            self.skipTest("Disabled for Queens and older")
        # wait until all cinder pool timestamps updated
        pool_list = list(self.ocm.oc.volume.backend_pools())
        for pool in pool_list:
            pool_name = pool["name"]
            wait.wait_cinder_pool_updated(
                self.get_cinder_pool_timestamp, pool_name
            )

        metric_name = "osdpl_cinder_pool_allocated_capacity"
        pools_allocated_capacity = {}

        for pool in list(self.ocm.oc.volume.backend_pools()):
            pool_name = pool["name"]
            capacity = pool["capabilities"].get("allocated_capacity_gb") * (
                constants.Gi
            )
            pools_allocated_capacity[pool_name] = capacity

            self._test_cinder_pool_metric(
                metric_name,
                pool_name,
                capacity,
                "Before create",
            )

        # Create a test volume
        test_volume = self.volume_create(
            size=5, image=CONF.CIRROS_TEST_IMAGE_NAME
        )

        volume_pool = self.get_pool_by_volume(test_volume)
        wait.wait_cinder_pool_updated(
            self.get_cinder_pool_timestamp, volume_pool["name"]
        )

        for pool in list(self.ocm.oc.volume.backend_pools()):
            pool_name = pool["name"]
            capacity = pool["capabilities"].get("allocated_capacity_gb") * (
                constants.Gi
            )

            self._test_cinder_pool_metric(
                metric_name,
                pool_name,
                capacity,
                "After create non empty volume",
            )

        # Remove a test volume
        self.volume_delete(test_volume)
        wait.wait_cinder_pool_updated(
            self.get_cinder_pool_timestamp, volume_pool["name"]
        )
        for pool in list(self.ocm.oc.volume.backend_pools()):
            pool_name = pool["name"]
            capacity = pool["capabilities"].get("allocated_capacity_gb") * (
                constants.Gi
            )

            self._test_cinder_pool_metric(
                metric_name,
                pool_name,
                capacity,
                "After remove non-empty volume",
            )

    def test_osdpl_cinder_zone_volumes(self):
        """Total number of volumes' zones in the cluster."""

        metric_name = "osdpl_cinder_zone_volumes"
        availability_zone = list(self.ocm.oc.volume.availability_zones())[0][
            "name"
        ]

        volumes = len(
            list(
                self.ocm.oc.volume.volumes(
                    availability_zone=availability_zone, all_tenants=True
                )
            )
        )
        self._test_cinder_volumes(metric_name, volumes, "Before create")

        # Create one test volume
        created_volume = self.volume_create(
            availability_zone=availability_zone
        )
        self._test_cinder_volumes(metric_name, volumes + 1, "After create")

        # Delete volume and check that the zone's volumes metric is changed
        self.volume_delete(created_volume)
        self._test_cinder_volumes(metric_name, volumes, "After delete")

    def test_osdpl_cinder_zone_volumes_count(self):
        total_zones = len(list(self.ocm.oc.volume.availability_zones()))
        metric = self.get_metric_after_refresh(
            "osdpl_cinder_zone_volumes", self.scrape_collector
        )
        self.assertEqual(
            len(metric.samples),
            total_zones,
            "The number of samples for osdpl_cinder_zone_volumes is not correct.",
        )
