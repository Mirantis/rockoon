from parameterized import parameterized
import pytest

from rockoon import constants as const
from rockoon.exporter import constants
from rockoon.tests.functional.exporter import base
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
