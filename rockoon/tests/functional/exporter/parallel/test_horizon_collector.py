import asyncio
import pytest

from rockoon import kube

from rockoon.tests.functional.exporter import base


@pytest.mark.xdist_group(name="exporter-horizon")
class HorizonCollectorFunctionalTestCase(base.BaseFunctionalExporterTestCase):
    known_metrics = {
        "osdpl_horizon_login_success": {
            "labels": [
                "authentication_method",
                "url",
                "user_domain_name",
                "username",
            ]
        },
        "osdpl_horizon_login_latency": {"labels": ["type", "url"]},
    }
    scrape_collector = "osdpl_horizon"

    @property
    def horizon_deployment(self):
        return kube.find(
            kube.Deployment,
            "horizon",
            namespace="openstack",
        )

    @classmethod
    def setUpClass(cls):
        cls.horizon_pod_count = kube.find(
            kube.Deployment,
            "horizon",
            namespace="openstack",
        ).obj["spec"]["replicas"]

    @classmethod
    def tearDownClass(cls):
        asyncio.run(
            kube.find(
                kube.Deployment,
                "horizon",
                namespace="openstack",
            ).wait_for_replicas(cls.horizon_pod_count)
        )

    def setUp(self):
        super().setUp()
        asyncio.run(
            self.horizon_deployment.wait_for_replicas(self.horizon_pod_count)
        )

    def tearDown(self):
        if (
            self.horizon_pod_count
            != self.horizon_deployment.obj["spec"]["replicas"]
        ):
            self.horizon_deployment.scale(self.horizon_pod_count)
        super().tearDown()

    def test_osdpl_horizon_login_success(self):
        self.assert_metric_value(
            "osdpl_horizon_login_success",
            1.0,
            "Horizon",
        )

    def test_horizon_login_latency(self):
        metric = self.get_metric_after_refresh(
            "osdpl_horizon_login_latency", self.scrape_collector
        )
        self.assertIsNotNone(metric)
        self.assertTrue(len(metric.samples) > 0)
        for sample in metric.samples:
            self.assertTrue(
                sample.value < 120.0,
                "Login to Horizon took more than 120 seconds",
            )

    def test_horizon_login_success_negative(self):
        self.horizon_deployment.scale(0)
        asyncio.run(self.horizon_deployment.wait_for_replicas(0))
        self.assert_metric_value(
            "osdpl_horizon_login_success",
            0.0,
            "After scaling Horizon pods to 0",
        )
        self.horizon_deployment.scale(self.horizon_pod_count)
        asyncio.run(
            self.horizon_deployment.wait_for_replicas(self.horizon_pod_count)
        )
