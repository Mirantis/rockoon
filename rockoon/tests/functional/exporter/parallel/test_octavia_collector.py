import pytest

from rockoon.tests.functional.exporter import base
from rockoon.exporter import constants


@pytest.mark.xdist_group("exporter-compute-network")
class OctaviaCollectorFunctionalTestCase(base.BaseFunctionalExporterTestCase):
    known_metrics = {
        "osdpl_octavia_loadbalancers": {"labels": []},
    }
    scrape_collector = "osdpl_octavia"

    def test_octavia_lb_samples_total(self):
        expected_metrics_count = len(
            constants.LoadbalancerProvisioningStatus
        ) * len(constants.LoadbalancerStatus)

        lb_samples = self.get_metric_after_refresh(
            "osdpl_octavia_loadbalancers", self.scrape_collector
        )
        self.assertEqual(
            expected_metrics_count,
            len(lb_samples.samples),
            "The number of samples for osdpl_octavia_loadbalancers is not correct.",
        )

    def test_octavia_loadbalancers_statuses(self):
        """Octavia Loadbalancers status metrics.


        **Steps:**

        #. Get exporter metric "osdpl_octavia_loadbalancers" with number
        of loadbalancers in the cluster
        #. Check that number of loadbalancer statuses is equal for OS and exporter
        #. Set operation status for the test Loadbalancer to OFFLINE
        #. Check that number of loadbalancer statuses is equal for OS and exporter

        """

        metric_name = "osdpl_octavia_loadbalancers"

        def _test_lb_metrics(metric_name, expected_num, phase):
            lb_total_by_status = {}
            for lb in list(self.ocm.oc.load_balancer.load_balancers()):
                statuses = (lb.operating_status, lb.provisioning_status)
                lb_total_by_status.setdefault(statuses, 0)
                lb_total_by_status[statuses] += 1

            # Check all non-zero values
            service_samples = self.get_metric_after_refresh(
                metric_name, self.scrape_collector
            )
            for statuses, statuses_count in lb_total_by_status.items():
                sample_filter = {
                    "operating_status": statuses[0],
                    "provisioning_status": statuses[1],
                }
                sample = self.filter_metric_samples(
                    service_samples, sample_filter
                )
                self.assertEqual(
                    statuses_count,
                    sample[0].value,
                    f"{phase}: The {metric_name} for {sample_filter} metric value is not correct.",
                )

            metric_lb_total = self.sum_metric_samples(service_samples)
            self.assertEqual(
                metric_lb_total,
                expected_num,
                f"{phase}: The sum  for osdpl_octavia_loadbalancers is not correct.",
            )

        # Check initial number of Loadbalancers
        lbs_num = len(list(self.ocm.oc.load_balancer.load_balancers()))

        # Check LB metrics
        _test_lb_metrics(metric_name, lbs_num, "Before create")

        # Create a test loadbalancer
        test_lb = self.lb_bundle_create()

        # Check LB metrics
        _test_lb_metrics(metric_name, lbs_num + 1, "After create")

        # Set operation status for Loadbalancer to OFFLINE
        self.lb_update(test_lb["id"], admin_state_up=False)

        # Check LB metrics
        _test_lb_metrics(metric_name, lbs_num + 1, "After update")
