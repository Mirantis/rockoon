import yaml

from rockoon import constants
from rockoon.filters.tempest import base_section


class Telemetry(base_section.BaseSection):
    name = "telemetry"
    options = [
        "alarm_granularity",
        "alarm_threshold",
    ]

    @property
    def alarm_granularity(self):
        ceilometer_enabled = self.is_service_enabled("ceilometer")
        if ceilometer_enabled:
            archive_policy_values = {
                "ceilometer-low": 60,
                "ceilometer-low-rate": 60,
                "ceilometer-high-static": 3600,
                "ceilometer-high-static-rate": 3600,
            }

            # NOTE(pas-ha) we pass ceilo YAML config files as text
            gnocchi_resources_text = self.get_values_item(
                "ceilometer", "conf.gnocchi_resources", "{}"
            )
            gnocchi_resources = yaml.safe_load(gnocchi_resources_text)
            resources = gnocchi_resources.get("resources", [])
            for res in resources:
                # check all resources and find the first with type instance and
                # return granularity related to policy name in archive_policy_values
                if res.get("resource_type") == "instance" and isinstance(
                    res.get("metrics"), dict
                ):
                    policy_name = (
                        res["metrics"]
                        .get("cpu", {})
                        .get("archive_policy_name")
                    )
                    if (
                        policy_name
                        and policy_name in archive_policy_values.keys()
                    ):
                        return archive_policy_values[policy_name]

    @property
    def alarm_threshold(self):
        """Calculate correct alarm threshold for gnocchi alarm

        since the 'cpu' metric the tests are using is just
        'nanoseconds used by all vCPUs of the instance',
        we need to convert the user-friendly 'cpu utilization in %'
        into those nanoseconds.
        The formula is thus

        (cpu_util_percent / 100) * N_of_vcpus * granularity * 10^9 ns
        """
        if not self.is_service_enabled("ceilometer"):
            return
        version = constants.OpenStackVersion[self.spec["openstack_version"]]
        if version < constants.OpenStackVersion.antelope:
            return
        granularity = self.alarm_granularity
        if not granularity:
            return
        # use the same 10% the default of this option is
        target_cpu_util = 0.1
        # NOTE(pas-ha): ideally this has to be fetched from nova flavor,
        # but the script that loads CPU is single threaded,
        # so it has no sense to use multi-core flavors for this test
        vcpus = 1
        # NOTE(pas-ha) YAML renderer in helm has a bug with large integers
        # https://github.com/helm/helm/issues/12195
        # thus we convert it to string to prevent mangling
        return str(int(target_cpu_util * vcpus * granularity * 1e9))
