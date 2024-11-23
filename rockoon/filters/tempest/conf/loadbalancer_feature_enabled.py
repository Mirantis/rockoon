from rockoon import constants
from rockoon.filters.tempest import base_section


class LoadBalancerFeatureEnabled(base_section.BaseSection):
    name = "loadbalancer-feature-enabled"
    options = [
        "not_implemented_is_error",
        "health_monitor_enabled",
        "terminated_tls_enabled",
        "l7_protocol_enabled",
        "pool_algorithms_enabled",
        "l4_protocol",
        "spare_pool_enabled",
        "session_persistence_enabled",
        "force_cleanup_enabled",
    ]

    @property
    def enabled(self):
        return self.is_service_enabled("octavia")

    def _ovn_enabled(self):
        return "ovn" in self.get_values_item(
            "octavia",
            "conf.octavia.api_settings.default_provider_driver",
            "amphora",
        )

    @property
    def not_implemented_is_error(self):
        if self.tf_enabled():
            return False
        if self._ovn_enabled():
            return False

    @property
    def health_monitor_enabled(self):
        if self.tf_enabled():
            return False

    @property
    def terminated_tls_enabled(self):
        if self.tf_enabled():
            return False

    @property
    def l7_protocol_enabled(self):
        if self._ovn_enabled():
            return False

    @property
    def pool_algorithms_enabled(self):
        if self._ovn_enabled():
            return False

    @property
    def l4_protocol(self):
        pass

    @property
    def spare_pool_enabled(self):
        pass

    @property
    def session_persistence_enabled(self):
        if self._ovn_enabled():
            return False

    @property
    def force_cleanup_enabled(self):
        if (
            self.spec["openstack_version"] != "master"
            and constants.OpenStackVersion[self.spec["openstack_version"]]
            >= constants.OpenStackVersion["victoria"]
        ):
            return True
