from rockoon.filters.tempest import base_section


class BaremetalFeatureEnabled(base_section.BaseSection):
    name = "baremetal_feature_enabled"
    options = ["ipxe_enabled", "adoption", "fast_track_discovery"]

    @property
    def ipxe_enabled(self):
        if self.is_service_enabled("ironic"):
            if "ipxe" in self.get_values_item(
                "ironic", "conf.ironic.DEFAULT.enabled_boot_interfaces"
            ):
                return True
            else:
                return False

    @property
    def adoption(self):
        pass

    @property
    def fast_track_discovery(self):
        if self.is_service_enabled("ironic"):
            return self.get_values_item(
                "ironic", "conf.ironic.DEFAULT.fast_track", False
            )
