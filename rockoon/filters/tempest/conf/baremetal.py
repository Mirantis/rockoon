from rockoon.filters.tempest import base_section

IRONIC_MICROVERSION_RELEASE_MAPPING = {
    "ussuri": {"min_microversion": "1.1", "max_microversion": "1.65"},
    "train": {"min_microversion": "1.1", "max_microversion": "1.58"},
    "stein": {"min_microversion": "1.1", "max_microversion": "1.56"},
    "rocky": {"min_microversion": "1.1", "max_microversion": "1.46"},
    "queens": {"min_microversion": "1.1", "max_microversion": "1.38"},
    "pike": {"min_microversion": "1.1", "max_microversion": "1.34"},
    "ocata": {"min_microversion": "1.1", "max_microversion": "1.31"},
    "newton": {"min_microversion": "1.1", "max_microversion": "1.22"},
    "mitaka": {"min_microversion": "1.1", "max_microversion": "1.16"},
}


class Baremetal(base_section.BaseSection):
    name = "baremetal"
    options = [
        "active_timeout",
        "adjusted_root_disk_size_gb",
        "association_timeout",
        "available_nodes",
        "boot_mode",
        "catalog_type",
        "default_rescue_interface",
        "deploywait_timeout",
        "driver",
        "enabled_bios_interfaces",
        "enabled_boot_interfaces",
        "enabled_deploy_interfaces",
        "enabled_drivers",
        "enabled_hardware_types",
        "enabled_rescue_interfaces",
        "endpoint_type",
        "max_microversion",
        "min_microversion",
        "partition_image_ref",
        "power_timeout",
        "rescue_timeout",
        "unprovision_timeout",
        "unrescue_timeout",
        "use_provision_network",
        "whole_disk_image_checksum",
        "whole_disk_image_ref",
        "whole_disk_image_url",
        "tenant_network_types",
    ]

    @property
    def active_timeout(self):
        pass

    @property
    def adjusted_root_disk_size_gb(self):
        pass

    @property
    def available_nodes(self):
        pass

    @property
    def association_timeout(self):
        pass

    @property
    def boot_mode(self):
        pass

    @property
    def catalog_type(self):
        pass

    @property
    def default_rescue_interface(self):
        pass

    @property
    def deploywait_timeout(self):
        pass

    @property
    def driver(self):
        pass

    @property
    def enabled_bios_interfaces(self):
        if self.is_service_enabled("ironic"):
            return self.get_values_item(
                "ironic", "conf.ironic.DEFAULT.enabled_bios_interfaces"
            )

    @property
    def enabled_boot_interfaces(self):
        if self.is_service_enabled("ironic"):
            return self.get_values_item(
                "ironic", "conf.ironic.DEFAULT.enabled_boot_interfaces"
            )

    @property
    def enabled_deploy_interfaces(self):
        if self.is_service_enabled("ironic"):
            return self.get_values_item(
                "ironic", "conf.ironic.DEFAULT.enabled_deploy_interfaces"
            )

    @property
    def enabled_drivers(self):
        pass

    @property
    def enabled_hardware_types(self):
        if self.is_service_enabled("ironic"):
            return self.get_values_item(
                "ironic", "conf.ironic.DEFAULT.enabled_hardware_types"
            )

    @property
    def enabled_rescue_interfaces(self):
        if self.is_service_enabled("ironic"):
            return self.get_values_item(
                "ironic", "conf.ironic.DEFAULT.enabled_rescue_interfaces"
            )

    @property
    def endpoint_type(self):
        pass

    @property
    def max_microversion(self):
        ironic_enabled = self.is_service_enabled("ironic")
        version = self.spec["openstack_version"]
        if (
            ironic_enabled
            and version
            and version in IRONIC_MICROVERSION_RELEASE_MAPPING
        ):
            return IRONIC_MICROVERSION_RELEASE_MAPPING[version][
                "max_microversion"
            ]

    @property
    def min_microversion(self):
        ironic_enabled = self.is_service_enabled("ironic")
        version = self.spec["openstack_version"]
        if (
            ironic_enabled
            and version
            and version in IRONIC_MICROVERSION_RELEASE_MAPPING
        ):
            return IRONIC_MICROVERSION_RELEASE_MAPPING[version][
                "min_microversion"
            ]

    @property
    def partition_image_ref(self):
        pass

    @property
    def power_timeout(self):
        pass

    @property
    def rescue_timeout(self):
        pass

    @property
    def unprovision_timeout(self):
        pass

    @property
    def unrescue_timeout(self):
        pass

    @property
    def use_provision_network(self):
        pass

    @property
    def whole_disk_image_checksum(self):
        pass

    @property
    def whole_disk_image_ref(self):
        pass

    @property
    def whole_disk_image_url(self):
        pass

    @property
    def tenant_network_types(self):
        return self.get_values_item(
            "neutron", "conf.plugins.ml2_conf.ml2.tenant_network_types"
        )
