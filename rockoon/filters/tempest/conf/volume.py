from rockoon.filters.tempest import base_section

MICROVERSION_RELEASE_MAPPING = {
    "caracal": {"min_microversion": "3.0", "max_microversion": "3.71"},
    "antelope": {"min_microversion": "3.0", "max_microversion": "3.70"},
    "yoga": {"min_microversion": "3.0", "max_microversion": "3.68"},
    "xena": {"min_microversion": "3.0", "max_microversion": "3.66"},
    "wallaby": {"min_microversion": "3.0", "max_microversion": "3.64"},
    "victoria": {"min_microversion": "3.0", "max_microversion": "3.62"},
    "ussuri": {"min_microversion": "3.0", "max_microversion": "3.60"},
    "train": {"min_microversion": "3.0", "max_microversion": "3.59"},
    "stein": {"min_microversion": "3.0", "max_microversion": "3.59"},
    "rocky": {"min_microversion": "3.0", "max_microversion": "3.55"},
    "queens": {"min_microversion": "3.0", "max_microversion": "3.50"},
}


class Volume(base_section.BaseSection):
    name = "volume"
    options = [
        "backend_names",
        "build_interval",
        "build_timeout",
        "catalog_type",
        "disk_format",
        "endpoint_type",
        "manage_snapshot_ref",
        "manage_volume_ref",
        "max_microversion",
        "min_microversion",
        "region",
        "storage_protocol",
        "vendor_name",
        "volume_size",
        "scheduler_default_filters",
        "volume_type_multiattach",
    ]

    @property
    def enabled(self):
        return self.is_service_enabled("cinder")

    @property
    def backend_names(self):
        pass

    @property
    def build_interval(self):
        pass

    @property
    def build_timeout(self):
        pass

    @property
    def catalog_type(self):
        return "volumev3"

    @property
    def disk_format(self):
        pass

    @property
    def endpoint_type(self):
        pass

    @property
    def manage_snapshot_ref(self):
        pass

    @property
    def manage_volume_ref(self):
        pass

    @property
    def max_microversion(self):
        version = self.spec["openstack_version"]
        return MICROVERSION_RELEASE_MAPPING.get(version, {}).get(
            "max_microversion"
        )

    @property
    def min_microversion(self):
        version = self.spec["openstack_version"]
        return MICROVERSION_RELEASE_MAPPING.get(version, {}).get(
            "min_microversion"
        )

    @property
    def region(self):
        return self.get_spec_item("region_name", "RegionOne")

    @property
    def storage_protocol(self):
        backend = self.get_values_item("cinder", "storage")

        # TODO: Add more backends here
        protocol_map = {"ceph": "ceph"}
        return protocol_map.get(backend)

    @property
    def vendor_name(self):
        pass

    @property
    def volume_size(self):
        # Some tests use volume_size to boot an instance and it should be an
        # equal disk of used flavor described in flavor_ref. By default,
        # this value will be equal to 1.
        flavor_ref = self.get_spec_item(
            "services.tempest.tempest.values.conf.convert_to_uuid.compute.flavor_ref"
        )
        flavors = self.get_values_item(
            "nova", "bootstrap.structured.flavors.options", {}
        )
        default_flavors_disks = {
            "m1.tiny": 1,
            "m1.small": 20,
            "m1.medium": 40,
            "m1.large": 80,
            "m1.xlarge": 160,
        }
        if flavor_ref:
            return flavors.get(flavor_ref, {}).get(
                "disk"
            ) or default_flavors_disks.get(flavor_ref)

    @property
    def scheduler_default_filters(self):
        scheduler_default_filters = self.get_values_item(
            "cinder", "conf.cinder.DEFAULT.scheduler_default_filters", None
        )
        return scheduler_default_filters

    @property
    def volume_type_multiattach(self):
        for volume_type, volume_type_prop in self.get_values_item(
            "cinder", "bootstrap.volume_types"
        ).items():
            if "multiattach" in volume_type_prop.keys():
                return volume_type
