from rockoon.filters.tempest import base_section


MICROVERSION_RELEASE_MAPPING = {
    "caracal": {"min_microversion": "2.1", "max_microversion": "2.96"},
    "antelope": {"min_microversion": "2.1", "max_microversion": "2.95"},
    "yoga": {"min_microversion": "2.1", "max_microversion": "2.90"},
    "xena": {"min_microversion": "2.1", "max_microversion": "2.90"},
    "wallaby": {"min_microversion": "2.1", "max_microversion": "2.88"},
    "victoria": {"min_microversion": "2.1", "max_microversion": "2.87"},
    "ussuri": {"min_microversion": "2.1", "max_microversion": "2.87"},
    "train": {"min_microversion": "2.1", "max_microversion": "2.79"},
    "stein": {"min_microversion": "2.1", "max_microversion": "2.72"},
    "rocky": {"min_microversion": "2.1", "max_microversion": "2.65"},
    "queens": {"min_microversion": "2.1", "max_microversion": "2.60"},
    "pike": {"min_microversion": "2.1", "max_microversion": "2.53"},
    "ocata": {"min_microversion": "2.1", "max_microversion": "2.42"},
    "newton": {"min_microversion": "2.1", "max_microversion": "2.42"},
    "mitaka": {"min_microversion": "2.1", "max_microversion": "2.42"},
}


class Compute(base_section.BaseSection):
    name = "compute"
    options = [
        "build_interval",
        "build_timeout",
        "catalog_type",
        "compute_volume_common_az",
        "endpoint_type",
        "fixed_network_name",
        "flavor_ref",
        "flavor_ref_alt",
        "hypervisor_type",
        "image_ref",
        "image_ref_alt",
        "image_raw_ref",
        "max_microversion",
        "min_compute_nodes",
        "min_microversion",
        "ready_wait",
        "region",
        "shelved_offload_time",
        "volume_device_name",
    ]

    @property
    def build_interval(self):
        pass

    @property
    def build_timeout(self):
        pass

    @property
    def catalog_type(self):
        pass

    @property
    def compute_volume_common_az(self):
        return self.get_values_item(
            "nova", "conf.nova.DEFAULT.default_schedule_zone", "nova"
        )

    @property
    def endpoint_type(self):
        pass

    @property
    def fixed_network_name(self):
        pass

    @property
    def flavor_ref(self):
        pass

    @property
    def flavor_ref_alt(self):
        pass

    @property
    def hypervisor_type(self):
        pass

    @property
    def image_ref(self):
        pass

    @property
    def image_ref_alt(self):
        pass

    @property
    def image_raw_ref(self):
        pass

    @property
    def max_microversion(self):
        nova_enabled = self.is_service_enabled("nova")
        version = self.spec["openstack_version"]
        if (
            nova_enabled
            and version
            and version in MICROVERSION_RELEASE_MAPPING
        ):
            return MICROVERSION_RELEASE_MAPPING[version]["max_microversion"]

    @property
    def min_compute_nodes(self):
        pass

    @property
    def min_microversion(self):
        nova_enabled = self.is_service_enabled("nova")
        version = self.spec["openstack_version"]
        if (
            nova_enabled
            and version
            and version in MICROVERSION_RELEASE_MAPPING
        ):
            return MICROVERSION_RELEASE_MAPPING[version]["min_microversion"]

    @property
    def ready_wait(self):
        pass

    @property
    def region(self):
        return self.get_spec_item("region_name", "RegionOne")

    @property
    def shelved_offload_time(self):
        shelved_offload_time = self.get_values_item(
            "nova", "conf.nova.DEFAULT.shelved_offload_time"
        )
        # NOTE(vsaienko): we use 5G flavors, it takes significant time to take a snapshot and
        # push it to glance. Give extra time here explicitly for shelved tests.
        if not shelved_offload_time:
            shelved_offload_time = 300
        return shelved_offload_time

    @property
    def volume_device_name(self):
        pass
