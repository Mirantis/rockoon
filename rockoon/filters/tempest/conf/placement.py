from rockoon.filters.tempest import base_section

MICROVERSION_RELEASE_MAPPING = {
    "placement": {"min_microversion": "1.0", "max_microversion": "1.39"},
    "antelope": {"min_microversion": "1.0", "max_microversion": "1.39"},
    "yoga": {"min_microversion": "1.0", "max_microversion": "1.39"},
    "xena": {"min_microversion": "1.0", "max_microversion": "1.37"},
    "wallaby": {"min_microversion": "1.0", "max_microversion": "1.36"},
    "victoria": {"min_microversion": "1.0", "max_microversion": "1.36"},
}


class Placement(base_section.BaseSection):
    name = "placement"
    options = [
        "max_microversion",
        "min_microversion",
    ]

    @property
    def max_microversion(self):
        version = self.spec["openstack_version"]
        if version and version in MICROVERSION_RELEASE_MAPPING:
            return MICROVERSION_RELEASE_MAPPING[version]["max_microversion"]

    @property
    def min_microversion(self):
        version = self.spec["openstack_version"]
        if version and version in MICROVERSION_RELEASE_MAPPING:
            return MICROVERSION_RELEASE_MAPPING[version]["min_microversion"]
