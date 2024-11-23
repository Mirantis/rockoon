from rockoon.filters.tempest import base_section


class Orchestration(base_section.BaseSection):
    name = "orchestration"
    options = [
        "build_interval",
        "build_timeout",
        "catalog_type",
        "endpoint_type",
        "instance_type",
        "keypair_name",
        "max_resources_per_stack",
        "max_template_size",
        "region",
        "stack_owner_role",
        "stack_user_role",
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
    def endpoint_type(self):
        pass

    @property
    def instance_type(self):
        pass

    @property
    def keypair_name(self):
        pass

    @property
    def max_resources_per_stack(self):
        pass

    @property
    def max_template_size(self):
        pass

    @property
    def region(self):
        return self.get_spec_item("region_name", "RegionOne")

    @property
    def stack_owner_role(self):
        pass

    @property
    def stack_user_role(self):
        pass
