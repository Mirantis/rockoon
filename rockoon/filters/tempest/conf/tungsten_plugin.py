from rockoon.filters.tempest import base_section


class TungstenPlugin(base_section.BaseSection):
    name = "sdn"
    options = [
        "service_name",
        "endpoint_type",
        "catalog_type",
        "contrail_version",
    ]

    @property
    def service_name(self):
        return "opencontrail"

    @property
    def endpoint_type(self):
        return "internal"

    @property
    def catalog_type(self):
        pass

    @property
    def contrail_version(self):
        pass
