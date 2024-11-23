from rockoon.filters.tempest import base_section


class Dns(base_section.BaseSection):
    name = "dns"
    options = [
        "build_interval",
        "build_timeout",
        "catalog_type",
        "endpoint_type",
        "min_ttl",
        "nameservers",
        "query_timeout",
        "zone_id",
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
    def min_ttl(self):
        pass

    @property
    def nameservers(self):
        pass

    @property
    def query_timeout(self):
        pass

    @property
    def zone_id(self):
        pass
