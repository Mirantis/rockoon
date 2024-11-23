from rockoon.filters.tempest import base_section


class ServiceClients(base_section.BaseSection):
    name = "service-clients"
    options = ["http_timeout", "proxy_url"]

    @property
    def http_timeout(self):
        pass

    @property
    def proxy_url(self):
        pass
