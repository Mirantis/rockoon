from rockoon.filters.tempest import base_section


class ServiceAvailable(base_section.BaseSection):
    name = "service_available"
    options = [
        "aodh",
        "barbican",
        "cinder",
        "ceilometer",
        "contrail",
        "designate",
        "glance",
        "gnocchi",
        "heat",
        "ironic",
        "manila",
        "neutron",
        "nova",
        "panko",
        "sahara",
        "swift",
        "horizon",
        "keystone",
        "load_balancer",
    ]

    @property
    def aodh(self):
        return self.is_service_enabled("aodh")

    @property
    def barbican(self):
        return self.is_service_enabled("barbican")

    @property
    def cinder(self):
        return self.is_service_enabled("cinder")

    @property
    def ceilometer(self):
        return self.is_service_enabled("ceilometer")

    @property
    def contrail(self):
        if self.tf_enabled():
            return True
        else:
            return False

    @property
    def designate(self):
        return self.is_service_enabled("designate")

    @property
    def glance(self):
        return self.is_service_enabled("glance")

    @property
    def gnocchi(self):
        return self.is_service_enabled("gnocchi")

    @property
    def heat(self):
        return self.is_service_enabled("heat")

    @property
    def ironic(self):
        return self.is_service_enabled("ironic")

    @property
    def manila(self):
        return self.is_service_enabled("manila")

    @property
    def neutron(self):
        return self.is_service_enabled("neutron")

    @property
    def nova(self):
        return self.is_service_enabled("nova")

    @property
    def panko(self):
        return self.is_service_enabled("panko")

    @property
    def sahara(self):
        return self.is_service_enabled("sahara")

    @property
    def swift(self):
        return self.is_service_enabled("ceph-rgw")

    @property
    def horizon(self):
        return self.is_service_enabled("horizon")

    @property
    def keystone(self):
        return self.is_service_enabled("keystone")

    @property
    def load_balancer(self):
        return self.is_service_enabled("octavia")
