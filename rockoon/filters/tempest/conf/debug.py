from rockoon.filters.tempest import base_section


class Debug(base_section.BaseSection):
    name = "debug"
    options = ["trace_requests"]

    @property
    def trace_requests(self):
        pass
