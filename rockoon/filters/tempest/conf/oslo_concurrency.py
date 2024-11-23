from rockoon.filters.tempest import base_section


class OsloConcurrency(base_section.BaseSection):
    name = "oslo_concurrency"
    options = ["disable_process_locking", "lock_path"]

    @property
    def disable_process_locking(self):
        pass

    @property
    def lock_path(self):
        pass
