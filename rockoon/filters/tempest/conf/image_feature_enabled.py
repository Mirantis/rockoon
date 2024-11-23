from rockoon.filters.tempest import base_section


class ImageFeatureEnabled(base_section.BaseSection):
    name = "image-feature-enabled"
    options = [
        "api_v1",
        "api_v2",
        "deactivate_image",
        "import_image",
        "os_glance_reserved",
    ]

    @property
    def api_v1(self):
        return False

    @property
    def api_v2(self):
        return True

    @property
    def deactivate_image(self):
        return True

    @property
    def import_image(self):
        return True

    @property
    def os_glance_reserved(self):
        return True
