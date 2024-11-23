from rockoon.filters.tempest import base_section


class Scenario(base_section.BaseSection):
    name = "scenario"
    options = [
        "aki_img_file",
        "ami_img_file",
        "ari_img_file",
        "dhcp_client",
        "img_container_format",
        "img_dir",
        "img_disk_format",
        "img_file",
        "img_properties",
    ]

    @property
    def aki_img_file(self):
        pass

    @property
    def ami_img_file(self):
        pass

    @property
    def ari_img_file(self):
        pass

    @property
    def dhcp_client(self):
        pass

    @property
    def img_container_format(self):
        pass

    @property
    def img_dir(self):
        pass

    @property
    def img_disk_format(self):
        pass

    @property
    def img_file(self):
        pass

    @property
    def img_properties(self):
        pass
