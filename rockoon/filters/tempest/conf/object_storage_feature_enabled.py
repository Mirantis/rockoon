from rockoon.filters.tempest import base_section


class ObjectStorageFeatureEnabled(base_section.BaseSection):
    name = "object-storage-feature-enabled"
    options = [
        "container_sync",
        "discoverability",
        "discoverable_apis",
        "object_versioning",
        "tempurl_digest_hashlib",
    ]

    @property
    def container_sync(self):
        pass

    @property
    def discoverability(self):
        pass

    @property
    def discoverable_apis(self):
        pass

    @property
    def object_versioning(self):
        pass

    @property
    def tempurl_digest_hashlib(self):
        # see tempest Change-Id Ia4923d47870fcb914a33adecb7155763ec1d0b2f
        # recent Swift supports more secure algos like sha256 or sha512,
        # and tempest since approx Zed release defaults to sha256,
        # however Ceph RGW still does still only support sha1 here.
        return "sha1"
