from rockoon.filters.tempest import base_section


class VolumeFeatureEnabled(base_section.BaseSection):
    name = "volume-feature-enabled"
    options = [
        "api_extensions",
        "api_v1",
        "api_v2",
        "api_v3",
        "backup",
        "clone",
        "enable_volume_image_dep_tests",
        "extend_attached_volume",
        "manage_snapshot",
        "manage_volume",
        "multi_backend",
        "snapshot",
        "volume_locked_by_snapshot",
        "instance_locality_enabled",
    ]

    @property
    def enabled(self):
        return self.is_service_enabled("cinder")

    @property
    def api_extensions(self):
        pass

    @property
    def api_v1(self):
        pass

    @property
    def api_v2(self):
        pass

    @property
    def api_v3(self):
        pass

    @property
    def backup(self):
        return self.get_spec_item("features.cinder.backup.enabled", True)

    @property
    def clone(self):
        pass

    @property
    def enable_volume_image_dep_tests(self):
        """disable for glance on rbd

        current rook/pelagia default min compat client is 'luminous',
        passing these tests requires 'mimic' or later
        """
        # TODO: reconsider when min compat client version is raised
        if (
            # single backend
            "rbd"
            in self.get_values_item(
                "glance", "conf.glance.glance_store.stores", ""
            )
            or
            # multi-backend
            "rbd"
            in self.get_values_item(
                "glance", "conf.glance.DEFAULT.enabled_backends", ""
            )
        ):
            return False
        return True

    @property
    def extend_attached_volume(self):
        return True

    @property
    def manage_snapshot(self):
        pass

    @property
    def manage_volume(self):
        pass

    @property
    def multi_backend(self):
        pass

    @property
    def snapshot(self):
        pass

    @property
    def volume_locked_by_snapshot(self):
        rbd_flatten_volume_from_snapshot = []
        for backend in self.get_values_item(
            "cinder", "conf.cinder.DEFAULT.enabled_backends", ""
        ).split(","):
            rbd_flatten_volume_from_snapshot.append(
                self.get_values_item(
                    "cinder",
                    f"conf.backends.{backend}.rbd_flatten_volume_from_snapshot",
                    False,
                )
            )
        return not any(rbd_flatten_volume_from_snapshot)

    @property
    def instance_locality_enabled(self):
        # This option should be explicitly specified in osdpl by the user
        return False
