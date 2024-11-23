from rockoon.filters.tempest import base_section


class EphemeralStorageEncryption(base_section.BaseSection):
    name = "ephemeral_storage_encryption"
    options = ["enabled", "cipher", "key_size"]

    @property
    def enabled(self):
        return self.get_values_item(
            "nova", "conf.nova.ephemeral_storage_encryption.enabled", False
        )

    @property
    def cipher(self):
        enabled = self.get_values_item(
            "nova", "conf.nova.ephemeral_storage_encryption.enabled", False
        )
        cipher = self.get_values_item(
            "nova", "conf.nova.ephemeral_storage_encryption.cipher"
        )
        if cipher and enabled:
            return cipher

    @property
    def key_size(self):
        enabled = self.get_values_item(
            "nova", "conf.nova.ephemeral_storage_encryption.enabled", False
        )
        key_size = self.get_values_item(
            "nova", "conf.nova.ephemeral_storage_encryption.key_size"
        )
        if key_size and enabled:
            return key_size
