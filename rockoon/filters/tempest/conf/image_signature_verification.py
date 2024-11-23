from rockoon.filters.tempest import base_section


class ImageSignatureVerification(base_section.BaseSection):
    name = "image_signature_verification"
    options = [
        "enforced",
        "certificate_validation",
    ]

    @property
    def enforced(self):
        return self.get_values_item(
            "nova", "conf.nova.glance.verify_glance_signatures", False
        )

    @property
    def certificate_validation(self):
        return self.get_spec_item(
            "features.glance.signature.certificate_validation", False
        )
