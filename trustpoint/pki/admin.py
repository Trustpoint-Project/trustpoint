from django.contrib import admin
from .models import CertificateModel, CredentialModel, CertificateChainOrderModel, IssuingCaModel
from .models.devid_registration import DevIdRegistration


class DevIdRegistrationAdmin(admin.ModelAdmin):
    pass


class CertificateModelAdmin(admin.ModelAdmin):
    readonly_fields = (
        'sha256_fingerprint',
        'common_name',
        'certificate_status',
        'signature_algorithm_oid',
        'signature_algorithm',
        'signature_algorithm_padding_scheme',
        'signature_value',
        'version',
        'serial_number',
        'issuer_public_bytes',
        'issuer',
        'not_valid_before',
        'not_valid_after',
        'subject_public_bytes',
        'subject',
        'spki_algorithm_oid',
        'spki_algorithm',
        'spki_key_size',
        'spki_ec_curve_oid',
        'spki_ec_curve',
        'cert_pem',
        'public_key_pem',
        'is_self_signed',
        'key_usage_extension',
        'subject_alternative_name_extension',
        'issuer_alternative_name_extension',
        'basic_constraints_extension',
    )


class CredentialModelAdmin(admin.ModelAdmin):
    pass


class CertificateChainOrderModelAdmin(admin.ModelAdmin):
    pass


class IssuingCaModelAdmin(admin.ModelAdmin):
    pass


admin.site.register(CertificateModel, CertificateModelAdmin)
admin.site.register(CredentialModel, CredentialModelAdmin)
admin.site.register(CertificateChainOrderModel, CertificateChainOrderModelAdmin)
admin.site.register(IssuingCaModel, IssuingCaModelAdmin)
admin.site.register(DevIdRegistration, DevIdRegistrationAdmin)
