"""Django admin configuration for the PKI app."""

from django.contrib import admin
from django.http import HttpRequest

from .models import CertificateChainOrderModel, CertificateModel, CredentialModel, IssuingCaModel
from .models.devid_registration import DevIdRegistration


class DevIdRegistrationAdmin(admin.ModelAdmin[DevIdRegistration]):
    """Admin configuration for the DevIdRegistrationModel."""


class CertificateModelAdmin(admin.ModelAdmin[CertificateModel]):
    """Admin configuration for the CertificateModel."""

    def get_readonly_fields(self, _request: HttpRequest, _obj: CertificateModel = None) -> list[str]:
        """Sets all fields as read-only."""
        return [f.name for f in CertificateModel._meta.fields]  # noqa: SLF001


class CredentialModelAdmin(admin.ModelAdmin[CredentialModel]):
    """Admin configuration for the CredentialModel."""


class CertificateChainOrderModelAdmin(admin.ModelAdmin[CertificateChainOrderModel]):
    """Admin configuration for the CertificateChainOrderModel."""


class IssuingCaModelAdmin(admin.ModelAdmin[IssuingCaModel]):
    """Admin configuration for the IssuingCaModel."""


admin.site.register(CertificateModel, CertificateModelAdmin)
admin.site.register(CredentialModel, CredentialModelAdmin)
admin.site.register(CertificateChainOrderModel, CertificateChainOrderModelAdmin)
admin.site.register(IssuingCaModel, IssuingCaModelAdmin)
admin.site.register(DevIdRegistration, DevIdRegistrationAdmin)
