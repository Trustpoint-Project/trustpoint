"""Django admin configuration for the PKI app."""

from django.contrib import admin
from django.http import HttpRequest

from .models import CaModel
from .models.certificate import CertificateModel
from .models.credential import CertificateChainOrderModel, CredentialModel
from .models.devid_registration import DevIdRegistration


class DevIdRegistrationAdmin(admin.ModelAdmin[DevIdRegistration]):
    """Admin configuration for the DevIdRegistrationModel."""


class CertificateModelAdmin(admin.ModelAdmin[CertificateModel]):
    """Admin configuration for the CertificateModel."""

    def get_readonly_fields(self, _request: HttpRequest, _obj: CertificateModel | None = None) -> list[str]:
        """Sets all fields as read-only."""
        return [f.name for f in CertificateModel._meta.fields]  # noqa: SLF001


class CredentialModelAdmin(admin.ModelAdmin[CredentialModel]):
    """Admin configuration for the CredentialModel."""


class CertificateChainOrderModelAdmin(admin.ModelAdmin[CertificateChainOrderModel]):
    """Admin configuration for the CertificateChainOrderModel."""


class CaModelAdmin(admin.ModelAdmin[CaModel]):
    """Admin configuration for the CaModel."""

    fieldsets = (
        (
            'General',
            {
                'fields': (
                    'unique_name',
                    'is_active',
                    'ca_type',
                    'parent_ca',
                )
            }
        ),
        (
            'Certificates and Credentials',
            {
                'fields': (
                    'certificate',
                    'credential',
                    'chain_truststore',
                )
            }
        ),
        (
            'Remote Configuration',
            {
                'fields': (
                    'remote_host',
                    'remote_port',
                    'remote_path',
                    'est_username',
                    'onboarding_config',
                    'no_onboarding_config',
                ),
                'classes': ('collapse',),
            }
        ),
        (
            'CRL Cycle Configuration',
            {
                'fields': (
                    'crl_cycle_enabled',
                    'crl_cycle_interval_hours',
                    'last_crl_generation_started_at',
                ),
                'description': 'Configure automatic periodic CRL generation',
            }
        ),
    )

    readonly_fields = ('last_crl_generation_started_at',)


admin.site.register(CertificateModel, CertificateModelAdmin)
admin.site.register(CredentialModel, CredentialModelAdmin)
admin.site.register(CertificateChainOrderModel, CertificateChainOrderModelAdmin)
admin.site.register(CaModel, CaModelAdmin)
admin.site.register(DevIdRegistration, DevIdRegistrationAdmin)
