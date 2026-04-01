"""Django admin configuration for the PKI app."""

from django.contrib import admin
from django.http import HttpRequest

from pki.models.issued_credential import IssuedCredentialModel, RemoteIssuedCredentialModel

from .models import CaModel
from .models.ca_rollover import CaRolloverModel
from .models.certificate import CertificateModel
from .models.credential import CertificateChainOrderModel, CredentialModel
from .models.devid_registration import DevIdRegistration


class IssuedCredentialModelAdmin(admin.ModelAdmin[IssuedCredentialModel]):
    """Registers the IssuedCredentialModelAdmin with Django Admin."""

class RemoteIssuedCredentialModelAdmin(admin.ModelAdmin[RemoteIssuedCredentialModel]):
    """Registers the RemoteIssuedCredentialModelAdmin with Django Admin."""


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
                    'auto_crl_on_revocation_enabled',
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
admin.site.register(IssuedCredentialModel, IssuedCredentialModelAdmin)
admin.site.register(RemoteIssuedCredentialModel, RemoteIssuedCredentialModelAdmin)


@admin.register(CaRolloverModel)
class CaRolloverAdmin(admin.ModelAdmin[CaRolloverModel]):
    """Admin configuration for the CaRolloverModel."""

    list_display = ('old_issuing_ca', 'new_issuing_ca', 'state', 'strategy_type', 'planned_at', 'initiated_by')
    list_filter = ('state', 'strategy_type')
    readonly_fields = ('planned_at', 'started_at', 'completed_at')
    search_fields = ('old_issuing_ca__unique_name', 'new_issuing_ca__unique_name', 'notes')
