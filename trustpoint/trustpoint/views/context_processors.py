"""Shared template context processors for Trustpoint runtime state."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.db import DatabaseError

from crypto.models import BackendKind, CryptoProviderProfileModel
from setup_wizard.models import SetupWizardCompletedModel, SetupWizardConfigModel

if TYPE_CHECKING:
    from django.http import HttpRequest


def trustpoint_runtime_banner(request: HttpRequest) -> dict[str, Any]:
    """Expose a small runtime banner when the instance is in demo/dev backend mode."""
    is_wizard_request = request.path_info.startswith('/setup-wizard')
    if not is_wizard_request and (not hasattr(request, 'user') or not request.user.is_authenticated):
        return {}

    try:
        setup_completed = SetupWizardCompletedModel.setup_wizard_completed()
        if not setup_completed:
            config_model = SetupWizardConfigModel.get_singleton()
            if (
                config_model.fresh_install_crypto_storage_submitted
                and config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.SoftwareStorage
            ):
                return {
                    'trustpoint_runtime_banner': {
                        'title': 'Demo Setup',
                        'message': (
                            'This Trustpoint instance is configured for the development and testing crypto '
                            'backend. Use it only for testing, demos, and evaluation.'
                        ),
                    }
                }
            return {}

        active_backend_kind = (
            CryptoProviderProfileModel.objects.filter(active=True).values_list('backend_kind', flat=True).first()
        )
    except DatabaseError:
        return {}

    if active_backend_kind != BackendKind.SOFTWARE:
        return {}

    return {
        'trustpoint_runtime_banner': {
            'title': 'Demo Setup',
            'message': (
                'This Trustpoint instance is configured for the development and testing crypto backend. '
                'Use it only for testing, demos, and evaluation.'
            ),
        }
    }
