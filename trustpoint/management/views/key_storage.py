"""Read-only view of the configured crypto/app-secret backend state."""

import io
from typing import Any

from django.contrib import messages
from django.core.exceptions import ObjectDoesNotExist
from django.core.management import CommandError, call_command
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.utils.translation import gettext_lazy as _
from django.views.generic import TemplateView

from appsecrets.models import AppSecretBackendModel
from crypto.models import BackendKind, CryptoProviderProfileModel


class KeyStorageConfigView(TemplateView):
    """Display the configured managed-crypto and application-secret backends."""

    template_name = 'management/key_storage.html'
    extra_context: dict[str, str] = {'page_category': 'management', 'page_name': 'key_storage'}  # noqa: RUF012

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Manually refresh the provider capability snapshot for the active backend."""
        action = request.POST.get('action')
        if action != 'reprobe':
            return redirect('management:key_storage')

        command_output = io.StringIO()
        try:
            call_command('reprobe_crypto_provider', stdout=command_output)
        except CommandError as exc:
            error_detail = str(exc) or 'The crypto provider reprobe failed.'
            messages.error(request, error_detail)
        else:
            success_detail = command_output.getvalue().strip() or _('Crypto provider reprobe completed successfully.')
            messages.success(request, success_detail)

        return redirect('management:key_storage')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add backend summary context for the management UI."""
        context = super().get_context_data(**kwargs)
        context['page_title'] = _('Crypto Backend Configuration')

        crypto_profile = (
            CryptoProviderProfileModel.objects.filter(active=True)
            .select_related(
                'pkcs11_config',
                'software_config',
                'rest_config',
                'current_capability_snapshot__pkcs11_detail',
            )
            .first()
        )
        app_secret_backend = AppSecretBackendModel.objects.first()
        pkcs11_probe_detail = None
        if crypto_profile is not None and crypto_profile.backend_kind == BackendKind.PKCS11:
            current_snapshot = crypto_profile.current_capability_snapshot
            if current_snapshot is not None:
                try:
                    pkcs11_probe_detail = current_snapshot.pkcs11_detail
                except ObjectDoesNotExist:
                    pkcs11_probe_detail = None

        context['crypto_profile'] = crypto_profile
        context['app_secret_backend'] = app_secret_backend
        context['pkcs11_config'] = getattr(crypto_profile, 'pkcs11_config', None) if crypto_profile else None
        context['software_config'] = getattr(crypto_profile, 'software_config', None) if crypto_profile else None
        context['rest_config'] = getattr(crypto_profile, 'rest_config', None) if crypto_profile else None
        context['pkcs11_probe_detail'] = pkcs11_probe_detail
        context['is_pkcs11_backend'] = bool(crypto_profile and crypto_profile.backend_kind == BackendKind.PKCS11)
        context['is_software_backend'] = bool(crypto_profile and crypto_profile.backend_kind == BackendKind.SOFTWARE)
        context['is_rest_backend'] = bool(crypto_profile and crypto_profile.backend_kind == BackendKind.REST)
        context['pkcs11_token_serial_display'] = (
            getattr(pkcs11_probe_detail, 'token_serial', None)
            or getattr(context['pkcs11_config'], 'token_serial', None)
            or '-'
        )
        pkcs11_slot_id = (
            getattr(pkcs11_probe_detail, 'slot_id', None)
            if getattr(pkcs11_probe_detail, 'slot_id', None) is not None
            else getattr(context['pkcs11_config'], 'slot_id', None)
        )
        context['pkcs11_slot_id_display'] = pkcs11_slot_id if pkcs11_slot_id is not None else '-'

        if crypto_profile is None:
            messages.warning(self.request, _('No configured crypto backend profile was found.'))

        if app_secret_backend is None:
            messages.warning(self.request, _('No configured application-secret backend was found.'))

        return context
