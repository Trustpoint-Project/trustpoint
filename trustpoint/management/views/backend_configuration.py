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
from crypto.application.capabilities import BackendCapabilityReport, get_active_backend_capability_report
from crypto.models import BackendKind, CryptoProviderProfileModel
from pki.util.keys import supported_auto_gen_pki_key_algorithms


def _capability_status(report: BackendCapabilityReport | None) -> tuple[str, Any, Any]:
    """Return Bootstrap badge class, label, and user-facing message for a capability report."""
    if report is None:
        return 'secondary', _('Not configured'), _('No active backend profile is configured.')
    if not report.capabilities_known:
        return (
            'warning',
            _('Probe required'),
            _('Trustpoint has no successful capability snapshot for this backend yet.'),
        )
    if not report.available:
        return (
            'danger',
            _('Unavailable'),
            _('The backend is configured, but no usable key-generation/signing capabilities were reported.'),
        )
    return 'success', _('Ready'), _('The backend reports usable key-generation and signing capabilities.')


def _supported_key_capabilities(report: BackendCapabilityReport | None) -> list[dict[str, str]]:
    """Build human-readable supported key capability rows."""
    if report is None or not report.available:
        return []

    rows: list[dict[str, str]] = []
    if report.rsa_key_sizes:
        rows.append(
            {
                'family': 'RSA',
                'values': ', '.join(str(key_size) for key_size in report.rsa_key_sizes),
            }
        )
    if report.ec_curves:
        rows.append(
            {
                'family': 'Elliptic Curve',
                'values': ', '.join(curve.value.upper() for curve in report.ec_curves),
            }
        )
    return rows


def _mechanism_key_size_range(mechanism: dict[str, Any]) -> str:
    """Return a compact key-size range for mechanism metadata."""
    min_key_size = mechanism.get('min_key_size')
    max_key_size = mechanism.get('max_key_size')

    if min_key_size is None and max_key_size is None:
        return ''
    if min_key_size is None:
        return f'<= {max_key_size}'
    if max_key_size is None:
        return f'>= {min_key_size}'
    if min_key_size == max_key_size:
        return str(min_key_size)
    return f'{min_key_size} - {max_key_size}'


def _mechanism_group_id(mechanism_name: str) -> str:
    """Classify a PKCS#11 mechanism name for display."""
    if 'RSA' in mechanism_name:
        return 'rsa'
    if 'ECDSA' in mechanism_name or 'ECDH' in mechanism_name or 'EC_' in mechanism_name:
        return 'ec'
    if 'AES' in mechanism_name:
        return 'aes'
    if 'SHA' in mechanism_name or 'HMAC' in mechanism_name or 'MD5' in mechanism_name:
        return 'hash'
    return 'other'


def _pkcs11_mechanism_groups(
    mechanisms: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Group PKCS#11 mechanisms and pre-format optional metadata for the template."""
    group_titles = {
        'rsa': _('RSA'),
        'ec': _('Elliptic Curve'),
        'aes': _('AES / Symmetric'),
        'hash': _('Hash / MAC'),
        'other': _('Other'),
    }
    grouped_mechanisms: dict[str, list[dict[str, Any]]] = {group_id: [] for group_id in group_titles}

    for mechanism in mechanisms:
        mechanism_name = str(mechanism.get('name') or '')
        if not mechanism_name:
            continue
        display_mechanism = {
            'name': mechanism_name,
            'code': mechanism.get('code'),
            'flags': mechanism.get('flags') or (),
            'key_size_range': _mechanism_key_size_range(mechanism),
        }
        grouped_mechanisms[_mechanism_group_id(mechanism_name)].append(display_mechanism)

    groups: list[dict[str, Any]] = []
    for group_id, title in group_titles.items():
        group_mechanisms = grouped_mechanisms[group_id]
        if not group_mechanisms:
            continue
        groups.append(
            {
                'id': group_id,
                'title': title,
                'mechanisms': group_mechanisms,
                'has_key_size_ranges': any(mechanism['key_size_range'] for mechanism in group_mechanisms),
                'expanded': not groups,
            }
        )
    return groups


class BackendConfigurationView(TemplateView):
    """Display the configured managed-crypto and application-secret backends."""

    template_name = 'management/backend_configuration.html'
    extra_context: dict[str, str] = {  # noqa: RUF012
        'page_category': 'management',
        'page_name': 'backend_configuration',
    }

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Manually refresh the provider capability snapshot for the active backend."""
        action = request.POST.get('action')
        if action != 'reprobe':
            return redirect('management:backend_configuration')

        command_output = io.StringIO()
        try:
            call_command('reprobe_crypto_provider', stdout=command_output)
        except CommandError as exc:
            error_detail = str(exc) or 'The crypto provider reprobe failed.'
            messages.error(request, error_detail)
        else:
            success_detail = command_output.getvalue().strip() or _('Crypto provider reprobe completed successfully.')
            messages.success(request, success_detail)

        return redirect('management:backend_configuration')

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
                'current_capability_snapshot__software_detail',
                'current_capability_snapshot__rest_detail',
            )
            .first()
        )
        app_secret_backend = AppSecretBackendModel.objects.first()
        capability_report = get_active_backend_capability_report() if crypto_profile is not None else None
        capability_badge, capability_label, capability_message = _capability_status(capability_report)
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
        context['capability_report'] = capability_report
        context['capability_badge'] = capability_badge
        context['capability_label'] = capability_label
        context['capability_message'] = capability_message
        context['capability_diagnostics'] = capability_report.diagnostics if capability_report is not None else ()
        context['supported_key_capabilities'] = _supported_key_capabilities(capability_report)
        context['supported_auto_gen_pki_algorithms'] = supported_auto_gen_pki_key_algorithms()
        pkcs11_capability_payload = (
            getattr(pkcs11_probe_detail, 'snapshot_payload', None)
            if pkcs11_probe_detail is not None
            else None
        )
        context['pkcs11_capability_payload'] = pkcs11_capability_payload
        context['pkcs11_derived_features'] = (
            sorted((pkcs11_capability_payload.get('derived_features') or {}).items())
            if pkcs11_capability_payload
            else []
        )
        pkcs11_mechanisms = (
            sorted((pkcs11_capability_payload.get('mechanisms') or {}).values(), key=lambda item: item.get('name', ''))
            if pkcs11_capability_payload
            else []
        )
        context['pkcs11_mechanisms'] = pkcs11_mechanisms
        context['pkcs11_mechanism_groups'] = _pkcs11_mechanism_groups(pkcs11_mechanisms)
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
