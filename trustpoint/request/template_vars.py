# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Template variable resolver for certificate profile values."""

from __future__ import annotations

import contextlib
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from cryptography import x509

from pki.models.ca_rollover import CaRolloverState
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from pki.services.ca_rollover import CaRolloverService
from pki.util.crl_urls import CRL_PLACEHOLDER, validate_crl_url
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from devices.models import DeviceModel
    from pki.models.domain import DomainModel
    from request.request_context import BaseRequestContext

_TEMPLATE_VAR_RE = re.compile(r'\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}')


class TemplateVariableResolver(LoggerMixin):
    """Resolves ``{{ namespace.field }}`` placeholders in certificate profile values."""

    @classmethod
    def build_variable_map_from_models(
        cls,
        device: DeviceModel | None = None,
        domain: DomainModel | None = None,
    ) -> dict[str, str]:
        """Build a mapping of template variable names to their resolved string values."""
        variables: dict[str, str] = {}

        now = datetime.now(UTC)
        variables['time.now'] = now.isoformat()
        variables['time.date'] = now.date().isoformat()
        variables['time.timestamp'] = str(int(now.timestamp()))

        if device is not None:
            variables['device.id'] = str(device.pk)
            variables['device.rfc_4122_uuid'] = str(device.rfc_4122_uuid)
            variables['device.common_name'] = device.common_name
            variables['device.serial_number'] = device.serial_number
            variables['device.device_type'] = str(device.get_device_type_display())
            # Optional fields are omitted when unset so the placeholder is left unresolved.
            if device.ip_address:
                variables['device.ip_address'] = str(device.ip_address)
            if hasattr(device, 'opc_ua_gds_push_config') and device.opc_ua_gds_push_config.opc_server_port:
                variables['device.opc_server_port'] = str(device.opc_ua_gds_push_config.opc_server_port)

        if domain is not None:
            variables['domain.unique_name'] = domain.unique_name
            if domain.issuing_ca is not None:
                variables['domain.issuing_ca'] = str(domain.issuing_ca.unique_name)
            variables.update({
                'domain.organization': '',
                'domain.organization_unit': '',
                'domain.country': '',
                'domain.state': '',
                'domain.locality': '',
            })
            if domain.organization is not None:
                variables['domain.organization'] = domain.organization.organization
                variables['domain.organization_unit'] = domain.organization.organization_unit
                variables['domain.country'] = domain.organization.country
                variables['domain.state'] = domain.organization.state
                variables['domain.locality'] = domain.organization.locality

        return variables

    @classmethod
    def _build_variable_map(cls, context: BaseRequestContext) -> dict[str, str]:
        """Build a variable map from a request context."""
        return cls.build_variable_map_from_models(device=context.device, domain=context.domain)

    @classmethod
    def _resolve_string(cls, value: str, variables: dict[str, str]) -> str:
        """Replace all ``{{ ... }}`` placeholders in *value* with resolved values."""

        def _replacer(match: re.Match[str]) -> str:
            key = match.group(1).strip()
            resolved = variables.get(key)
            if resolved is None:
                cls.logger.warning("Unresolved template variable '{{ %s }}' - leaving as-is.", key)
                return match.group(0)
            return resolved

        return _TEMPLATE_VAR_RE.sub(_replacer, value)

    @classmethod
    def resolve_string(cls, value: str, variables: dict[str, str]) -> str:
        """Resolve ``{{ ... }}`` placeholders in a single string value."""
        return cls._resolve_string(value, variables)

    @classmethod
    def _resolves_to_empty(cls, value: Any, variables: dict[str, str]) -> bool:
        """Whether *value* is a placeholder-containing string that resolves to nothing."""
        return (
            isinstance(value, str)
            and bool(_TEMPLATE_VAR_RE.search(value))
            and not cls._resolve_string(value, variables).strip()
        )

    @classmethod
    def _resolve_recursively(cls, obj: Any, variables: dict[str, str]) -> Any:
        """Walk *obj* (dict / list / str) and resolve template variables in all string leaves.

        Entries that resolve to an empty string are dropped, as empty X.509 attribute values are invalid.
        """
        if isinstance(obj, str):
            return cls._resolve_string(obj, variables)
        if isinstance(obj, list):
            return [
                cls._resolve_recursively(item, variables)
                for item in obj
                if not cls._resolves_to_empty(item, variables)
            ]
        if isinstance(obj, dict):
            return {
                key: cls._resolve_recursively(val, variables)
                for key, val in obj.items()
                if not cls._resolves_to_empty(val, variables)
            }
        return obj

    @classmethod
    def resolve_template_variables(
        cls,
        data: dict[str, Any],
        context: BaseRequestContext,
    ) -> dict[str, Any]:
        """Resolve ``{{ ... }}`` template variables in *data* using *context*."""
        variables = cls._build_variable_map(context)
        if not variables:
            cls.logger.debug('No template variables available in context - skipping substitution.')
            return data

        resolved: dict[str, Any] = cls._resolve_recursively(data, variables)
        resolve_crl_urls(resolved, context)
        cls.logger.debug('Template variable substitution complete. Result: %s', resolved)
        return resolved

def build_variable_map_from_models(
    device: DeviceModel | None = None,
    domain: DomainModel | None = None,
) -> dict[str, str]:
    """Build a mapping of template variable names to their resolved string values."""
    return TemplateVariableResolver.build_variable_map_from_models(device=device, domain=domain)


def resolve_string(value: str, variables: dict[str, str]) -> str:
    """Resolve ``{{ ... }}`` placeholders in a single string value."""
    return TemplateVariableResolver.resolve_string(value, variables)


def resolve_template_variables(
    data: dict[str, Any],
    context: BaseRequestContext,
) -> dict[str, Any]:
    """Resolve ``{{ ... }}`` template variables in *data* using *context*."""
    return TemplateVariableResolver.resolve_template_variables(data, context)


def resolve_crl_urls(data: dict[str, Any], context: BaseRequestContext) -> None:
    """Resolve CRL placeholders using the active TLS certificate and effective issuing CA."""
    crl = data.get('extensions', {}).get('crl_distribution_points', {})
    urls = crl.get('uris', [])
    variables: dict[str, str] = {}
    keys = {match.group(1) or match.group(2) for url in urls for match in CRL_PLACEHOLDER.finditer(url)}
    if 'issuing_ca.id' in keys:
        if context.domain is None:
            msg = 'An issuing domain is required to resolve {issuing_ca.id}.'
            raise ValueError(msg)
        ca = context.domain.get_issuing_ca_or_value_error()
        rollover = CaRolloverService.get_active_rollover(ca)
        if (rollover and rollover.state == CaRolloverState.TRANSITION
                and rollover.new_issuing_ca and rollover.new_issuing_ca.credential):
            ca = rollover.new_issuing_ca
        variables['issuing_ca.id'] = str(ca.pk)
    if any(key.startswith('tls_certificate.') for key in keys):
        variables.update(_tls_ip_variables())

    def replace(match: re.Match[str]) -> str:
        key = match.group(1) or match.group(2)
        if key not in variables:
            msg = f'Cannot resolve CRL URL placeholder {{{key}}}; check the active TLS certificate IP SANs.'
            raise ValueError(msg)
        return variables[key]

    if urls:
        crl['uris'] = [validate_crl_url(CRL_PLACEHOLDER.sub(replace, url)) for url in urls]


def _tls_ip_variables() -> dict[str, str]:
    """Read IP SANs in certificate order; bracket IPv6 addresses for URL hosts."""
    active = ActiveTrustpointTlsServerCredentialModel.objects.select_related('credential').first()
    addresses = []
    if active and active.credential:
        cert = active.credential.get_certificate()
        with contextlib.suppress(x509.ExtensionNotFound):
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            addresses = san.get_values_for_type(x509.IPAddress)
    return {
        f'tls_certificate.ip_address.{index}': f'[{address}]' if ':' in str(address) else str(address)
        for index, address in enumerate(addresses, start=1)
    }
