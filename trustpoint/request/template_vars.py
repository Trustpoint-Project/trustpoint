"""Template variable resolver for certificate profile values."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

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

        if device is not None:
            variables['device.rfc_4122_uuid'] = str(device.rfc_4122_uuid)
            variables['device.common_name'] = device.common_name
            variables['device.serial_number'] = device.serial_number

        if domain is not None:
            variables['domain.unique_name'] = domain.unique_name

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
    def _resolve_recursively(cls, obj: Any, variables: dict[str, str]) -> Any:
        """Walk *obj* (dict / list / str) and resolve template variables in all string leaves."""
        if isinstance(obj, str):
            return cls._resolve_string(obj, variables)
        if isinstance(obj, list):
            return [cls._resolve_recursively(item, variables) for item in obj]
        if isinstance(obj, dict):
            return {key: cls._resolve_recursively(val, variables) for key, val in obj.items()}
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
