# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Environment-backed security policy restrictions."""

# ruff: noqa: C901, EM102, PLC0415, PLR0912, SLF001, TRY003

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeGuard, cast

from onboarding.enums import NoOnboardingPkiProtocol, OnboardingProtocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from management.models.security import _SecurityModeDefaults


class SecurityConfigurationError(ValueError):
    """Raised when Trustpoint security environment configuration is invalid."""


logger = logging.getLogger('trustpoint.security')


class _Unset:
    """Sentinel for an environment variable that was not defined."""


UNSET = _Unset()


def _is_unset(value: object) -> TypeGuard[_Unset]:
    return isinstance(value, _Unset)


def _fail(message: str) -> None:
    raise SecurityConfigurationError(message)


@dataclass(frozen=True)
class SecurityRestrictions:
    """Optional restrictions parsed from the Trustpoint environment."""

    rsa_minimum_key_size: int | _Unset | None = UNSET
    max_cert_validity_days: int | _Unset | None = UNSET
    max_crl_validity_days: int | _Unset | None = UNSET
    allow_ca_issuance: bool | _Unset = UNSET
    allow_auto_gen_pki: bool | _Unset = UNSET
    allow_self_signed_ca: bool | _Unset = UNSET
    allow_imported_private_keys: bool | _Unset = UNSET
    auto_gen_pki: bool | _Unset = UNSET
    permitted_no_onboarding_pki_protocols: list[int] | _Unset = UNSET
    permitted_onboarding_protocols: list[int] | _Unset = UNSET


def _raw_environment(environment: Mapping[str, str] | None, name: str) -> str | _Unset:
    """Read one environment value while preserving an unset value."""
    source = os.environ if environment is None else environment
    value = source.get(name)
    return UNSET if value is None else value.strip()


def _parse_bool(name: str, value: str | _Unset) -> bool | _Unset:
    if isinstance(value, _Unset):
        return UNSET
    normalized = value.lower()
    if normalized in {'true', '1', 'yes', 'on'}:
        return True
    if normalized in {'false', '0', 'no', 'off'}:
        return False
    _fail(f'{name} must be a boolean (true/false, 1/0, yes/no, or on/off).')
    return UNSET


def _parse_nullable_integer(name: str, value: str | _Unset) -> int | _Unset | None:
    if isinstance(value, _Unset):
        return UNSET
    if value.lower() == 'null':
        return None
    try:
        parsed = int(value)
    except ValueError:
        _fail(f'{name} must be a non-negative integer or null.')
    if parsed < 0:
        _fail(f'{name} must be a non-negative integer or null.')
    return parsed


def _parse_protocols(
    name: str,
    value: str | _Unset,
    protocol_type: type[OnboardingProtocol | NoOnboardingPkiProtocol],
) -> list[int] | _Unset:
    if isinstance(value, _Unset):
        return UNSET
    if not value:
        return []
    members = {member.name: member.value for member in protocol_type}
    result: list[int] = []
    for raw_name in value.split(','):
        protocol_name = raw_name.strip().upper()
        if not protocol_name:
            _fail(f'{name} contains an empty protocol name.')
        if protocol_name not in members:
            supported = ', '.join(members)
            _fail(f'{name} contains unknown protocol {raw_name.strip()!r}. Supported values: {supported}.')
        protocol_value = members[protocol_name]
        if protocol_value in result:
            _fail(f'{name} contains duplicate protocol {protocol_name}.')
        result.append(protocol_value)
    return result


def parse_security_restrictions(environment: Mapping[str, str] | None = None) -> SecurityRestrictions:
    """Parse all optional ``TP_SECURITY_*`` restrictions."""
    return SecurityRestrictions(
        rsa_minimum_key_size=_parse_nullable_integer(
            'TP_SECURITY_RSA_MINIMUM_KEY_SIZE',
            _raw_environment(environment, 'TP_SECURITY_RSA_MINIMUM_KEY_SIZE'),
        ),
        max_cert_validity_days=_parse_nullable_integer(
            'TP_SECURITY_MAX_CERT_VALIDITY_DAYS',
            _raw_environment(environment, 'TP_SECURITY_MAX_CERT_VALIDITY_DAYS'),
        ),
        max_crl_validity_days=_parse_nullable_integer(
            'TP_SECURITY_MAX_CRL_VALIDITY_DAYS',
            _raw_environment(environment, 'TP_SECURITY_MAX_CRL_VALIDITY_DAYS'),
        ),
        allow_ca_issuance=_parse_bool(
            'TP_SECURITY_ALLOW_CA_ISSUANCE',
            _raw_environment(environment, 'TP_SECURITY_ALLOW_CA_ISSUANCE'),
        ),
        allow_auto_gen_pki=_parse_bool(
            'TP_SECURITY_ALLOW_AUTO_GEN_PKI',
            _raw_environment(environment, 'TP_SECURITY_ALLOW_AUTO_GEN_PKI'),
        ),
        allow_self_signed_ca=_parse_bool(
            'TP_SECURITY_ALLOW_SELF_SIGNED_CA',
            _raw_environment(environment, 'TP_SECURITY_ALLOW_SELF_SIGNED_CA'),
        ),
        allow_imported_private_keys=_parse_bool(
            'TP_SECURITY_ALLOW_IMPORTED_PRIVATE_KEYS',
            _raw_environment(environment, 'TP_SECURITY_ALLOW_IMPORTED_PRIVATE_KEYS'),
        ),
        auto_gen_pki=_parse_bool(
            'TP_SECURITY_AUTO_GEN_PKI',
            _raw_environment(environment, 'TP_SECURITY_AUTO_GEN_PKI'),
        ),
        permitted_no_onboarding_pki_protocols=_parse_protocols(
            'TP_SECURITY_PERMITTED_NO_ONBOARDING_PKI_PROTOCOLS',
            _raw_environment(environment, 'TP_SECURITY_PERMITTED_NO_ONBOARDING_PKI_PROTOCOLS'),
            NoOnboardingPkiProtocol,
        ),
        permitted_onboarding_protocols=_parse_protocols(
            'TP_SECURITY_PERMITTED_ONBOARDING_PROTOCOLS',
            _raw_environment(environment, 'TP_SECURITY_PERMITTED_ONBOARDING_PROTOCOLS'),
            OnboardingProtocol,
        ),
    )


def security_mode_from_environment(environment: Mapping[str, str] | None = None) -> str:
    """Return the database value for the symbolic ``TP_SECURITY_MODE``."""
    raw_mode = _raw_environment(environment, 'TP_SECURITY_MODE')
    mode_name = 'BROWNFIELD' if isinstance(raw_mode, _Unset) or not raw_mode else raw_mode.upper()
    from management.models.security import SecurityConfig

    try:
        return SecurityConfig.SecurityModeChoices[mode_name].value
    except KeyError as exc:
        supported = ', '.join(SecurityConfig.SecurityModeChoices.names)
        message = f'Invalid TP_SECURITY_MODE={raw_mode!r}. Supported values: {supported}.'
        raise SecurityConfigurationError(message) from exc


def effective_security_defaults(
    mode: str,
    restrictions: SecurityRestrictions | None = None,
) -> dict[str, object]:
    """Return a validated copy of a preset with environment restrictions applied."""
    from management.models.security import SecurityConfig

    try:
        defaults = cast('dict[str, object]', dict(SecurityConfig._MODE_DEFAULTS[mode]))
    except KeyError as exc:
        raise SecurityConfigurationError(f'Unknown security mode database value: {mode}.') from exc
    defaults.update(
        {
            'not_permitted_ecc_curve_oids': list(cast('list[str]', defaults['not_permitted_ecc_curve_oids'])),
            'not_permitted_mldsa_variant_oids': list(cast('list[str]', defaults['not_permitted_mldsa_variant_oids'])),
            'not_permitted_signature_algorithm_oids': list(
                cast('list[str]', defaults['not_permitted_signature_algorithm_oids'])
            ),
            'permitted_no_onboarding_pki_protocols': list(
                cast('list[int]', defaults['permitted_no_onboarding_pki_protocols'])
            ),
            'permitted_onboarding_protocols': list(cast('list[int]', defaults['permitted_onboarding_protocols'])),
        }
    )
    restrictions = restrictions or parse_security_restrictions()

    for field in ('rsa_minimum_key_size', 'max_cert_validity_days', 'max_crl_validity_days'):
        value = getattr(restrictions, field)
        if _is_unset(value):
            continue
        preset = defaults[field]
        if field == 'rsa_minimum_key_size':
            valid = value is None or (preset is not None and (preset == 0 or value >= preset))
        else:
            valid = (value is not None and (preset is None or value <= preset)) or (value is None and preset is None)
        if not valid:
            _fail(
                f'{field}={value!r} would weaken security mode {mode}; environment restrictions may only be stricter.',
            )
        defaults[field] = value

    for field in (
        'allow_ca_issuance', 'allow_auto_gen_pki', 'allow_self_signed_ca', 'allow_imported_private_keys',
    ):
        value = getattr(restrictions, field)
        if not _is_unset(value):
            if value and not defaults[field]:
                _fail(
                    f'{field}=true is not permitted by security mode {mode}; '
                    'environment restrictions may only be stricter.',
                )
            defaults[field] = value

    for field in ('permitted_no_onboarding_pki_protocols', 'permitted_onboarding_protocols'):
        value = getattr(restrictions, field)
        if not _is_unset(value):
            preset_protocols = set(cast('list[int]', defaults[field]))
            for protocol in value:
                if protocol not in preset_protocols:
                    protocol_type = (
                        NoOnboardingPkiProtocol
                        if field == 'permitted_no_onboarding_pki_protocols'
                        else OnboardingProtocol
                    )
                    protocol_name = next(
                        (member.name for member in protocol_type if member.value == protocol), str(protocol),
                    )
                    _fail(
                        f'Protocol {protocol_name} is not permitted by security mode {mode}; '
                        'environment configuration may only further restrict the selected preset.',
                    )
            defaults[field] = value

    if not _is_unset(restrictions.auto_gen_pki):
        if restrictions.auto_gen_pki and not defaults['allow_auto_gen_pki']:
            _fail(
                f'TP_SECURITY_AUTO_GEN_PKI=true is not permitted by security mode {mode}.',
            )
        defaults['auto_gen_pki'] = restrictions.auto_gen_pki
    return defaults


def synchronize_security_config() -> bool:
    """Apply the current environment policy, retaining it when existing data conflicts."""
    from django.db import transaction

    from management.models import SecurityConfig

    mode = security_mode_from_environment()
    restrictions = parse_security_restrictions()
    effective = effective_security_defaults(mode, restrictions)
    with transaction.atomic():
        config = SecurityConfig.objects.select_for_update().filter(pk=1).first()
        validation_config = config or SecurityConfig(security_mode=mode)
        violations = validation_config.check_policy_transition(
            cast('_SecurityModeDefaults', effective), mode,
        )
        if violations:
            mode_name = SecurityConfig.SecurityModeChoices(mode).name
            logger.error(
                'Environment security configuration rejected. Requested mode: %s. '
                'The existing security configuration remains active. Policy violations (%d):\n- %s',
                mode_name,
                len(violations),
                '\n- '.join(violations),
            )
            return False

        if config is None:
            config = SecurityConfig(pk=1, security_mode=mode)
        config.security_mode = mode
        config.apply_security_settings(save=False)
        if effective['allow_auto_gen_pki'] is False and restrictions.auto_gen_pki is UNSET:
            effective['auto_gen_pki'] = False
        for field, value in effective.items():
            if (
                field
                in {
                    'auto_gen_pki',
                    'not_permitted_ecc_curve_oids',
                    'not_permitted_mldsa_variant_oids',
                    'not_permitted_signature_algorithm_oids',
                    'permitted_no_onboarding_pki_protocols',
                    'permitted_onboarding_protocols',
                }
                or field.startswith('allow_')
                or field
                in {
                    'rsa_minimum_key_size',
                    'max_cert_validity_days',
                    'max_crl_validity_days',
                }
            ):
                setattr(config, field, value)
        config.save()
    return True
