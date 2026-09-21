# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for environment-backed security configuration."""

# ruff: noqa: D102, PT009, PT027, SLF001

from __future__ import annotations

from unittest.mock import patch

from django.test import TestCase

from management.models import SecurityConfig
from management.security_env import (
    SecurityConfigurationError,
    effective_security_defaults,
    parse_security_restrictions,
    security_mode_from_environment,
    synchronize_security_config,
)


class SecurityEnvironmentTest(TestCase):
    """Test parsing and monotonic application of security restrictions."""

    def test_security_mode_names_are_mapped(self) -> None:
        for name, choice in SecurityConfig.SecurityModeChoices.__members__.items():
            self.assertEqual(security_mode_from_environment({'TP_SECURITY_MODE': name}), choice.value)

    def test_invalid_security_mode_is_rejected(self) -> None:
        with self.assertRaisesRegex(SecurityConfigurationError, 'Invalid TP_SECURITY_MODE'):
            security_mode_from_environment({'TP_SECURITY_MODE': 'UNKNOWN'})

    def test_unset_restrictions_inherit_preset(self) -> None:
        defaults = effective_security_defaults(
            SecurityConfig.SecurityModeChoices.BROWNFIELD, parse_security_restrictions({}),
        )
        preset = SecurityConfig._MODE_DEFAULTS[SecurityConfig.SecurityModeChoices.BROWNFIELD]
        self.assertEqual(defaults['rsa_minimum_key_size'], preset['rsa_minimum_key_size'])
        self.assertEqual(defaults['permitted_onboarding_protocols'], preset['permitted_onboarding_protocols'])

    def test_boolean_restrictions_are_monotonic(self) -> None:
        defaults = SecurityConfig.SecurityModeChoices.BROWNFIELD
        self.assertFalse(effective_security_defaults(defaults, parse_security_restrictions({
            'TP_SECURITY_ALLOW_AUTO_GEN_PKI': 'false',
        }))['allow_auto_gen_pki'])
        with self.assertRaisesRegex(SecurityConfigurationError, 'allow_ca_issuance'):
            effective_security_defaults(defaults, parse_security_restrictions({
                'TP_SECURITY_ALLOW_CA_ISSUANCE': 'true',
            }))

    def test_numeric_restrictions_are_monotonic(self) -> None:
        mode = SecurityConfig.SecurityModeChoices.BROWNFIELD
        restricted = effective_security_defaults(mode, parse_security_restrictions({
            'TP_SECURITY_RSA_MINIMUM_KEY_SIZE': '2048',
            'TP_SECURITY_MAX_CERT_VALIDITY_DAYS': '365',
        }))
        self.assertEqual(restricted['rsa_minimum_key_size'], 2048)
        self.assertEqual(restricted['max_cert_validity_days'], 365)
        with self.assertRaises(SecurityConfigurationError):
            effective_security_defaults(mode, parse_security_restrictions({'TP_SECURITY_RSA_MINIMUM_KEY_SIZE': '512'}))
        with self.assertRaises(SecurityConfigurationError):
            effective_security_defaults(
                mode, parse_security_restrictions({'TP_SECURITY_MAX_CERT_VALIDITY_DAYS': 'null'}),
            )

    def test_protocol_lists_must_be_subsets(self) -> None:
        mode = SecurityConfig.SecurityModeChoices.BROWNFIELD
        restricted = effective_security_defaults(mode, parse_security_restrictions({
            'TP_SECURITY_PERMITTED_ONBOARDING_PROTOCOLS': 'CMP_IDEVID,EST_IDEVID,BRSKI',
        }))
        self.assertEqual(restricted['permitted_onboarding_protocols'], [1, 3, 6])
        with self.assertRaisesRegex(SecurityConfigurationError, 'not permitted'):
            effective_security_defaults(SecurityConfig.SecurityModeChoices.HARDENED, parse_security_restrictions({
                'TP_SECURITY_PERMITTED_ONBOARDING_PROTOCOLS': 'MANUAL,CMP_IDEVID',
            }))

    def test_auto_gen_pki_cannot_bypass_policy(self) -> None:
        with self.assertRaisesRegex(SecurityConfigurationError, 'AUTO_GEN_PKI'):
            effective_security_defaults(SecurityConfig.SecurityModeChoices.HARDENED, parse_security_restrictions({
                'TP_SECURITY_AUTO_GEN_PKI': 'true',
            }))

    def test_synchronization_restores_preset_after_restriction_is_removed(self) -> None:
        with patch.dict('os.environ', {
            'TP_SECURITY_MODE': 'BROWNFIELD',
            'TP_SECURITY_RSA_MINIMUM_KEY_SIZE': '2048',
        }, clear=True):
            synchronize_security_config()
        config = SecurityConfig.objects.get(pk=1)
        self.assertEqual(config.rsa_minimum_key_size, 2048)

        with patch.dict('os.environ', {'TP_SECURITY_MODE': 'BROWNFIELD'}, clear=True):
            synchronize_security_config()
        config.refresh_from_db()
        self.assertEqual(config.rsa_minimum_key_size, 1024)
        self.assertEqual(config.allow_imported_private_keys, False)

    def test_policy_conflict_keeps_existing_security_config_and_logs(self) -> None:
        config = SecurityConfig.objects.create(
            pk=1,
            security_mode=SecurityConfig.SecurityModeChoices.BROWNFIELD,
            rsa_minimum_key_size=1024,
            permitted_onboarding_protocols=[0, 1, 2],
        )
        original_values = {
            'security_mode': config.security_mode,
            'rsa_minimum_key_size': config.rsa_minimum_key_size,
            'permitted_onboarding_protocols': config.permitted_onboarding_protocols,
        }
        with patch.dict('os.environ', {
            'TP_SECURITY_MODE': 'BROWNFIELD',
            'TP_SECURITY_PERMITTED_ONBOARDING_PROTOCOLS': 'EST_IDEVID,BRSKI',
        }, clear=True), patch.object(
            SecurityConfig,
            'check_policy_transition',
            return_value=['Device "PLC-01" uses onboarding protocol "CMP - Shared Secret".'],
        ) as check_policy, self.assertLogs('trustpoint.security', level='ERROR') as logs:
            applied = synchronize_security_config()

        self.assertFalse(applied)
        check_policy.assert_called_once()
        config.refresh_from_db()
        self.assertEqual(config.security_mode, original_values['security_mode'])
        self.assertEqual(config.rsa_minimum_key_size, original_values['rsa_minimum_key_size'])
        self.assertEqual(config.permitted_onboarding_protocols, original_values['permitted_onboarding_protocols'])
        self.assertIn('Requested mode: BROWNFIELD', logs.output[0])
        self.assertIn('PLC-01', logs.output[0])
        self.assertIn('remains active', logs.output[0])
