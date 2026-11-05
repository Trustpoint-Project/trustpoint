# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Test suite for SecurityConfigForm."""
import pytest
from django.test import TestCase
from management.forms import SecurityConfigForm
from management.models import SecurityConfig
from onboarding.enums import NoOnboardingPkiProtocol, OnboardingProtocol


class SecurityConfigFormTest(TestCase):
    """Test suite for the SecurityConfigForm."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = SecurityConfig.objects.create(
            security_mode=SecurityConfig.SecurityModeChoices.BROWNFIELD,
            auto_gen_pki=False,
        )

    def test_form_initialization_with_instance(self):
        """Test form initializes correctly with existing instance."""
        form = SecurityConfigForm(instance=self.config)
        self.assertIn('security_mode', form.fields)
        self.assertIn('auto_gen_pki', form.fields)
        assert 'allow_auto_gen_pki' not in form.fields
        assert 'auto_gen_pki_key_algorithm' not in form.fields
        assert 'allow_imported_private_keys' in form.fields

    def test_form_initialization_without_instance(self):
        """Test form initializes with default values."""
        form = SecurityConfigForm()
        self.assertIsNotNone(form.fields['security_mode'])

    def test_unsupported_onboarding_protocol_is_not_offered(self) -> None:
        """Test the security policy cannot permit the unsupported BRSKI protocol."""
        form = SecurityConfigForm()
        choices = [value for value, _label in form.fields['permitted_onboarding_protocols'].choices]
        assert OnboardingProtocol.BRSKI.value not in choices

    def test_security_mode_defaults_exclude_unsupported_onboarding_protocol(self) -> None:
        """Test no security preset includes the unsupported BRSKI protocol."""
        for mode in SecurityConfig.SecurityModeChoices:
            config = SecurityConfig(security_mode=mode)
            config.apply_security_settings(save=False)
            assert OnboardingProtocol.BRSKI.value not in config.permitted_onboarding_protocols

    def test_security_mode_field_is_radio_select(self):
        """Test that security_mode uses RadioSelect widget."""
        form = SecurityConfigForm()
        from django.forms import RadioSelect
        self.assertIsInstance(form.fields['security_mode'].widget, RadioSelect)

    def test_auto_gen_pki_field_has_correct_attributes(self):
        """Test auto_gen_pki field has data attributes."""
        form = SecurityConfigForm()
        widget_attrs = form.fields['auto_gen_pki'].widget.attrs
        self.assertIn('data-sl-defaults', widget_attrs)
        self.assertIn('data-hide-at-sl', widget_attrs)
        self.assertIn('data-more-secure', widget_attrs)

    def test_form_with_dev_security_mode(self):
        """Test form with LAB security mode."""
        form_data = {
            'security_mode': SecurityConfig.SecurityModeChoices.LAB,
            'auto_gen_pki': True,
            'allow_auto_gen_pki': True,
        }
        form = SecurityConfigForm(data=form_data, instance=self.config)
        self.assertTrue(form.is_valid())

    def test_form_with_high_security_mode(self):
        """Test form with HARDENED security mode disables auto_gen_pki."""
        form_data = {
            'security_mode': SecurityConfig.SecurityModeChoices.HARDENED,
            'auto_gen_pki': False,
            # Hardened defaults from _MODE_DEFAULTS
            'rsa_minimum_key_size': 4096,
            'max_cert_validity_days': 365,
            'max_crl_validity_days': 90,
            'credential_ttl_seconds': 600,
            'allow_ca_issuance': False,
            'allow_auto_gen_pki': False,
            'allow_self_signed_ca': False,
        }
        form = SecurityConfigForm(data=form_data, instance=self.config)
        self.assertTrue(form.is_valid())

    def test_form_initialization_with_data_security_mode(self):
        """Test form initialization considers security_mode from form data."""
        form_data = {
            'security_mode': SecurityConfig.SecurityModeChoices.CRITICAL,
        }
        form = SecurityConfigForm(data=form_data, instance=self.config)
        # The form should process the CRITICAL security mode
        self.assertIn('security_mode', form.data)

    def test_all_security_modes(self):
        """Test form field accepts all security mode choices."""
        self.config.security_mode = SecurityConfig.SecurityModeChoices.CRITICAL
        self.config.save()

        for mode in SecurityConfig.SecurityModeChoices:
            instance = SecurityConfig.objects.get(pk=self.config.pk)


            defaults = SecurityConfig._MODE_DEFAULTS[mode]  # type: ignore[attr-defined]

            form_data = {
                'security_mode': mode,
                'auto_gen_pki': defaults['allow_auto_gen_pki'],
                'rsa_minimum_key_size': defaults['rsa_minimum_key_size'] or '',
                'max_cert_validity_days': defaults['max_cert_validity_days'],
                'max_crl_validity_days': defaults['max_crl_validity_days'],
                'credential_ttl_seconds': defaults['credential_ttl_seconds'],
                'allow_ca_issuance': defaults['allow_ca_issuance'],
                'allow_auto_gen_pki': defaults['allow_auto_gen_pki'],
                'allow_self_signed_ca': defaults['allow_self_signed_ca'],
            }
            form = SecurityConfigForm(data=form_data, instance=instance)
            self.assertTrue(form.is_valid(), f"Form should be valid for mode {mode}")

    def test_form_helper_layout(self):
        """Test that form has crispy forms helper with proper layout."""
        form = SecurityConfigForm()
        self.assertIsNotNone(form.helper)
        self.assertIsNotNone(form.helper.layout)

    def test_form_saves_imported_private_key_policy(self) -> None:
        """Test that the imported private-key policy is saved from the Security settings form."""
        form = SecurityConfigForm(
            data={
                'security_mode': SecurityConfig.SecurityModeChoices.LAB,
                'auto_gen_pki': False,
                'allow_imported_private_keys': True,
            },
            instance=self.config,
        )

        assert form.is_valid(), form.errors
        saved = form.save()

        assert saved.allow_imported_private_keys


@pytest.mark.django_db
@pytest.mark.parametrize('mode', list(SecurityConfig.SecurityModeChoices))
@pytest.mark.parametrize('ttl_seconds', [None, 0, 300, 600, 601])
def test_credential_ttl_form_policy(mode: str, ttl_seconds: int | None) -> None:
    """The form permits custom TTLs without weakening the hardened presets."""
    defaults = SecurityConfig._MODE_DEFAULTS[mode]
    config = SecurityConfig.objects.create(security_mode=mode)
    form = SecurityConfigForm(data={
        'security_mode': mode,
        'rsa_minimum_key_size': defaults['rsa_minimum_key_size'] or '',
        'max_cert_validity_days': defaults['max_cert_validity_days'],
        'max_crl_validity_days': defaults['max_crl_validity_days'],
        'credential_ttl_seconds': ttl_seconds,
    }, instance=config)
    hardened = mode in (SecurityConfig.SecurityModeChoices.HARDENED, SecurityConfig.SecurityModeChoices.CRITICAL)
    valid = ttl_seconds != 0 and (not hardened or (ttl_seconds is not None and ttl_seconds <= 600))
    assert form.is_valid() == valid, form.errors
    if valid:
        form.save()
        config.refresh_from_db()
        assert config.credential_ttl_seconds == ttl_seconds
    else:
        assert 'credential_ttl_seconds' in form.errors


@pytest.mark.django_db
def test_protocol_allowlists_are_saved_as_int_lists() -> None:
    """Protocol allow-lists from multi-select fields are normalized to integer lists on save."""
    config = SecurityConfig.objects.create(
        security_mode=SecurityConfig.SecurityModeChoices.LAB,
        auto_gen_pki=False,
    )

    no_onboarding_values = [
        str(NoOnboardingPkiProtocol.CMP_SHARED_SECRET.value),
        str(NoOnboardingPkiProtocol.MANUAL.value),
    ]
    onboarding_values = [
        str(OnboardingProtocol.MANUAL.value),
        str(OnboardingProtocol.REST_USERNAME_PASSWORD.value),
    ]

    form = SecurityConfigForm(
        data={
            'security_mode': SecurityConfig.SecurityModeChoices.LAB,
            'auto_gen_pki': False,
            'permitted_no_onboarding_pki_protocols': no_onboarding_values,
            'permitted_onboarding_protocols': onboarding_values,
        },
        instance=config,
    )

    assert form.is_valid(), form.errors
    saved = form.save()
    saved.refresh_from_db()

    assert saved.permitted_no_onboarding_pki_protocols == [1, 16]
    assert saved.permitted_onboarding_protocols == [0, 8]
    assert all(isinstance(value, int) for value in saved.permitted_no_onboarding_pki_protocols)
    assert all(isinstance(value, int) for value in saved.permitted_onboarding_protocols)
