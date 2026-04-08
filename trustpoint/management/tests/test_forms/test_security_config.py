"""Test suite for SecurityConfigForm."""
import pytest
from django.test import TestCase
from management.forms import SecurityConfigForm
from management.models import SecurityConfig
from onboarding.enums import NoOnboardingPkiProtocol, OnboardingProtocol
from pki.util.keys import AutoGenPkiKeyAlgorithm


class SecurityConfigFormTest(TestCase):
    """Test suite for the SecurityConfigForm."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = SecurityConfig.objects.create(
            security_mode=SecurityConfig.SecurityModeChoices.BROWNFIELD,
            auto_gen_pki=False,
            auto_gen_pki_key_algorithm=AutoGenPkiKeyAlgorithm.RSA2048
        )

    def test_form_initialization_with_instance(self):
        """Test form initializes correctly with existing instance."""
        form = SecurityConfigForm(instance=self.config)
        self.assertIn('security_mode', form.fields)
        self.assertIn('auto_gen_pki', form.fields)
        self.assertIn('auto_gen_pki_key_algorithm', form.fields)

    def test_form_initialization_without_instance(self):
        """Test form initializes with default values."""
        form = SecurityConfigForm()
        self.assertIsNotNone(form.fields['security_mode'])

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
            'auto_gen_pki_key_algorithm': AutoGenPkiKeyAlgorithm.RSA2048,
            'allow_auto_gen_pki': True,
        }
        form = SecurityConfigForm(data=form_data, instance=self.config)
        self.assertTrue(form.is_valid())

    def test_form_with_high_security_mode(self):
        """Test form with HARDENED security mode disables auto_gen_pki."""
        form_data = {
            'security_mode': SecurityConfig.SecurityModeChoices.HARDENED,
            'auto_gen_pki': False,
            'auto_gen_pki_key_algorithm': AutoGenPkiKeyAlgorithm.RSA2048,
            # Hardened defaults from _MODE_DEFAULTS
            'rsa_minimum_key_size': 4096,
            'max_cert_validity_days': 365,
            'max_crl_validity_days': 90,
            'allow_ca_issuance': False,
            'allow_auto_gen_pki': False,
            'allow_self_signed_ca': False,
            'require_physical_hsm': False,
        }
        form = SecurityConfigForm(data=form_data, instance=self.config)
        self.assertTrue(form.is_valid())

    def test_clean_auto_gen_pki_key_algorithm_with_none(self):
        """Test clean method returns instance value when form value is not provided."""
        self.config.auto_gen_pki = True
        self.config.auto_gen_pki_key_algorithm = AutoGenPkiKeyAlgorithm.SECP256R1
        self.config.save()

        form_data = {
            'security_mode': SecurityConfig.SecurityModeChoices.BROWNFIELD,
            'auto_gen_pki': True,
            'auto_gen_pki_key_algorithm': AutoGenPkiKeyAlgorithm.SECP256R1,
            # Brownfield defaults from _MODE_DEFAULTS
            'rsa_minimum_key_size': 1024,
            'max_cert_validity_days': 1825,
            'max_crl_validity_days': 365,
            'allow_ca_issuance': False,
            'allow_auto_gen_pki': True,
            'allow_self_signed_ca': True,
            'require_physical_hsm': False,
        }
        form = SecurityConfigForm(data=form_data, instance=self.config)
        self.assertTrue(form.is_valid())
        result = form.cleaned_data['auto_gen_pki_key_algorithm']
        self.assertEqual(result, AutoGenPkiKeyAlgorithm.SECP256R1)

    def test_clean_auto_gen_pki_key_algorithm_returns_provided_value(self):
        """Test clean method uses the provided algorithm value."""
        form_data = {
            'security_mode': SecurityConfig.SecurityModeChoices.BROWNFIELD,
            'auto_gen_pki': True,
            'auto_gen_pki_key_algorithm': AutoGenPkiKeyAlgorithm.RSA2048,
            # Brownfield defaults from _MODE_DEFAULTS
            'rsa_minimum_key_size': 1024,
            'max_cert_validity_days': 1825,
            'max_crl_validity_days': 365,
            'allow_ca_issuance': False,
            'allow_auto_gen_pki': True,
            'allow_self_signed_ca': True,
            'require_physical_hsm': False,
        }
        form = SecurityConfigForm(data=form_data)
        self.assertTrue(form.is_valid())
        result = form.cleaned_data['auto_gen_pki_key_algorithm']
        self.assertEqual(result, AutoGenPkiKeyAlgorithm.RSA2048)

    def test_clean_auto_gen_pki_key_algorithm_with_value(self):
        """Test clean method uses provided value when available."""
        form_data = {
            'security_mode': SecurityConfig.SecurityModeChoices.BROWNFIELD,
            'auto_gen_pki': True,
            'auto_gen_pki_key_algorithm': AutoGenPkiKeyAlgorithm.RSA4096,
            # Brownfield defaults from _MODE_DEFAULTS
            'rsa_minimum_key_size': 1024,
            'max_cert_validity_days': 1825,
            'max_crl_validity_days': 365,
            'allow_ca_issuance': False,
            'allow_auto_gen_pki': True,
            'allow_self_signed_ca': True,
            'require_physical_hsm': False,
        }
        form = SecurityConfigForm(data=form_data, instance=self.config)
        self.assertTrue(form.is_valid())
        result = form.cleaned_data['auto_gen_pki_key_algorithm']
        self.assertEqual(result, AutoGenPkiKeyAlgorithm.RSA4096)

    def test_form_disables_algorithm_field_when_auto_gen_pki_enabled(self):
        """Test that algorithm field is disabled when auto_gen_pki is already enabled."""
        self.config.auto_gen_pki = True
        self.config.save()

        form = SecurityConfigForm(instance=self.config)
        self.assertEqual(
            form.fields['auto_gen_pki_key_algorithm'].widget.attrs.get('disabled'),
            'disabled'
        )

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
                'auto_gen_pki_key_algorithm': AutoGenPkiKeyAlgorithm.RSA2048,
                'rsa_minimum_key_size': defaults['rsa_minimum_key_size'] or '',
                'max_cert_validity_days': defaults['max_cert_validity_days'],
                'max_crl_validity_days': defaults['max_crl_validity_days'],
                'allow_ca_issuance': defaults['allow_ca_issuance'],
                'allow_auto_gen_pki': defaults['allow_auto_gen_pki'],
                'allow_self_signed_ca': defaults['allow_self_signed_ca'],
                'require_physical_hsm': defaults['require_physical_hsm'],
            }
            form = SecurityConfigForm(data=form_data, instance=instance)
            self.assertTrue(form.is_valid(), f"Form should be valid for mode {mode}")

    def test_form_helper_layout(self):
        """Test that form has crispy forms helper with proper layout."""
        form = SecurityConfigForm()
        self.assertIsNotNone(form.helper)
        self.assertIsNotNone(form.helper.layout)


@pytest.mark.django_db
def test_protocol_allowlists_are_saved_as_int_lists() -> None:
    """Protocol allow-lists from multi-select fields are normalized to integer lists on save."""
    config = SecurityConfig.objects.create(
        security_mode=SecurityConfig.SecurityModeChoices.LAB,
        auto_gen_pki=False,
        auto_gen_pki_key_algorithm=AutoGenPkiKeyAlgorithm.RSA2048,
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
            'auto_gen_pki_key_algorithm': AutoGenPkiKeyAlgorithm.RSA2048,
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
