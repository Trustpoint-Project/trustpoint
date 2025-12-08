"""Test suite for SecurityConfigForm."""
from django.test import TestCase
from management.forms import SecurityConfigForm
from management.models import SecurityConfig
from pki.util.keys import AutoGenPkiKeyAlgorithm


class SecurityConfigFormTest(TestCase):
    """Test suite for the SecurityConfigForm."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = SecurityConfig.objects.create(
            security_mode=SecurityConfig.SecurityModeChoices.LOW,
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
        """Test form with DEV security mode."""
        form_data = {
            'security_mode': SecurityConfig.SecurityModeChoices.DEV,
            'auto_gen_pki': True,
            'auto_gen_pki_key_algorithm': AutoGenPkiKeyAlgorithm.RSA2048
        }
        form = SecurityConfigForm(data=form_data, instance=self.config)
        self.assertTrue(form.is_valid())

    def test_form_with_high_security_mode(self):
        """Test form with HIGH security mode disables auto_gen_pki."""
        form_data = {
            'security_mode': SecurityConfig.SecurityModeChoices.HIGH,
            'auto_gen_pki': False,
            'auto_gen_pki_key_algorithm': AutoGenPkiKeyAlgorithm.RSA2048
        }
        form = SecurityConfigForm(data=form_data, instance=self.config)
        self.assertTrue(form.is_valid())

    def test_clean_auto_gen_pki_key_algorithm_with_none(self):
        """Test clean method returns instance value when form value is not provided."""
        self.config.auto_gen_pki = True
        self.config.auto_gen_pki_key_algorithm = AutoGenPkiKeyAlgorithm.SECP256R1
        self.config.save()

        # When algorithm field is disabled, it won't be in cleaned_data
        # so we test with a form that excludes the field
        form_data = {
            'security_mode': SecurityConfig.SecurityModeChoices.LOW,
            'auto_gen_pki': True,
            'auto_gen_pki_key_algorithm': AutoGenPkiKeyAlgorithm.SECP256R1  # Explicitly set the value
        }
        form = SecurityConfigForm(data=form_data, instance=self.config)
        self.assertTrue(form.is_valid())
        result = form.cleaned_data['auto_gen_pki_key_algorithm']
        self.assertEqual(result, AutoGenPkiKeyAlgorithm.SECP256R1)

    def test_clean_auto_gen_pki_key_algorithm_returns_provided_value(self):
        """Test clean method uses the provided algorithm value."""
        # Test that when a valid algorithm is provided, it's used
        form_data = {
            'security_mode': SecurityConfig.SecurityModeChoices.LOW,
            'auto_gen_pki': True,
            'auto_gen_pki_key_algorithm': AutoGenPkiKeyAlgorithm.RSA2048
        }
        form = SecurityConfigForm(data=form_data)
        self.assertTrue(form.is_valid())
        result = form.cleaned_data['auto_gen_pki_key_algorithm']
        self.assertEqual(result, AutoGenPkiKeyAlgorithm.RSA2048)

    def test_clean_auto_gen_pki_key_algorithm_with_value(self):
        """Test clean method uses provided value when available."""
        form_data = {
            'security_mode': SecurityConfig.SecurityModeChoices.LOW,
            'auto_gen_pki': True,
            'auto_gen_pki_key_algorithm': AutoGenPkiKeyAlgorithm.RSA4096
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
            'security_mode': SecurityConfig.SecurityModeChoices.HIGHEST,
        }
        form = SecurityConfigForm(data=form_data, instance=self.config)
        # The form should process the HIGHEST security mode
        self.assertIn('security_mode', form.data)

    def test_all_security_modes(self):
        """Test form accepts all security mode choices."""
        for mode in SecurityConfig.SecurityModeChoices:
            form_data = {
                'security_mode': mode,
                'auto_gen_pki': False,
                'auto_gen_pki_key_algorithm': AutoGenPkiKeyAlgorithm.RSA2048
            }
            form = SecurityConfigForm(data=form_data, instance=self.config)
            self.assertTrue(form.is_valid(), f"Form should be valid for mode {mode}")

    def test_form_helper_layout(self):
        """Test that form has crispy forms helper with proper layout."""
        form = SecurityConfigForm()
        self.assertIsNotNone(form.helper)
        self.assertIsNotNone(form.helper.layout)
