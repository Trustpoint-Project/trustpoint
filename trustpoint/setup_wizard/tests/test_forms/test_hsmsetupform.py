from django.test import TestCase

from setup_wizard.forms import HsmSetupForm


class HsmSetupFormTestCase(TestCase):
    def setUp(self):
        """Set up valid data for testing."""
        self.valid_data = {
            'hsm_type': 'softhsm',
            'module_path': '/usr/lib/softhsm/libsofthsm2.so',
            'slot': 0,
            'label': 'Trustpoint-SoftHSM',
        }

    def test_form_initialization(self):
        """Test that the form initializes with default values."""
        form = HsmSetupForm()
        self.assertEqual(form.fields['hsm_type'].initial, 'softhsm')
        self.assertEqual(form.fields['module_path'].initial, '/usr/lib/softhsm/libsofthsm2.so')
        self.assertEqual(form.fields['slot'].initial, 0)
        self.assertEqual(form.fields['label'].initial, 'Trustpoint-SoftHSM')

    def test_valid_data_for_softhsm(self):
        """Test that the form is valid with correct data for SoftHSM."""
        form = HsmSetupForm(data=self.valid_data)
        self.assertTrue(form.is_valid())
        cleaned_data = form.clean()
        self.assertEqual(cleaned_data['hsm_type'], 'softhsm')
        self.assertEqual(cleaned_data['module_path'], '/usr/lib/softhsm/libsofthsm2.so')
        self.assertEqual(cleaned_data['slot'], 0)
        self.assertEqual(cleaned_data['label'], 'Trustpoint-SoftHSM')

    def test_invalid_hsm_type(self):
        """Test that the form is invalid with an unsupported HSM type."""
        invalid_data = self.valid_data.copy()
        invalid_data['hsm_type'] = 'unsupported_hsm'
        form = HsmSetupForm(data=invalid_data)
        self.assertFalse(form.is_valid())
        self.assertIn('hsm_type', form.errors)

    def test_physical_hsm_not_supported(self):
        """Test that the form raises an error for physical HSM."""
        invalid_data = self.valid_data.copy()
        invalid_data['hsm_type'] = 'physical'
        form = HsmSetupForm(data=invalid_data)
        self.assertFalse(form.is_valid())
        self.assertIn('Physical HSM is not yet supported.', form.errors['__all__'])

    def test_clean_label_for_softhsm(self):
        """Test that the label is overridden for SoftHSM."""
        data = self.valid_data.copy()
        data['label'] = 'CustomLabel'  # This will be ignored for SoftHSM
        form = HsmSetupForm(data=data)
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['label'], 'Trustpoint-SoftHSM')

    def test_clean_slot_for_softhsm(self):
        """Test that the slot is overridden for SoftHSM."""
        data = self.valid_data.copy()
        data['slot'] = 5  # This will be overridden for SoftHSM
        form = HsmSetupForm(data=data)
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['slot'], 0)

    def test_clean_module_path_for_softhsm(self):
        """Test that the module path is overridden for SoftHSM."""
        data = self.valid_data.copy()
        data['module_path'] = '/custom/path/libsofthsm2.so'  # This will be overridden for SoftHSM
        form = HsmSetupForm(data=data)
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['module_path'], '/usr/lib/softhsm/libsofthsm2.so')

    def test_missing_required_fields(self):
        """Test that the form is invalid if required fields are missing."""
        invalid_data = {'hsm_type': 'softhsm'}  # Missing other required fields
        form = HsmSetupForm(data=invalid_data)
        self.assertFalse(form.is_valid())
        self.assertIn('label', form.errors)
        self.assertIn('slot', form.errors)
        self.assertIn('module_path', form.errors)
