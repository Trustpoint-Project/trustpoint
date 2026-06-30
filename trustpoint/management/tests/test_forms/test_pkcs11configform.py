from django.core.exceptions import ValidationError
from django.test import TestCase

from crypto.models import BackendKind, CryptoProviderPkcs11ConfigModel, CryptoProviderProfileModel, Pkcs11AuthSource
from management.forms import PKCS11ConfigForm


class PKCS11ConfigFormTestCase(TestCase):
    def setUp(self):
        """Set up test environment."""
        CryptoProviderProfileModel.objects.filter(active=True).update(active=False)

    def test_form_initialization_with_existing_token(self):
        """Test that the form initializes with active PKCS#11 profile data."""
        profile = CryptoProviderProfileModel.objects.create(
            name='pkcs11',
            backend_kind=BackendKind.PKCS11,
            active=True,
        )
        CryptoProviderPkcs11ConfigModel.objects.create(
            profile=profile,
            module_path='/usr/lib/libpkcs11-proxy.so',
            token_label='Trustpoint-SoftHSM',
            slot_id=0,
            auth_source=Pkcs11AuthSource.FILE,
            auth_source_ref='/var/lib/trustpoint/hsm/config/user-pin.txt',
        )

        form = PKCS11ConfigForm()

        self.assertEqual(form.fields['token_label'].initial, 'Trustpoint-SoftHSM')
        self.assertEqual(form.fields['slot_id'].initial, 0)
        self.assertEqual(form.fields['module_path'].initial, '/usr/lib/libpkcs11-proxy.so')
        self.assertEqual(form.fields['auth_source_ref'].initial, '/var/lib/trustpoint/hsm/config/user-pin.txt')

    def test_form_initialization_without_existing_token(self):
        """Test that the form initializes empty if no active PKCS#11 profile exists."""
        form = PKCS11ConfigForm()
        self.assertIsNone(form.fields['token_label'].initial)
        self.assertIsNone(form.fields['slot_id'].initial)
        self.assertIsNone(form.fields['module_path'].initial)
        self.assertIsNone(form.fields['auth_source_ref'].initial)

    def test_form_is_read_only_and_valid_without_changes(self):
        """Test that the read-only form accepts no posted changes."""
        form = PKCS11ConfigForm(data={})
        self.assertTrue(form.is_valid())

    def test_save_token_config_is_rejected(self):
        """Test that management cannot mutate PKCS#11 backend config after setup."""
        form = PKCS11ConfigForm(data={})

        with self.assertRaises(ValidationError):
            form.save_token_config()
