"""Tests for the fresh-install backend configuration form."""

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from setup_wizard.forms import FreshInstallBackendConfigModelForm
from setup_wizard.models import SetupWizardConfigModel


class FreshInstallBackendConfigModelFormTests(TestCase):
    """Tests for the simplified PKCS#11 backend configuration step."""

    def test_non_hsm_backend_hides_pkcs11_fields(self) -> None:
        config_model = SetupWizardConfigModel.get_singleton()
        config_model.crypto_storage = SetupWizardConfigModel.CryptoStorageType.SoftwareStorage

        form = FreshInstallBackendConfigModelForm(instance=config_model)

        self.assertTrue(form.fields['fresh_install_pkcs11_token_label'].widget.is_hidden)
        self.assertTrue(form.fields['pkcs11_module_upload'].widget.is_hidden)
        self.assertTrue(form.fields['pkcs11_user_pin'].widget.is_hidden)

    def test_pkcs11_form_prefills_token_label(self) -> None:
        config_model = SetupWizardConfigModel.get_singleton()
        config_model.crypto_storage = SetupWizardConfigModel.CryptoStorageType.HsmStorage
        config_model.fresh_install_pkcs11_token_label = 'Trustpoint-SoftHSM'

        form = FreshInstallBackendConfigModelForm(instance=config_model)

        self.assertEqual(form.initial['fresh_install_pkcs11_token_label'], 'Trustpoint-SoftHSM')

    def test_pkcs11_form_requires_module_upload_and_user_pin(self) -> None:
        config_model = SetupWizardConfigModel.get_singleton()
        config_model.crypto_storage = SetupWizardConfigModel.CryptoStorageType.HsmStorage

        form = FreshInstallBackendConfigModelForm(
            data={
                'fresh_install_pkcs11_token_label': 'Trustpoint-SoftHSM',
                'pkcs11_user_pin': '',
            },
            instance=config_model,
        )

        self.assertFalse(form.is_valid())
        self.assertIn('pkcs11_module_upload', form.errors)
        self.assertIn('pkcs11_user_pin', form.errors)

    def test_pkcs11_form_accepts_valid_upload_and_pin(self) -> None:
        config_model = SetupWizardConfigModel.get_singleton()
        config_model.crypto_storage = SetupWizardConfigModel.CryptoStorageType.HsmStorage

        form = FreshInstallBackendConfigModelForm(
            data={
                'fresh_install_pkcs11_token_label': 'Trustpoint-SoftHSM',
                'pkcs11_user_pin': '1234',
            },
            files={
                'pkcs11_module_upload': SimpleUploadedFile('libpkcs11-vendor.so', b'pkcs11-bytes'),
            },
            instance=config_model,
        )

        self.assertTrue(form.is_valid(), form.errors)

    def test_pkcs11_form_accepts_local_dev_fallback_without_upload(self) -> None:
        config_model = SetupWizardConfigModel.get_singleton()
        config_model.crypto_storage = SetupWizardConfigModel.CryptoStorageType.HsmStorage

        with patch('setup_wizard.forms.local_dev_pkcs11_handoff_available', return_value=True):
            form = FreshInstallBackendConfigModelForm(
                data={
                    'fresh_install_pkcs11_token_label': 'Trustpoint-SoftHSM',
                    'pkcs11_user_pin': '1234',
                },
                instance=config_model,
            )

        self.assertTrue(form.is_valid(), form.errors)

    def test_pkcs11_form_accepts_existing_staged_assets(self) -> None:
        with TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            module_path = temp_root / 'uploaded-pkcs11-module.so'
            pin_path = temp_root / 'user-pin.txt'
            module_path.write_bytes(b'pkcs11-bytes')
            pin_path.write_text('1234', encoding='utf-8')

            config_model = SetupWizardConfigModel.get_singleton()
            config_model.crypto_storage = SetupWizardConfigModel.CryptoStorageType.HsmStorage
            config_model.fresh_install_pkcs11_module_path = str(module_path)
            config_model.fresh_install_pkcs11_auth_source_ref = str(pin_path)

            form = FreshInstallBackendConfigModelForm(
                data={
                    'fresh_install_pkcs11_token_label': 'Trustpoint-SoftHSM',
                    'pkcs11_user_pin': '',
                },
                instance=config_model,
            )

        self.assertTrue(form.is_valid(), form.errors)
