"""Tests for the redesigned fresh-install wizard views."""

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from django.test import SimpleTestCase, TestCase, override_settings

from appsecrets.models import (
    AppSecretBackendKind,
    AppSecretBackendModel,
    AppSecretPkcs11ConfigModel,
    AppSecretSoftwareConfigModel,
)
from crypto.models import (
    BackendKind,
    CryptoProviderPkcs11ConfigModel,
    CryptoProviderProfileModel,
    CryptoProviderSoftwareConfigModel,
    SoftwareKeyEncryptionSource,
)
from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.views import (
    FreshInstallFormBaseView,
    FreshInstallSummaryTruststoreDownloadView,
    FreshInstallSummaryView,
    FreshInstallTlsConfigView,
)


class FreshInstallTlsConfigViewTests(SimpleTestCase):
    """Small unit tests for current fresh-install helpers."""

    def test_format_csv_initial_with_values(self) -> None:
        self.assertEqual(FreshInstallTlsConfigView._format_csv_initial(['a', 'b']), 'a, b, ')

    def test_format_csv_initial_without_values(self) -> None:
        self.assertEqual(FreshInstallTlsConfigView._format_csv_initial([]), '')

    def test_get_step_state_active(self) -> None:
        step = Mock()
        self.assertEqual(
            FreshInstallFormBaseView._get_step_state(step, step, Mock(), is_submitted=False),
            FreshInstallFormBaseView.StepState.ACTIVE,
        )


class FreshInstallSummaryTruststoreDownloadViewTests(SimpleTestCase):
    """Tests for summary truststore download helper behavior."""

    def setUp(self) -> None:
        self.root_ca_serializer = Mock()
        self.root_ca_serializer.as_pem.return_value = b'pem'
        self.root_ca_serializer.as_der.return_value = b'der'

    def test_get_root_ca_certificate_and_content_type_for_pem(self) -> None:
        content, content_type = FreshInstallSummaryTruststoreDownloadView._get_root_ca_certificate_and_content_type(
            self.root_ca_serializer,
            'pem',
        )

        self.assertEqual(content, b'pem')
        self.assertEqual(content_type, 'application/x-pem-file')

    def test_get_root_ca_certificate_and_content_type_for_der(self) -> None:
        content, content_type = FreshInstallSummaryTruststoreDownloadView._get_root_ca_certificate_and_content_type(
            self.root_ca_serializer,
            'der',
        )

        self.assertEqual(content, b'der')
        self.assertEqual(content_type, 'application/pkix-cert')


class FreshInstallSummaryBackendConfigurationTests(TestCase):
    """Tests for configuring the crypto backend from the summary step."""

    @override_settings(DEVELOPMENT_ENV=True)
    def test_configure_instance_crypto_backend_creates_software_profile(self) -> None:
        config_model = SetupWizardConfigModel.get_singleton()
        config_model.crypto_storage = SetupWizardConfigModel.CryptoStorageType.SoftwareStorage
        config_model.save()

        FreshInstallSummaryView._configure_instance_crypto_backend(config_model)

        profile = CryptoProviderProfileModel.objects.get(active=True)
        software_config = CryptoProviderSoftwareConfigModel.objects.get(profile=profile)
        self.assertEqual(profile.backend_kind, BackendKind.SOFTWARE)
        self.assertEqual(software_config.encryption_source, SoftwareKeyEncryptionSource.DEV_PLAINTEXT)

    @override_settings(DEVELOPMENT_ENV=True)
    def test_configure_app_secret_backend_creates_software_backend(self) -> None:
        config_model = SetupWizardConfigModel.get_singleton()
        config_model.crypto_storage = SetupWizardConfigModel.CryptoStorageType.SoftwareStorage
        config_model.save()

        with patch('setup_wizard.views.get_app_secret_service') as mock_get_service:
            mock_get_service.return_value.ensure_backend_ready.return_value = None
            FreshInstallSummaryView._configure_app_secret_backend(config_model)

        backend = AppSecretBackendModel.objects.get(pk=AppSecretBackendModel.SINGLETON_ID)
        AppSecretSoftwareConfigModel.objects.get(backend=backend)
        self.assertEqual(backend.backend_kind, AppSecretBackendKind.SOFTWARE)

    def test_configure_instance_crypto_backend_creates_pkcs11_profile(self) -> None:
        with TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            module_path = temp_root / 'libpkcs11.so'
            pin_file = temp_root / 'user-pin.txt'
            module_path.write_text('', encoding='utf-8')
            pin_file.write_text('1234', encoding='utf-8')

            with override_settings(
                HSM_DEFAULT_PKCS11_MODULE_PATH=module_path,
                HSM_DEFAULT_USER_PIN_FILE=pin_file,
                HSM_DEFAULT_TOKEN_LABEL='Trustpoint-SoftHSM',
            ):
                config_model = SetupWizardConfigModel.get_singleton()
                config_model.crypto_storage = SetupWizardConfigModel.CryptoStorageType.HsmStorage
                config_model.fresh_install_pkcs11_token_label = 'Trustpoint-SoftHSM'
                config_model.save()

                FreshInstallSummaryView._configure_instance_crypto_backend(config_model)

        profile = CryptoProviderProfileModel.objects.get(active=True)
        pkcs11_config = CryptoProviderPkcs11ConfigModel.objects.get(profile=profile)
        self.assertEqual(profile.backend_kind, BackendKind.PKCS11)
        self.assertEqual(pkcs11_config.token_label, 'Trustpoint-SoftHSM')
        self.assertIsNone(pkcs11_config.token_serial)

    def test_configure_app_secret_backend_creates_pkcs11_backend(self) -> None:
        with TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            module_path = temp_root / 'libpkcs11.so'
            pin_file = temp_root / 'user-pin.txt'
            module_path.write_text('', encoding='utf-8')
            pin_file.write_text('1234', encoding='utf-8')

            profile = CryptoProviderProfileModel.objects.create(
                name='trustpoint-pkcs11-backend',
                backend_kind=BackendKind.PKCS11,
                active=True,
            )
            CryptoProviderPkcs11ConfigModel.objects.create(
                profile=profile,
                module_path=str(module_path),
                token_label='Trustpoint-SoftHSM',
                token_serial=None,
                slot_id=None,
                auth_source='file',
                auth_source_ref=str(pin_file),
            )

            config_model = SetupWizardConfigModel.get_singleton()
            config_model.crypto_storage = SetupWizardConfigModel.CryptoStorageType.HsmStorage
            config_model.save()

            with patch('setup_wizard.views.get_app_secret_service') as mock_get_service:
                mock_get_service.return_value.ensure_backend_ready.return_value = None
                FreshInstallSummaryView._configure_app_secret_backend(config_model)

        backend = AppSecretBackendModel.objects.get(pk=AppSecretBackendModel.SINGLETON_ID)
        secret_config = AppSecretPkcs11ConfigModel.objects.get(backend=backend)
        self.assertEqual(backend.backend_kind, AppSecretBackendKind.PKCS11)
        self.assertEqual(secret_config.token_label, 'Trustpoint-SoftHSM')
