"""pytest configuration for the tests in the devices app."""

from typing import Any

import pytest
from pki.models import DomainModel, CaModel
from management.models import KeyStorageConfig
from pki.util.x509 import CertificateGenerator

from devices.issuer import LocalDomainCredentialIssuer
from devices.models import DeviceModel, NoOnboardingConfigModel, NoOnboardingPkiProtocol, RemoteDeviceCredentialDownloadModel


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db: None) -> None:
    """Fixture to enable database access for all tests."""


@pytest.fixture
def mock_models() -> dict[str, Any]:
    """Creates mock models."""
    return create_mock_models()


def create_mock_models() -> dict[str, Any]:
    """Fixture to create mock CA, domain, device, and credential models for testing."""
    # Ensure crypto storage config exists for encrypted fields
    KeyStorageConfig.get_or_create_default()
    
    root_1, root_1_key = CertificateGenerator.create_root_ca('Test Root CA')
    issuing_1, issuing_1_key = CertificateGenerator.create_issuing_ca(root_1_key, 'Root CA', 'Issuing CA A')

    CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=issuing_1, private_key=issuing_1_key, chain=[root_1], unique_name='test_local_ca'
    )

    mock_ca = CaModel.objects.get(unique_name='test_local_ca')

    mock_domain = DomainModel(unique_name='test_domain', issuing_ca=mock_ca)
    mock_domain.save()

    no_onboarding_pki_protocols = [
        NoOnboardingPkiProtocol.MANUAL
    ]
    no_onboarding_config_model = NoOnboardingConfigModel()
    no_onboarding_config_model.set_pki_protocols(no_onboarding_pki_protocols)

    no_onboarding_config_model.full_clean()
    no_onboarding_config_model.save()

    mock_device = DeviceModel(
        common_name='test_device',
        serial_number='1234567890',
        domain=mock_domain,
        no_onboarding_config=no_onboarding_config_model,
    )
    mock_device.save()

    credential_issuer = LocalDomainCredentialIssuer(device=mock_device, domain=mock_domain)
    mock_issued_credential = credential_issuer.issue_domain_credential()

    mock_remote_credential_download = RemoteDeviceCredentialDownloadModel(
        issued_credential_model=mock_issued_credential, device=mock_device
    )

    return {
        'device': mock_device,
        'domain': mock_domain,
        'ca': mock_ca,
        'issued_credential': mock_issued_credential,
        'remote_credential_download': mock_remote_credential_download,
    }
