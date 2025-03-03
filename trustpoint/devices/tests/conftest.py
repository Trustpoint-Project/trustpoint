"""pytest configuration for the tests in the devices app."""

import pytest
from pki.models import DomainModel, IssuingCaModel
from pki.util.x509 import CertificateGenerator

from devices.issuer import LocalDomainCredentialIssuer
from devices.models import DeviceModel, RemoteDeviceCredentialDownloadModel


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db: None) -> None:
    """Fixture to enable database access for all tests."""


@pytest.fixture
def mock_models() -> dict:
    return create_mock_models()


def create_mock_models() -> dict:
    """Fixture to create mock CA, domain, device, and credential models for testing."""
    root_1, root_1_key = CertificateGenerator.create_root_ca('Test Root CA')
    issuing_1, issuing_1_key = CertificateGenerator.create_issuing_ca(root_1_key, 'Root CA', 'Issuing CA A')

    CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=issuing_1, private_key=issuing_1_key, chain=[root_1], unique_name='test_local_ca'
    )

    mock_ca = IssuingCaModel.objects.get(unique_name='test_local_ca')

    mock_domain = DomainModel(unique_name='test_domain', issuing_ca=mock_ca)
    mock_domain.save()

    mock_device = DeviceModel(
        unique_name='test_device',
        serial_number='1234567890',
        domain=mock_domain,
        onboarding_protocol=DeviceModel.OnboardingProtocol.NO_ONBOARDING,
        onboarding_status=DeviceModel.OnboardingStatus.PENDING,
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
