"""Test cases for Trustpoint model deletion."""

from typing import Any

import pytest
from django.core.exceptions import ValidationError
from django.db.models import ProtectedError
from pki.models.certificate import CertificateModel
from pki.models.credential import CredentialModel
from pki.models.domain import DomainModel

from devices.models import DeviceModel, IssuedCredentialModel


def test_device_delete_revocation(mock_models: dict[str, Any]) -> None:
    """Tests that credentials issued to a device are deleted and certificates revoked on device deletion."""
    device = mock_models['device']
    assert device.issued_credentials.count() == 1, 'Mock Device should have one issued credential.'
    issued_cred = device.issued_credentials.first()
    assert issued_cred.credential.certificate.certificate_status == CertificateModel.CertificateStatus.OK, (
        'Mock Device credential should not be revoked before deletion.'
    )
    device_id = device.id
    issued_cred_id = issued_cred.id
    cred_id = issued_cred.credential.id
    cert_id = issued_cred.credential.certificate.id
    device.delete()
    # Ensure device, issued credential and credential are deleted
    with pytest.raises(DeviceModel.DoesNotExist):
        DeviceModel.objects.get(id=device_id)
    with pytest.raises(IssuedCredentialModel.DoesNotExist):
        IssuedCredentialModel.objects.get(id=issued_cred_id)
    with pytest.raises(CredentialModel.DoesNotExist):
        CredentialModel.objects.get(id=cred_id)

    # Ensure certificate is revoked
    cert = CertificateModel.objects.get(id=cert_id)
    assert cert.certificate_status == CertificateModel.CertificateStatus.REVOKED, (
        'Certificate should be revoked after delete.'
    )


def test_multi_device_delete(mock_models: dict[str, Any]) -> None:
    """Tests that multiple devices can be deleted and pre_delete is called even on a QuerySet of DeviceModels."""
    mock_domain = mock_models['domain']
    mock_device1 = mock_models['device']
    issued_cred = mock_device1.issued_credentials.first()
    cert_id = issued_cred.credential.certificate.id

    mock_device2 = DeviceModel(
        common_name='test_device2',
        serial_number='1234567890_2',
        domain=mock_domain,
        onboarding_protocol=DeviceModel.OnboardingProtocol.NO_ONBOARDING,
        onboarding_status=DeviceModel.OnboardingStatus.PENDING,
    )
    mock_device2.save()
    DeviceModel.objects.filter(domain=mock_domain).delete()  # queryset delete

    # Ensure certificate of device 1 is also revoked if deleted via queryset
    cert = CertificateModel.objects.get(id=cert_id)
    assert cert.certificate_status == CertificateModel.CertificateStatus.REVOKED, (
        'Certificate should be revoked after delete.'
    )


def test_domain_delete(mock_models: dict[str, Any]) -> None:
    """Tests that a domain can be deleted only if it has no associated devices."""
    domain = mock_models['domain']
    assert domain.devices.exists(), 'Mock Domain should have associated devices.'
    domain_id = domain.id
    with pytest.raises(ProtectedError):
        domain.delete()

    DeviceModel.objects.filter(domain=domain).delete()
    # Ensure domain is deleted after device deletion
    domain.delete()
    with pytest.raises(DomainModel.DoesNotExist):
        DomainModel.objects.get(id=domain_id)


def test_ca_delete_with_issued_certificates(mock_models: dict[str, Any]) -> None:
    """Tests that a CA can be deleted only if it has no associated domains and no issued unexpired certificates."""
    ca = mock_models['ca']
    assert ca.domains.exists(), 'Mock CA should have associated domains.'
    # Ensure CA cannot be deleted with issued certificates
    with pytest.raises(ValidationError):
        ca.delete()
