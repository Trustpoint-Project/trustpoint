"""Tests for the IDevID authenticator."""

from __future__ import annotations

import uuid

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from devices.models import DeviceModel
from onboarding.models import OnboardingConfigModel, OnboardingPkiProtocol, OnboardingProtocol
from pki.models import DevIdRegistration, DomainModel
from pki.models.truststore import TruststoreModel
from pki.util.idevid import IDevIDAuthenticationError, IDevIDAuthenticator, IDevIDVerifier
from pki.util.x509 import CertificateGenerator

def _create_idevid_cert(
    *,
    common_name: str,
    subject_serial_number: str | None = None,
    san_uris: list[str] | None = None,
) -> x509.Certificate:
    """Create a test IDevID certificate with optional subject serial number and SAN URIs."""
    root_cert, root_key = CertificateGenerator.create_root_ca('IDevID Auth Test Root')

    subject_attributes: list[x509.NameAttribute] = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if subject_serial_number is not None:
        subject_attributes.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, subject_serial_number))

    extensions: list[tuple[x509.ExtensionType, bool]] = []
    if san_uris:
        extensions.append(
            (
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri) for uri in san_uris]),
                False,
            )
        )

    idevid_cert, _idevid_key = CertificateGenerator.create_ee(
        issuer_private_key=root_key,
        issuer_name=root_cert.subject,
        subject_name=x509.Name(subject_attributes),
        extensions=extensions,
    )
    return idevid_cert


def _create_onboarding_config() -> OnboardingConfigModel:
    """Create and save a minimal onboarding config accepted by DeviceModel validation."""
    onboarding_config = OnboardingConfigModel(onboarding_protocol=OnboardingProtocol.MANUAL)
    onboarding_config.set_pki_protocols([OnboardingPkiProtocol.EST])
    onboarding_config.full_clean()
    onboarding_config.save()
    return onboarding_config


def _create_devid_registration(domain: DomainModel, serial_number_pattern: str, unique_name: str) -> DevIdRegistration:
    """Create a DevIdRegistration used by IDevIDAuthenticator lookup."""
    truststore = TruststoreModel.objects.create(
        unique_name=f'{unique_name}-ts',
        intended_usage=TruststoreModel.IntendedUsage.IDEVID,
    )
    return DevIdRegistration.objects.create(
        unique_name=unique_name,
        domain=domain,
        truststore=truststore,
        serial_number_pattern=serial_number_pattern,
    )


def test_authenticate_idevid_from_x509_returns_existing_device_by_uuid(domain_instance: dict[str, object]) -> None:
    """Returns an existing device when SAN UUID already exists in the target domain."""
    domain = domain_instance['domain']
    assert isinstance(domain, DomainModel)

    idevid_uuid = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
    subject_sn = 'SN-UUID-EXISTING'
    idevid_cert = _create_idevid_cert(
        common_name='device-uuid-existing',
        subject_serial_number=subject_sn,
        san_uris=[f'urn:uuid:{idevid_uuid}'],
    )
    _create_devid_registration(domain, rf'^{subject_sn}$', 'reg-uuid-existing')

    existing_device = DeviceModel.objects.create(
        common_name='existing-device-uuid',
        serial_number='DIFFERENT-SN',
        domain=domain,
        onboarding_config=_create_onboarding_config(),
        rfc_4122_uuid=uuid.UUID(idevid_uuid),
    )

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(IDevIDVerifier, 'verify_idevid_against_truststore', lambda *args, **kwargs: True)
        authenticated_device = IDevIDAuthenticator.authenticate_idevid_from_x509(
            idevid_cert=idevid_cert,
            intermediate_cas=[],
            domain=domain,
        )

    assert authenticated_device.pk == existing_device.pk
    assert DeviceModel.objects.count() == 1


def test_authenticate_idevid_from_x509_returns_existing_device_by_serial(domain_instance: dict[str, object]) -> None:
    """Returns an existing device when subject serial number exists and no UUID SAN is present."""
    domain = domain_instance['domain']
    assert isinstance(domain, DomainModel)

    subject_sn = 'SN-SERIAL-EXISTING'
    idevid_cert = _create_idevid_cert(
        common_name='device-sn-existing',
        subject_serial_number=subject_sn,
    )
    _create_devid_registration(domain, rf'^{subject_sn}$', 'reg-serial-existing')

    existing_device = DeviceModel.objects.create(
        common_name='existing-device-serial',
        serial_number=subject_sn,
        domain=domain,
        onboarding_config=_create_onboarding_config(),
    )

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(IDevIDVerifier, 'verify_idevid_against_truststore', lambda *args, **kwargs: True)
        authenticated_device = IDevIDAuthenticator.authenticate_idevid_from_x509(
            idevid_cert=idevid_cert,
            intermediate_cas=[],
            domain=domain,
        )

    assert authenticated_device.pk == existing_device.pk
    assert DeviceModel.objects.count() == 1


def test_authenticate_idevid_from_x509_auto_creates_with_serial_and_uuid(domain_instance: dict[str, object]) -> None:
    """Creates a new device and adopts UUID from SAN when no existing device matches."""
    domain = domain_instance['domain']
    assert isinstance(domain, DomainModel)

    idevid_uuid = '12345678-1234-4234-9234-123456789abc'
    subject_sn = 'SN-NEW-WITH-UUID'
    idevid_cert = _create_idevid_cert(
        common_name='device-autocreate-uuid',
        subject_serial_number=subject_sn,
        san_uris=[f'urn:uuid:{idevid_uuid}'],
    )
    _create_devid_registration(domain, rf'^{subject_sn}$', 'reg-create-uuid')

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(IDevIDVerifier, 'verify_idevid_against_truststore', lambda *args, **kwargs: True)
        authenticated_device = IDevIDAuthenticator.authenticate_idevid_from_x509(
            idevid_cert=idevid_cert,
            intermediate_cas=[],
            domain=domain,
        )

    assert authenticated_device.domain_id == domain.id
    assert authenticated_device.serial_number == subject_sn
    assert str(authenticated_device.rfc_4122_uuid) == idevid_uuid
    assert authenticated_device.onboarding_config is not None
    assert authenticated_device.onboarding_config.onboarding_protocol == OnboardingProtocol.EST_IDEVID


def test_authenticate_idevid_from_x509_auto_creates_with_uuid_only(domain_instance: dict[str, object]) -> None:
    """Creates a new device when certificate has no subject serial number but has UUID SAN URI."""
    domain = domain_instance['domain']
    assert isinstance(domain, DomainModel)

    idevid_uuid = '87654321-4321-4321-8321-cba987654321'
    uuid_uri = f'urn:uuid:{idevid_uuid}'
    idevid_cert = _create_idevid_cert(
        common_name='device-uuid-only',
        san_uris=[uuid_uri],
    )
    _create_devid_registration(domain, rf'^{uuid_uri}$', 'reg-uuid-only')

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(IDevIDVerifier, 'verify_idevid_against_truststore', lambda *args, **kwargs: True)
        authenticated_device = IDevIDAuthenticator.authenticate_idevid_from_x509(
            idevid_cert=idevid_cert,
            intermediate_cas=[],
            domain=domain,
        )

    assert authenticated_device.domain_id == domain.id
    assert authenticated_device.serial_number == ''
    assert str(authenticated_device.rfc_4122_uuid) == idevid_uuid


def test_authenticate_idevid_from_x509_uuid_not_reused_across_domains(issuing_ca_instance: dict[str, object]) -> None:
    """Does not copy SAN UUID to a new device if the same UUID already exists in a different domain."""
    issuing_ca = issuing_ca_instance['issuing_ca']

    first_domain = DomainModel.objects.create(unique_name='idevid-domain-a', issuing_ca=issuing_ca, is_active=True)
    second_domain = DomainModel.objects.create(unique_name='idevid-domain-b', issuing_ca=issuing_ca, is_active=True)

    idevid_uuid = '99999999-1111-4111-8111-222222222222'
    subject_sn = 'SN-UUID-COLLISION'
    idevid_cert = _create_idevid_cert(
        common_name='device-collision',
        subject_serial_number=subject_sn,
        san_uris=[f'urn:uuid:{idevid_uuid}'],
    )
    _create_devid_registration(first_domain, rf'^{subject_sn}$', 'reg-uuid-collision')

    DeviceModel.objects.create(
        common_name='existing-other-domain-device',
        serial_number='OTHER-DOMAIN-SN',
        domain=second_domain,
        onboarding_config=_create_onboarding_config(),
        rfc_4122_uuid=uuid.UUID(idevid_uuid),
    )

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(IDevIDVerifier, 'verify_idevid_against_truststore', lambda *args, **kwargs: True)
        authenticated_device = IDevIDAuthenticator.authenticate_idevid_from_x509(
            idevid_cert=idevid_cert,
            intermediate_cas=[],
            domain=first_domain,
        )

    assert authenticated_device.domain_id == first_domain.id
    assert str(authenticated_device.rfc_4122_uuid) != idevid_uuid


def test_authenticate_idevid_from_x509_rejects_without_subject_sn_and_san_uri() -> None:
    """Rejects certificates that have neither subject serial number nor SAN URI."""
    idevid_cert = _create_idevid_cert(common_name='device-missing-identifiers')

    with pytest.raises(IDevIDAuthenticationError, match='without a Subject DN Serial Number'):
        IDevIDAuthenticator.authenticate_idevid_from_x509(
            idevid_cert=idevid_cert,
            intermediate_cas=[],
        )
