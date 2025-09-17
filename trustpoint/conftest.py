"""pytest configuration for the tests in the PKI app."""

from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from devices.issuer import LocalTlsClientCredentialIssuer
from devices.models import (
    DeviceModel, IssuedCredentialModel, RemoteDeviceCredentialDownloadModel,
    NoOnboardingConfigModel, NoOnboardingPkiProtocol,
    OnboardingConfigModel, OnboardingPkiProtocol, OnboardingProtocol
)
from pki.models import CertificateModel, CredentialModel
from pki.models.domain import DomainModel
from pki.models.issuing_ca import IssuingCaModel
from pki.util.x509 import CertificateGenerator
from trustpoint_core.serializer import CredentialSerializer

@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db: None) -> None:
    """Fixture to enable database access for all tests."""


# ----------------------------
# RSA Private Key Fixture
# ----------------------------


@pytest.fixture
def rsa_private_key() -> rsa.RSAPrivateKey:
    """Generate a reusable RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


# ----------------------------
# EC Private Key Fixture
# ----------------------------


@pytest.fixture
def ec_private_key() -> ec.EllipticCurvePrivateKey:
    """Generate a reusable EC private key."""
    return ec.generate_private_key(ec.SECP256R1())


# ----------------------------
# Test model instance Fixtures
# ----------------------------

CA_COMMON_NAME = 'Root CA'
UNIQUE_NAME = CA_COMMON_NAME.replace(' ', '_').lower()
CA_TYPE = IssuingCaModel.IssuingCaTypeChoice.LOCAL_UNPROTECTED

DOMAIN_UNIQUE_NAME = 'domain_name'


@pytest.fixture
def issuing_ca_instance() -> dict[str, Any]:
    """Fixture for a testing IssuingCaModel instance."""
    cert, priv_key = CertificateGenerator.create_root_ca(cn=CA_COMMON_NAME)
    issuing_ca = CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=cert, private_key=priv_key, chain=[], unique_name=UNIQUE_NAME, ca_type=CA_TYPE
    )
    return {'issuing_ca': issuing_ca, 'cert': cert, 'priv_key': priv_key}


@pytest.fixture
def domain_instance(issuing_ca_instance: dict[str, Any]) -> dict[str, Any]:
    """Fixture for a DomainModel instance using a valid issuing CA."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    priv_key = issuing_ca_instance.get('priv_key')
    cert = issuing_ca_instance.get('cert')
    if (
        not isinstance(issuing_ca, IssuingCaModel)
        or not isinstance(cert, x509.Certificate)
        or not isinstance(priv_key, RSAPrivateKey)
    ):
        msg = 'Issuing CA not created properly'
        raise TypeError(msg)
    domain = DomainModel.objects.create(unique_name=DOMAIN_UNIQUE_NAME, issuing_ca=issuing_ca, is_active=True)
    issuing_ca_instance.update({'domain': domain})
    return issuing_ca_instance

@pytest.fixture
def device_instance(domain_instance: dict[str, Any]) -> dict[str, Any]:
    """Fixture to create a test device linked with a domain."""
    domain: DomainModel = domain_instance['domain']

    no_onboarding_pki_protocols = [
        NoOnboardingPkiProtocol.MANUAL
    ]
    no_onboarding_config_model = NoOnboardingConfigModel()
    no_onboarding_config_model.set_pki_protocols(no_onboarding_pki_protocols)

    no_onboarding_config_model.full_clean()
    no_onboarding_config_model.save()

    device = DeviceModel.objects.create(
        common_name='test-device-1',
        serial_number='TEST123456',
        domain=domain,
        no_onboarding_config=no_onboarding_config_model,
    )
    domain_instance.update({'device': device})
    return domain_instance

@pytest.fixture
def device_instance_onboarding(domain_instance: dict[str, Any]) -> dict[str, Any]:
    """Fixture to create a test device linked with a domain."""
    domain: DomainModel = domain_instance['domain']

    onboarding_pki_protocols = [
        OnboardingPkiProtocol.EST
    ]
    onboarding_config_model = OnboardingConfigModel(onboarding_protocol=OnboardingProtocol.MANUAL)
    onboarding_config_model.set_pki_protocols(onboarding_pki_protocols)

    onboarding_config_model.full_clean()
    onboarding_config_model.save()

    device = DeviceModel.objects.create(
        common_name='test-device-1',
        serial_number='TEST123456',
        domain=domain,
        onboarding_config=onboarding_config_model,
    )
    domain_instance.update({'device': device})
    return domain_instance

@pytest.fixture
def tls_client_credential_instance(device_instance: dict[str, Any]) -> dict[str, Any]:
    """Fixture to issue a TLS client credential for a specific device."""
    device: DeviceModel = device_instance['device']

    if device.domain is None:
        error_message = "Device's associated domain cannot be None"
        raise ValueError(error_message)

    issuer = LocalTlsClientCredentialIssuer(device=device, domain=device.domain)
    common_name = 'Fixture TLS Client Credential'
    validity_days = 365
    issued_credential = issuer.issue_tls_client_credential(common_name=common_name, validity_days=validity_days)
    device_instance.update({'issued_credential': issued_credential})
    return device_instance

@pytest.fixture
def remote_device_credential_download_instance(
        tls_client_credential_instance: dict[str, Any]
) -> dict[str, Any]:
    """Fixture to create a RemoteDeviceCredentialDownloadModel."""
    tls_client_credential: IssuedCredentialModel = tls_client_credential_instance['issued_credential']
    device: DeviceModel = tls_client_credential_instance['device']

    otp_token = 'example-otp'   # noqa: S105

    remote_credential = RemoteDeviceCredentialDownloadModel.objects.create(
        issued_credential_model=tls_client_credential,
        otp=otp_token,
        device=device,
    )
    tls_client_credential_instance.update({'remote_credential': remote_credential})

    return tls_client_credential_instance

@pytest.fixture
def credential_instance(issuing_ca_instance: dict[str, Any]) -> dict[str, Any]:
    """Fixture to create a CredentialModel instance linked to a valid end-entity certificate."""
    issuing_ca_cert = issuing_ca_instance['cert']
    issuing_ca_priv_key = issuing_ca_instance['priv_key']

    subject_cn = 'Test End-Entity Certificate'
    ee_cert, ee_private_key = CertificateGenerator.create_ee(
        issuer_private_key=issuing_ca_priv_key,
        issuer_cn=issuing_ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
        subject_name=subject_cn,
        validity_days=365,
    )

    CertificateModel.save_certificate(ee_cert)

    serializer = CredentialSerializer(
        private_key=ee_private_key,
        certificate=ee_cert,
        additional_certificates=[issuing_ca_cert],
    )

    credential = CredentialModel.save_credential_serializer(
        credential_serializer=serializer,
        credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL,
    )

    issuing_ca_instance.update({'credential': credential})

    return issuing_ca_instance



