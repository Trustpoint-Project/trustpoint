"""pytest configuration for the tests in the PKI app."""

import base64
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from devices.issuer import LocalDomainCredentialIssuer, LocalTlsClientCredentialIssuer
from devices.models import (
    DeviceModel,
    IssuedCredentialModel,
    NoOnboardingConfigModel,
    NoOnboardingPkiProtocol,
    OnboardingConfigModel,
    OnboardingPkiProtocol,
    OnboardingProtocol,
    RemoteDeviceCredentialDownloadModel,
)
from django.http import HttpRequest
from django.test.client import RequestFactory
from management.models import KeyStorageConfig
from pki.models import CertificateModel, CredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.domain import DomainAllowedCertificateProfileModel, DomainModel
from pki.models import CaModel
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
CA_TYPE = CaModel.CaTypeChoice.LOCAL_UNPROTECTED

DOMAIN_UNIQUE_NAME = 'domain_test_instance'


@pytest.fixture
def issuing_ca_instance() -> dict[str, Any]:
    """Fixture for a testing CaModel instance."""
    # Ensure crypto storage config exists for encrypted fields
    KeyStorageConfig.get_or_create_default()

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
        not isinstance(issuing_ca, CaModel)
        or not isinstance(cert, x509.Certificate)
        or not isinstance(priv_key, RSAPrivateKey)
    ):
        msg = 'Issuing CA not created properly'
        raise TypeError(msg)
    domain = DomainModel.objects.create(unique_name=DOMAIN_UNIQUE_NAME, issuing_ca=issuing_ca, is_active=True)
    issuing_ca_instance.update({'domain': domain})
    return issuing_ca_instance


@pytest.fixture
def cert_profile_instance(domain_instance: dict[str, Any]) -> None:
    """Fixture to create a domain_credential CertificateProfileModel instance linked to the domain fixture."""
    domain: DomainModel = domain_instance['domain']

    cert_profile = CertificateProfileModel.objects.create(
        unique_name='domain_credential',
        profile_json='{"type": "cert_profile", "subj": {"allow":"*"}, "ext": {}, "validity": {"days": 30}}',
    )

    DomainAllowedCertificateProfileModel.objects.create(
        domain=domain, certificate_profile=cert_profile, alias='test_profile_alias'
    )


@pytest.fixture
def cert_profile_instance_tls_server(domain_instance: dict[str, Any]) -> None:
    """Fixture to create a tls_server CertificateProfileModel instance linked to the domain fixture."""
    domain: DomainModel = domain_instance['domain']

    cert_profile = CertificateProfileModel.objects.create(
        unique_name='tls_server',
        profile_json='{"type": "cert_profile", "subj": {"allow":"*"}, "ext": {}, "validity": {"days": 10}}',
    )

    DomainAllowedCertificateProfileModel.objects.create(
        domain=domain, certificate_profile=cert_profile, alias='test_profile_alias_tls'
    )


@pytest.fixture
def device_instance(domain_instance: dict[str, Any]) -> dict[str, Any]:
    """Fixture to create a test device linked with a domain."""
    domain: DomainModel = domain_instance['domain']

    no_onboarding_pki_protocols = [NoOnboardingPkiProtocol.MANUAL]
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

    onboarding_pki_protocols = [OnboardingPkiProtocol.EST]
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
def est_device_without_onboarding(
    domain_instance: dict[str, Any], cert_profile_instance_tls_server: None
) -> dict[str, Any]:
    """Fixture to create a device using the EST protocol without onboarding."""
    domain: DomainModel = domain_instance['domain']

    no_onboarding_config = NoOnboardingConfigModel(est_password='test_est_password')  # noqa: S106
    no_onboarding_config.add_pki_protocol(NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD)
    no_onboarding_config.full_clean()
    no_onboarding_config.save()

    device = DeviceModel.objects.create(
        common_name='NoOnboarding_EST',
        serial_number='SN-NO-EST',
        domain=domain,
        no_onboarding_config=no_onboarding_config,
    )
    domain_instance.update({'device': device})
    return domain_instance


@pytest.fixture
def est_device_with_onboarding(
    domain_instance: dict[str, Any], cert_profile_instance: None, cert_profile_instance_tls_server: None
) -> dict[str, Any]:
    """Fixture to create a device using the EST protocol with onboarding."""
    domain: DomainModel = domain_instance['domain']
    onboarding_pki_protocols = [OnboardingPkiProtocol.EST]
    onboarding_config_model = OnboardingConfigModel(
        onboarding_protocol=OnboardingProtocol.EST_USERNAME_PASSWORD, est_password='test_est_password'
    )  # noqa: S106
    onboarding_config_model.set_pki_protocols(onboarding_pki_protocols)

    onboarding_config_model.full_clean()
    onboarding_config_model.save()

    device = DeviceModel.objects.create(
        common_name='EST_Onboarding',
        serial_number='SN-EST-ONBOARD',
        domain=domain,
        onboarding_config=onboarding_config_model,
    )
    domain_instance.update({'device': device})
    return domain_instance


@pytest.fixture
def cmp_device_without_onboarding(
    domain_instance: dict[str, Any], cert_profile_instance_tls_server: None
) -> dict[str, Any]:
    """Fixture to create a device using the CMP protocol without onboarding."""
    domain: DomainModel = domain_instance['domain']
    no_onboarding_config = NoOnboardingConfigModel(cmp_shared_secret='test_cmp_secret')  # noqa: S106
    no_onboarding_config.add_pki_protocol(NoOnboardingPkiProtocol.CMP_SHARED_SECRET)
    no_onboarding_config.full_clean()
    no_onboarding_config.save()

    device = DeviceModel.objects.create(
        common_name='NoOnboarding_CMP',
        serial_number='SN_NO_CMP',
        domain=domain,
        no_onboarding_config=no_onboarding_config,
    )
    domain_instance.update({'device': device})
    return domain_instance


@pytest.fixture
def cmp_device_with_onboarding(
    domain_instance: dict[str, Any], cert_profile_instance: None, cert_profile_instance_tls_server: None
) -> dict[str, Any]:
    """Fixture to create a device using the CMP protocol with onboarding."""
    domain: DomainModel = domain_instance['domain']
    onboarding_pki_protocols = [OnboardingPkiProtocol.CMP]
    onboarding_config_model = OnboardingConfigModel(onboarding_protocol=OnboardingProtocol.CMP_IDEVID)
    onboarding_config_model.set_pki_protocols(onboarding_pki_protocols)

    onboarding_config_model.full_clean()
    onboarding_config_model.save()

    device = DeviceModel.objects.create(
        common_name='CMP_Onboarding',
        serial_number='SN-CMP-ONBOARD',
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
def remote_device_credential_download_instance(tls_client_credential_instance: dict[str, Any]) -> dict[str, Any]:
    """Fixture to create a RemoteDeviceCredentialDownloadModel."""
    tls_client_credential: IssuedCredentialModel = tls_client_credential_instance['issued_credential']
    device: DeviceModel = tls_client_credential_instance['device']

    otp_token = 'example-otp'  # noqa: S105

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
        issuer_name=issuing_ca_cert.subject,
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


@pytest.fixture
def domain_credential_est_onboarding(
    est_device_with_onboarding: dict[str, Any], rsa_private_key: rsa.RSAPrivateKey
) -> dict[str, Any]:
    """Fixture to create a domain credential linked to an EST device."""
    device: DeviceModel = est_device_with_onboarding['device']
    domain: DomainModel = device.domain

    if domain is None:
        msg = 'The associated domain for the device cannot be None'
        raise ValueError(msg)

    credential_request = rsa_private_key.public_key()

    domain_credential_issuer = LocalDomainCredentialIssuer(device=device, domain=domain)
    issued_domain_credential = domain_credential_issuer.issue_domain_credential_certificate(
        public_key=credential_request
    )

    est_device_with_onboarding.update({'domain_credential': issued_domain_credential})
    return est_device_with_onboarding


@pytest.fixture
def domain_credential_cmp_onboarding(
    cmp_device_with_onboarding: dict[str, Any], rsa_private_key: rsa.RSAPrivateKey
) -> dict[str, Any]:
    """Fixture to create a domain credential linked to an CMP device."""
    device: DeviceModel = cmp_device_with_onboarding['device']
    domain: DomainModel = device.domain

    if domain is None:
        msg = 'The associated domain for the device cannot be None'
        raise ValueError(msg)

    credential_request = rsa_private_key.public_key()

    domain_credential_issuer = LocalDomainCredentialIssuer(device=device, domain=domain)
    issued_domain_credential = domain_credential_issuer.issue_domain_credential_certificate(
        public_key=credential_request
    )

    cmp_device_with_onboarding.update({'domain_credential': issued_domain_credential})
    return cmp_device_with_onboarding


@pytest.fixture
def tls_client_certificate_instance_est_onboarding(
    est_device_with_onboarding: dict[str, Any], rsa_private_key: rsa.RSAPrivateKey
) -> dict[str, Any]:
    """Fixture to issue a TLS client certificate for an EST device WITH onboarding."""
    device: DeviceModel = est_device_with_onboarding['device']
    domain: DomainModel = device.domain

    if domain is None:
        msg = 'The associated domain for the device cannot be None'
        raise ValueError(msg)

    credential_request = rsa_private_key.public_key()

    tls_client_issuer = LocalTlsClientCredentialIssuer(device=device, domain=domain)
    common_name = 'Fixture TLS Client Certificate'
    issued_tls_client_certificate = tls_client_issuer.issue_tls_client_certificate(
        common_name=common_name,
        public_key=credential_request,
        validity_days=365,
    )

    est_device_with_onboarding.update({'tls_client_certificate': issued_tls_client_certificate})
    return est_device_with_onboarding


@pytest.fixture
def tls_client_certificate_instance_est_no_onboarding(
    est_device_without_onboarding: dict[str, Any], rsa_private_key: rsa.RSAPrivateKey
) -> dict[str, Any]:
    """Fixture to issue a TLS client certificate for an EST device WITHOUT onboarding."""
    device: DeviceModel = est_device_without_onboarding['device']
    domain: DomainModel = device.domain

    if domain is None:
        msg = 'The associated domain for the device cannot be None'
        raise ValueError(msg)

    credential_request = rsa_private_key.public_key()

    tls_client_issuer = LocalTlsClientCredentialIssuer(device=device, domain=domain)
    common_name = 'TLS Client Certificate for EST without Onboarding'

    issued_tls_client_certificate = tls_client_issuer.issue_tls_client_certificate(
        common_name=common_name,
        public_key=credential_request,
        validity_days=365,
    )

    est_device_without_onboarding.update({'tls_client_certificate': issued_tls_client_certificate})
    return est_device_without_onboarding


@pytest.fixture
def domain_credential_instance_for_cmp(
    cmp_device_with_onboarding: dict[str, Any], rsa_private_key: rsa.RSAPrivateKey
) -> dict[str, Any]:
    """Fixture to create a domain credential linked to a CMP device."""
    device: DeviceModel = cmp_device_with_onboarding['device']
    domain: DomainModel = device.domain

    if domain is None:
        msg = 'The associated domain for the device cannot be None'
        raise ValueError(msg)

    credential_request = rsa_private_key.public_key()

    domain_credential_issuer = LocalDomainCredentialIssuer(device=device, domain=domain)
    issued_domain_credential = domain_credential_issuer.issue_domain_credential_certificate(
        public_key=credential_request
    )

    cmp_device_with_onboarding.update({'domain_credential': issued_domain_credential})
    return cmp_device_with_onboarding


@pytest.fixture
def tls_client_request_with_client_cert_header(
    domain_credential_instance: CertificateModel, rsa_private_key: rsa.RSAPrivateKey
) -> tuple[HttpRequest, str, str, str]:
    """Fixture to create an HttpRequest for a tls_client certificate request.

    Includes the client certificate in the 'HTTP_SSL_CLIENT_CERT' header for authentication.
    """
    domain = domain_credential_instance.credential.domain

    if domain is None:
        msg = 'The associated domain for the domain credential cannot be None'
        raise ValueError(msg)

    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COMMON_NAME, 'TLS Client Certificate'),
            ]
        )
    )
    csr = csr_builder.sign(private_key=rsa_private_key, algorithm=hashes.SHA256())

    domain_str = domain.unique_name
    operation_str = 'simpleenroll'
    protocol_str = 'est'
    cert_profile_str = 'tls_client'

    domaincredential_pem = domain_credential_instance.credential.certificate.cert_pem

    request_factory = RequestFactory()
    request = request_factory.post(
        path=f'/.well-known/{protocol_str}/{domain_str}/{cert_profile_str}/{operation_str}',
        data=csr.public_bytes(serialization.Encoding.DER),
        content_type='application/pkcs10',
        HTTP_SSL_CLIENT_CERT=domaincredential_pem,
    )

    return request, domain_str, operation_str, protocol_str


class CSRFixture:
    """Helper class to provide CSR in different formats."""

    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, 'Test Device'),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Test Organization'),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Test Unit'),
                    x509.NameAttribute(NameOID.COUNTRY_NAME, 'DE'),
                ]
            )
        )

        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName('test.example.com'),
                ]
            ),
            critical=False,
        )

        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )

        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        self.csr = builder.sign(self.private_key, hashes.SHA256())

    def get_pem(self) -> bytes:
        """Return the CSR in PEM format."""
        return self.csr.public_bytes(serialization.Encoding.PEM)

    def get_der(self) -> bytes:
        """Return the CSR in DER format."""
        return self.csr.public_bytes(serialization.Encoding.DER)

    def get_base64_der(self) -> bytes:
        """Return the CSR as Base64-encoded DER."""
        der_bytes = self.get_der()
        return base64.b64encode(der_bytes)

    def get_base64_der_with_newlines(self) -> bytes:
        """Return the CSR as Base64-encoded DER with newlines (common format)."""
        der_bytes = self.get_der()
        base64_bytes = base64.b64encode(der_bytes)
        # Add newlines every 64 characters to mimic common base64 formatting
        lines = [base64_bytes[i : i + 64] for i in range(0, len(base64_bytes), 64)]
        return b'\n'.join(lines) + b'\n'

    def get_cryptography_object(self) -> x509.CertificateSigningRequest:
        """Return the underlying cryptography CSR object."""
        return self.csr


@pytest.fixture
def test_csr_fixture() -> CSRFixture:
    """Create a test CSR fixture that can be retrieved in multiple formats."""
    return CSRFixture()
