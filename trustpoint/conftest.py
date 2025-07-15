"""pytest configuration for the tests in the PKI app."""
import base64
from typing import Any, Tuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from django.http import HttpRequest
from django.test.client import RequestFactory

from devices.issuer import LocalTlsClientCredentialIssuer, LocalDomainCredentialIssuer
from devices.models import DeviceModel, IssuedCredentialModel, RemoteDeviceCredentialDownloadModel
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
    device = DeviceModel.objects.create(
        common_name='test-device-1',
        serial_number='TEST123456',
        domain=domain,
        onboarding_status=DeviceModel.OnboardingStatus.NO_ONBOARDING,
        onboarding_protocol=DeviceModel.OnboardingProtocol.NO_ONBOARDING,
        pki_protocol=DeviceModel.PkiProtocol.EST_PASSWORD,
    )
    domain_instance.update({'device': device})
    return domain_instance


@pytest.fixture
def est_device_without_onboarding(domain_instance: dict[str, Any]) -> dict[str, Any]:
    """Fixture to create a device using the EST protocol without onboarding."""
    domain: DomainModel = domain_instance['domain']
    device = DeviceModel.objects.create(
        common_name="est-device-no-onboarding",
        serial_number="EST123456",
        domain=domain,
        onboarding_status=DeviceModel.OnboardingStatus.NO_ONBOARDING,
        onboarding_protocol=DeviceModel.OnboardingProtocol.NO_ONBOARDING,
        pki_protocol=DeviceModel.PkiProtocol.EST_PASSWORD,
    )
    domain_instance.update({'device': device})
    return domain_instance


@pytest.fixture
def est_device_with_onboarding(domain_instance: dict[str, Any]) -> dict[str, Any]:
    """Fixture to create a device using the EST protocol with onboarding."""
    domain: DomainModel = domain_instance['domain']
    device = DeviceModel.objects.create(
        common_name="est-device-with-onboarding",
        serial_number="EST654321",
        domain=domain,
        onboarding_status=DeviceModel.OnboardingStatus.ONBOARDED,
        onboarding_protocol=DeviceModel.OnboardingProtocol.EST_PASSWORD,
        pki_protocol=DeviceModel.PkiProtocol.EST_CLIENT_CERTIFICATE,
    )
    domain_instance.update({'device': device})
    return domain_instance


@pytest.fixture
def cmp_device_without_onboarding(domain_instance: dict[str, Any]) -> dict[str, Any]:
    """Fixture to create a device using the CMP protocol without onboarding."""
    domain: DomainModel = domain_instance['domain']
    device = DeviceModel.objects.create(
        common_name="cmp-device-no-onboarding",
        serial_number="CMP123456",
        domain=domain,
        onboarding_status=DeviceModel.OnboardingStatus.NO_ONBOARDING,
        onboarding_protocol=DeviceModel.OnboardingProtocol.NO_ONBOARDING,
        pki_protocol=DeviceModel.PkiProtocol.CMP_SHARED_SECRET,
    )
    domain_instance.update({'device': device})
    return domain_instance


@pytest.fixture
def cmp_device_with_onboarding(domain_instance: dict[str, Any]) -> dict[str, Any]:
    """Fixture to create a device using the CMP protocol with onboarding."""
    domain: DomainModel = domain_instance['domain']
    device = DeviceModel.objects.create(
        common_name="cmp-device-with-onboarding",
        serial_number="CMP654321",
        domain=domain,
        onboarding_status=DeviceModel.OnboardingStatus.ONBOARDED,
        onboarding_protocol=DeviceModel.OnboardingProtocol.CMP_SHARED_SECRET,
        pki_protocol=DeviceModel.PkiProtocol.CMP_CLIENT_CERTIFICATE,
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


@pytest.fixture
def domain_credential_instance(
        est_device_with_onboarding: dict[str, Any],
        rsa_private_key: rsa.RSAPrivateKey
) -> dict[str, Any]:
    """Fixture to create a domain credential linked to an EST device."""
    device: DeviceModel = est_device_with_onboarding['device']
    domain: DomainModel = device.domain

    if domain is None:
        raise ValueError("The associated domain for the device cannot be None")

    credential_request = rsa_private_key.public_key()

    domain_credential_issuer = LocalDomainCredentialIssuer(device=device, domain=domain)
    issued_domain_credential = domain_credential_issuer.issue_domain_credential_certificate(
        public_key=credential_request)

    est_device_with_onboarding.update({'domain_credential': issued_domain_credential})
    return est_device_with_onboarding

@pytest.fixture
def tls_client_certificate_instance_est_onboarding(
        est_device_with_onboarding: dict[str, Any],
                                    rsa_private_key: rsa.RSAPrivateKey
) -> dict[str, Any]:
    """Fixture to issue a TLS client certificate for an EST device WITH onboarding."""
    device: DeviceModel = est_device_with_onboarding['device']
    domain: DomainModel = device.domain

    if domain is None:
        raise ValueError("The associated domain for the device cannot be None")

    credential_request = rsa_private_key.public_key()

    tls_client_issuer = LocalTlsClientCredentialIssuer(device=device, domain=domain)
    common_name = "Fixture TLS Client Certificate"
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
        raise ValueError("The associated domain for the device cannot be None")

    credential_request = rsa_private_key.public_key()

    tls_client_issuer = LocalTlsClientCredentialIssuer(device=device, domain=domain)
    common_name = "TLS Client Certificate for EST without Onboarding"

    issued_tls_client_certificate = tls_client_issuer.issue_tls_client_certificate(
        common_name=common_name,
        public_key=credential_request,
        validity_days=365,
    )

    est_device_without_onboarding.update({'tls_client_certificate': issued_tls_client_certificate})
    return est_device_without_onboarding


@pytest.fixture
def domain_credential_instance_for_cmp(
        cmp_device_with_onboarding: dict[str, Any],
        rsa_private_key: rsa.RSAPrivateKey
) -> dict[str, Any]:
    """Fixture to create a domain credential linked to a CMP device."""
    device: DeviceModel = cmp_device_with_onboarding['device']
    domain: DomainModel = device.domain

    if domain is None:
        raise ValueError("The associated domain for the device cannot be None")

    credential_request = rsa_private_key.public_key()

    domain_credential_issuer = LocalDomainCredentialIssuer(device=device, domain=domain)
    issued_domain_credential = domain_credential_issuer.issue_domain_credential_certificate(
        public_key=credential_request)

    cmp_device_with_onboarding.update({'domain_credential': issued_domain_credential})
    return cmp_device_with_onboarding


####

def create_simpleenroll_http_request(
    device: DeviceModel,
    rsa_private_key: rsa.RSAPrivateKey,
    certtemplate_str: str
) -> Tuple[HttpRequest, str, str, str]:
    """Helper function to create an HttpRequest object for an EST simpleenroll request."""
    domain: DomainModel = device.domain

    if domain is None:
        raise ValueError("The associated domain for the device cannot be None")

    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, device.common_name),
        ])
    )

    csr = csr_builder.sign(private_key=rsa_private_key, algorithm=hashes.SHA256())

    domain_str = domain.unique_name
    operation_str = 'simpleenroll'
    protocol_str = 'est'

    credentials = f"{device.est_username}:{device.est_password}".encode("utf-8")
    auth_header = base64.b64encode(credentials).decode("utf-8")


    request_factory = RequestFactory()
    request = request_factory.post(
        path=f"/.well-known/{protocol_str}/{domain_str}/{certtemplate_str}/{operation_str}",
        data=csr.public_bytes(serialization.Encoding.DER),
        content_type="application/pkcs10",
        HTTP_AUTHORIZATION=f"Basic {auth_header}",

    )

    return request, domain_str, operation_str, protocol_str

def est_simpleenroll_http_request_no_onboarding(
    est_device_without_onboarding: dict[str, Any],
    rsa_private_key: rsa.RSAPrivateKey
) -> Tuple[HttpRequest, str, str, str]:
    """Fixture to create an HttpRequest object for an EST simpleenroll request without onboarding."""
    device = est_device_without_onboarding['device']
    certtemplate_str = 'tls-client'
    return create_simpleenroll_http_request(device, rsa_private_key, certtemplate_str)


@pytest.fixture
def est_simpleenroll_http_request_with_onboarding(
    est_device_with_onboarding: dict[str, Any],
    rsa_private_key: rsa.RSAPrivateKey
) -> Tuple[HttpRequest, str, str, str]:
    """Fixture to create an HttpRequest object for an EST simpleenroll request with onboarding."""
    device = est_device_with_onboarding['device']
    certtemplate_str = 'domaincredential'
    return create_simpleenroll_http_request(device, rsa_private_key, certtemplate_str)


@pytest.fixture
def tls_client_request_with_client_cert_header(
    domain_credential_instance: CertificateModel,
    rsa_private_key: rsa.RSAPrivateKey
) -> Tuple[HttpRequest, str, str, str]:
    """
    Fixture to create an HttpRequest for a tls-client certificate request.
    Includes the client certificate in the 'SSL_CLIENT_CERT' header for authentication.
    """
    domain = domain_credential_instance.credential.domain

    if domain is None:
        raise ValueError("The associated domain for the domain credential cannot be None")

    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "TLS Client Certificate"),
        ])
    )
    csr = csr_builder.sign(private_key=rsa_private_key, algorithm=hashes.SHA256())

    domain_str = domain.unique_name
    operation_str = 'simpleenroll'
    protocol_str = 'est'
    certtemplate_str = 'tls-client'

    domaincredential_pem = domain_credential_instance.credential.certificate.cert_pem

    request_factory = RequestFactory()
    request = request_factory.post(
        path=f"/.well-known/{protocol_str}/{domain_str}/{certtemplate_str}/{operation_str}",
        data=csr.public_bytes(serialization.Encoding.DER),
        content_type="application/pkcs10",
        HTTP_SSL_CLIENT_CERT=domaincredential_pem,
    )

    return request, domain_str, operation_str, protocol_str



