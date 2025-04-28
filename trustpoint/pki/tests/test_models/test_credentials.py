"""Test module for credential models in the PKI application."""

from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.exceptions import ValidationError
from django.utils import timezone
from trustpoint_core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    CredentialSerializer,
    PrivateKeySerializer,
)

from pki.models.certificate import CertificateModel
from pki.models.credential import (
    CertificateChainOrderModel,
    CredentialModel,
    PrimaryCredentialCertificate,
)


def create_test_certificate(
    subject_name: str = 'Test Cert', issuer_name: str = 'Test Issuer', *, is_ca: bool = False
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Create a simple test certificate.

    Args:
        subject_name: Common name for the certificate subject.
        issuer_name: Common name for the certificate issuer.
        is_ca: Whether the certificate should be a CA certificate.

    Returns:
        A tuple containing the certificate and its private key.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    subject = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, subject_name),
        ]
    )

    issuer = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, issuer_name),
        ]
    )

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.not_valid_before(timezone.now() - timedelta(days=1))
    builder = builder.not_valid_after(timezone.now() + timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)

    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )

    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )

    return certificate, private_key


def create_test_credential_serializer() -> CredentialSerializer:
    """Create a test credential serializer.

    Returns:
        A CredentialSerializer instance with test data.
    """
    cert1, priv_key1 = create_test_certificate('End Entity', 'Intermediate CA')
    cert2, _ = create_test_certificate('Intermediate CA', 'Root CA', is_ca=True)
    cert3, _ = create_test_certificate('Root CA', 'Root CA', is_ca=True)

    cert_serializer = CertificateSerializer(cert1.public_bytes(serialization.Encoding.PEM).decode())
    priv_key_serializer = PrivateKeySerializer(
        priv_key1.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
    )
    chain_serializer = CertificateCollectionSerializer(
        [
            CertificateSerializer(cert2.public_bytes(serialization.Encoding.PEM).decode()),
            CertificateSerializer(cert3.public_bytes(serialization.Encoding.PEM).decode()),
        ]
    )

    return CredentialSerializer((priv_key_serializer, cert_serializer, chain_serializer))


# Fixtures


@pytest.fixture
def test_certificate() -> CertificateModel:
    """Fixture to create and return a test certificate."""
    cert, _ = create_test_certificate()
    return CertificateModel.save_certificate(cert)


@pytest.fixture
def test_ca_certificate() -> CertificateModel:
    """Fixture to create and return a test CA certificate."""
    cert, _ = create_test_certificate(is_ca=True)
    return CertificateModel.save_certificate(cert)


@pytest.fixture
def test_credential_serializer() -> CredentialSerializer:
    """Fixture to create and return a test credential serializer."""
    return create_test_credential_serializer()


@pytest.fixture
def test_credential(test_credential_serializer: CredentialSerializer) -> CredentialModel:
    """Fixture to create and return a test credential."""
    return CredentialModel.save_credential_serializer(
        test_credential_serializer, CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL
    )


PRIMARY_CERTIFICATES_COUNT = 1
CHAIN_CERTIFICATES_COUNT = 2
TOTAL_CERTIFICATES_COUNT = PRIMARY_CERTIFICATES_COUNT + CHAIN_CERTIFICATES_COUNT


# Tests for CredentialModel


def test_credential_model_creation(test_credential_serializer: CredentialSerializer) -> None:
    """Test creating a credential model from a serializer."""
    credential = CredentialModel.save_credential_serializer(
        test_credential_serializer, CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL
    )

    assert credential is not None
    assert credential.credential_type == CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL
    assert credential.private_key != ''
    assert credential.certificate is not None

    assert credential.certificatechainordermodel_set.count() == CHAIN_CERTIFICATES_COUNT
    assert credential.certificates.count() == PRIMARY_CERTIFICATES_COUNT

    all_certificates = {credential.certificate}
    all_certificates.update(cc.certificate for cc in credential.certificatechainordermodel_set.all())
    assert len(all_certificates) == TOTAL_CERTIFICATES_COUNT


def test_credential_model_get_private_key(test_credential: CredentialModel) -> None:
    """Test getting the private key from a credential."""
    private_key = test_credential.get_private_key()
    assert private_key is not None
    assert isinstance(private_key, rsa.RSAPrivateKey)


def test_credential_model_get_certificate(test_credential: CredentialModel) -> None:
    """Test getting the certificate from a credential."""
    cert = test_credential.get_certificate()
    assert cert is not None
    assert isinstance(cert, x509.Certificate)


def test_credential_model_get_certificate_chain(test_credential: CredentialModel) -> None:
    """Test getting the certificate chain from a credential."""
    chain = test_credential.get_certificate_chain()
    assert chain is not None
    assert len(chain) == CHAIN_CERTIFICATES_COUNT
    assert all(isinstance(c, x509.Certificate) for c in chain)


def test_credential_model_get_credential_serializer(test_credential: CredentialModel) -> None:
    """Test getting a credential serializer from a credential model."""
    serializer = test_credential.get_credential_serializer()
    assert serializer is not None
    assert isinstance(serializer, CredentialSerializer)


def test_credential_model_is_valid_domain_credential(test_credential: CredentialModel) -> None:
    """Test the domain credential validation."""
    is_valid, reason = test_credential.is_valid_domain_credential()
    assert is_valid is True
    assert reason == 'Valid domain credential.'


def test_credential_model_invalid_domain_credential_status(test_credential_serializer: CredentialSerializer) -> None:
    """Test domain credential validation with expired certificate."""
    # Create an expired certificate from scratch
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Expired Cert')])
    issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Test CA')])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.not_valid_before(timezone.now() - timedelta(days=2))
    builder = builder.not_valid_after(timezone.now() - timedelta(days=1))  # Already expired
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)

    expired_cert = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )

    expired_cert_model = CertificateModel.save_certificate(expired_cert)

    credential = CredentialModel.save_credential_serializer(
        test_credential_serializer, CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL
    )
    credential.certificate = expired_cert_model
    credential.save()

    is_valid, reason = credential.is_valid_domain_credential()
    assert is_valid is False
    assert 'Invalid certificate status' in reason


def test_credential_model_invalid_domain_credential_status_expired() -> None:
    """Test domain credential validation with expired certificate."""
    # Create an expired certificate
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Expired Cert'),
        ]
    )

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.not_valid_before(timezone.now() - timedelta(days=2))
    builder = builder.not_valid_after(timezone.now() - timedelta(days=1))  # Already expired
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)

    expired_cert = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )

    ca_cert, _ = create_test_certificate('Test CA', is_ca=True)

    priv_key_serializer = PrivateKeySerializer(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
    )
    cert_serializer = CertificateSerializer(expired_cert.public_bytes(serialization.Encoding.PEM).decode())
    chain_serializer = CertificateCollectionSerializer(
        [CertificateSerializer(ca_cert.public_bytes(serialization.Encoding.PEM).decode())]
    )

    credential_serializer = CredentialSerializer((priv_key_serializer, cert_serializer, chain_serializer))

    credential = CredentialModel.save_credential_serializer(
        credential_serializer, CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL
    )

    is_valid, reason = credential.is_valid_domain_credential()
    assert is_valid is False
    assert 'Invalid certificate status' in reason


def test_credential_model_save_keyless_credential() -> None:
    """Test saving a credential without a private key."""
    cert, _ = create_test_certificate()
    chain_cert, _ = create_test_certificate(is_ca=True)

    credential = CredentialModel.save_keyless_credential(
        cert, [chain_cert], CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL
    )

    assert credential is not None
    assert credential.private_key == ''
    assert credential.certificate is not None
    assert credential.certificatechainordermodel_set.count() == 1


def test_credential_model_pre_delete_with_active_certs(test_credential: CredentialModel) -> None:
    """Test pre-delete validation with active certificates."""
    with pytest.raises(ValidationError):
        test_credential.delete()


def test_credential_model_pre_delete_ca_credential(test_ca_certificate: CertificateModel) -> None:
    """Test pre-delete for CA credentials."""
    credential = CredentialModel.objects.create(
        certificate=test_ca_certificate,
        credential_type=CredentialModel.CredentialTypeChoice.ROOT_CA,
        private_key='test-key',
    )
    PrimaryCredentialCertificate.objects.create(certificate=test_ca_certificate, credential=credential, is_primary=True)

    credential.delete()


# Tests for PrimaryCredentialCertificate


def test_primary_credential_certificate_creation(test_certificate: CertificateModel) -> None:
    """Test creating a primary credential certificate."""
    credential = CredentialModel.objects.create(
        certificate=test_certificate,
        credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL,
        private_key='test-key',
    )

    pcc = PrimaryCredentialCertificate.objects.create(
        certificate=test_certificate, credential=credential, is_primary=True
    )

    assert pcc is not None
    assert pcc.is_primary is True
    assert credential.primarycredentialcertificate_set.count() == 1


def test_primary_credential_certificate_only_one_primary(test_certificate: CertificateModel) -> None:
    """Test that only one primary certificate can exist per credential."""
    credential = CredentialModel.objects.create(
        certificate=test_certificate,
        credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL,
        private_key='test-key',
    )

    PrimaryCredentialCertificate.objects.create(certificate=test_certificate, credential=credential, is_primary=True)

    cert2, _ = create_test_certificate()
    cert2_model = CertificateModel.save_certificate(cert2)

    pcc2 = PrimaryCredentialCertificate.objects.create(certificate=cert2_model, credential=credential, is_primary=True)

    assert pcc2.is_primary is True
    assert PrimaryCredentialCertificate.objects.filter(credential=credential, is_primary=True).count() == 1


# Tests for CertificateChainOrderModel


def test_certificate_chain_order_creation(test_credential: CredentialModel) -> None:
    """Test creating a certificate chain order entry."""
    current_max = test_credential.certificatechainordermodel_set.count()

    new_cert, _ = create_test_certificate()
    new_cert_model = CertificateModel.save_certificate(new_cert)

    ccom = CertificateChainOrderModel.objects.create(
        certificate=new_cert_model, credential=test_credential, order=current_max
    )

    assert ccom is not None
    assert ccom.order == current_max
    assert test_credential.certificatechainordermodel_set.count() == current_max + 1


def test_certificate_chain_order_invalid_order(test_credential: CredentialModel) -> None:
    """Test creating a chain order entry with invalid order."""
    current_max = test_credential.certificatechainordermodel_set.count()

    new_cert, _ = create_test_certificate()
    new_cert_model = CertificateModel.save_certificate(new_cert)

    with pytest.raises(ValidationError):
        CertificateChainOrderModel.objects.create(
            certificate=new_cert_model,
            credential=test_credential,
            order=current_max + 2,  # Should be current_max
        )


def test_certificate_chain_order_delete_middle(test_credential: CredentialModel) -> None:
    """Test attempting to delete a chain order entry that's not last."""
    first_chain = test_credential.certificatechainordermodel_set.first()

    with pytest.raises(ValidationError):
        first_chain.delete()


def test_certificate_chain_order_delete_last(test_credential: CredentialModel) -> None:
    """Test deleting the last chain order entry."""
    last_chain = test_credential.certificatechainordermodel_set.last()

    last_chain.delete()

    assert not CertificateChainOrderModel.objects.filter(pk=last_chain.pk).exists()
