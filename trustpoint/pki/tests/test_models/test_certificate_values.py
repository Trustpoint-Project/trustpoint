"""Tests that verify the correctness of certificate property values."""

# ruff: noqa: F401  # keep the unused imports for future test use
# ruff: noqa: F811  # ruff does not like pytest fixtures as arguments

from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import Certificate

from pki.models.certificate import CertificateModel

# Project imports
from pki.tests import (
    COMMON_NAME
)
from pki.tests.fixtures import self_signed_cert_basic

CertificateTuple = tuple[CertificateModel, Certificate]

# ----------------------------
# Certificate Property Tests
# ----------------------------


@pytest.mark.django_db
def test_certificate_status(self_signed_cert_basic: CertificateTuple) -> None:
    """Test if the certificate status is correctly set to OK."""
    cert_model, _ = self_signed_cert_basic
    assert cert_model.certificate_status == cert_model.CertificateStatus.OK


@pytest.mark.django_db
def test_is_self_signed(self_signed_cert_basic: CertificateTuple) -> None:
    """Test if the certificate is correctly identified as self-signed."""
    cert_model, _ = self_signed_cert_basic
    assert cert_model.is_self_signed is True


@pytest.mark.django_db
def test_common_name(self_signed_cert_basic: CertificateTuple) -> None:
    """Test if the common name is correctly saved in the certificate model."""
    cert_model, _ = self_signed_cert_basic
    assert cert_model.common_name == COMMON_NAME


@pytest.mark.django_db
def test_fingerprint(self_signed_cert_basic: CertificateTuple) -> None:
    """Test if the SHA256 fingerprint is correctly saved."""
    cert_model, cert = self_signed_cert_basic
    cert_fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
    assert cert_model.sha256_fingerprint == cert_fingerprint


@pytest.mark.django_db
def test_signature_algorithm_oid(self_signed_cert_basic: CertificateTuple) -> None:
    """Test if the signature algorithm OID is correctly stored."""
    cert_model, cert = self_signed_cert_basic
    assert cert.signature_algorithm_oid.dotted_string == cert_model.signature_algorithm_oid


@pytest.mark.django_db
def test_signature_value(self_signed_cert_basic: CertificateTuple) -> None:
    """Test if the certificate signature value is correctly saved."""
    cert_model, cert = self_signed_cert_basic
    assert cert.signature.hex().upper() == cert_model.signature_value


@pytest.mark.django_db
def test_certificate_version(self_signed_cert_basic: CertificateTuple) -> None:
    """Test if the certificate version is correctly stored."""
    cert_model, cert = self_signed_cert_basic
    assert cert_model.version == cert.version.value


@pytest.mark.django_db
def test_serial_number(self_signed_cert_basic: CertificateTuple) -> None:
    """Test if the serial number is correctly saved."""
    cert_model, cert = self_signed_cert_basic
    expected_serial = hex(cert.serial_number)[2:].upper()
    assert cert_model.serial_number == expected_serial


@pytest.mark.django_db
def test_issuer_attributes(self_signed_cert_basic: CertificateTuple) -> None:
    """Test if test_issuer attributes are correctly stored."""
    cert_model: CertificateModel
    cert_model, cert = self_signed_cert_basic
    issuer = []
    for rdn in cert.issuer.rdns:
        issuer.extend((attr.oid.dotted_string, attr.value) for attr in rdn)
    assert len(issuer) == len(cert_model.issuer.all())


@pytest.mark.django_db
def test_issuer_public_bytes(self_signed_cert_basic: CertificateTuple) -> None:
    """Test if the test_issuer public bytes are correctly saved."""
    cert_model, cert = self_signed_cert_basic
    assert cert.issuer.public_bytes().hex().upper() == cert_model.issuer_public_bytes


@pytest.mark.django_db
def test_validity_period(self_signed_cert_basic: CertificateTuple) -> None:
    """Test if the validity period is correctly stored."""
    cert_model, cert = self_signed_cert_basic
    assert cert.not_valid_before_utc == cert_model.not_valid_before
    assert cert.not_valid_after_utc == cert_model.not_valid_after


@pytest.mark.django_db
def test_subject_attributes(self_signed_cert_basic: CertificateTuple) -> None:
    """Test if subject attributes are correctly stored."""
    cert_model, cert = self_signed_cert_basic
    subject = []
    for rdn in cert.subject.rdns:
        subject.extend((attr.oid.dotted_string, attr.value) for attr in rdn)
    assert len(subject) == len(cert_model.subject.all())


@pytest.mark.django_db
def test_certificate_pem(self_signed_cert_basic: CertificateTuple) -> None:
    """Test if the PEM-encoded certificate is correctly saved."""
    cert_model, cert = self_signed_cert_basic
    assert cert.public_bytes(encoding=serialization.Encoding.PEM).decode() == cert_model.cert_pem


@pytest.mark.django_db
def test_public_key_pem(self_signed_cert_basic: CertificateTuple) -> None:
    """Test if the PEM-encoded public key is correctly saved."""
    cert_model, cert = self_signed_cert_basic
    assert (
        cert.public_key()
        .public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
        == cert_model.public_key_pem
    )


@pytest.mark.django_db
def test_subject_public_bytes(self_signed_cert_basic: CertificateTuple) -> None:
    """Test if the subject public bytes are correctly saved."""
    cert_model, cert = self_signed_cert_basic
    assert cert.subject.public_bytes().hex().upper() == cert_model.subject_public_bytes


ONE_MINUTE = 60


@pytest.mark.django_db
def test_created_at_timestamp(self_signed_cert_basic: CertificateTuple) -> None:
    """Test if the creation timestamp is set correctly."""
    cert_model, _ = self_signed_cert_basic
    now = datetime.now(UTC)
    assert (now - cert_model.created_at).total_seconds() < ONE_MINUTE


@pytest.mark.django_db
def test_ca_attributes(self_signed_cert_basic: CertificateTuple) -> None:
    """Test if CA-related attributes are correctly stored."""
    cert_model, _ = self_signed_cert_basic
    assert cert_model.is_ca is True
    assert cert_model.is_root_ca is True
    assert cert_model.is_end_entity is False
