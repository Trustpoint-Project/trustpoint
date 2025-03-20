import datetime
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from django.utils import timezone
from trustpoint_core import oid

from pki.models.certificate import CertificateModel, RevokedCertificateModel
from pki.models.issuing_ca import IssuingCaModel
from pki.util.x509 import CertificateGenerator

COMMON_NAME = 'Root CA'
UNIQUE_NAME = COMMON_NAME.replace(' ','_').lower()
CA_TYPE = IssuingCaModel.IssuingCaTypeChoice.LOCAL_UNPROTECTED


@pytest.fixture
def issuing_ca_instance() -> dict[str, Any]:
    cert, priv_key = CertificateGenerator.create_root_ca(cn=COMMON_NAME)
    issuing_ca = CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=cert,
        private_key=priv_key,
        chain=[],
        unique_name=UNIQUE_NAME,
        ca_type= CA_TYPE
    )
    return {
        'issuing_ca': issuing_ca,
        'cert': cert,
        'priv_key': priv_key
    }


def test_attributes_and_properties(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that the common_name property returns the certificate's common name."""
    tz = timezone.get_current_timezone()
    current_time = datetime.datetime.now(tz)
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    priv_key = issuing_ca_instance.get('priv_key')
    cert = issuing_ca_instance.get('cert')
    if not isinstance(issuing_ca, IssuingCaModel) or not isinstance(cert, x509.Certificate) or not isinstance(priv_key, RSAPrivateKey):
        msg = 'Issuig CA not created properly'
        raise TypeError(msg)
    assert issuing_ca.unique_name == UNIQUE_NAME
    assert issuing_ca.credential
    assert issuing_ca.issuing_ca_type == CA_TYPE
    assert issuing_ca.is_active
    time_difference = (current_time - issuing_ca.created_at).total_seconds()
    assert time_difference <= 20
    assert issuing_ca.common_name == COMMON_NAME
    assert issuing_ca.last_crl_issued_at is None
    assert issuing_ca.crl_pem == ''
    assert issuing_ca.signature_suite == oid.SignatureSuite.from_certificate(cert)


def test_issue_crl(issuing_ca_instance: dict[str, Any]) -> None:
    tz = timezone.get_current_timezone()
    current_time = datetime.datetime.now(tz)
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    priv_key = issuing_ca_instance.get('priv_key')
    if not isinstance(issuing_ca, IssuingCaModel) or not isinstance(priv_key, RSAPrivateKey):
        msg = 'Issuig CA not created properly'
        raise TypeError(msg)

    assert issuing_ca.issue_crl()

    crl_object = x509.load_pem_x509_crl(str.encode(issuing_ca.crl_pem), default_backend())

    assert any(COMMON_NAME in str(attr) for attr in crl_object.issuer)

    time_difference = (current_time - crl_object.last_update_utc).total_seconds()
    assert time_difference <= 20

    crl_object.is_signature_valid(priv_key.public_key())


def test_revoke_all_issued_certificates_and_crl(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that revoke_all_issued_certificates method and if crl is build correctly."""
    # Create a dummy certificate model that appears to have been issued by this CA.
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    priv_key = issuing_ca_instance.get('priv_key')
    cert = issuing_ca_instance.get('cert')
    if not isinstance(issuing_ca, IssuingCaModel) or not isinstance(cert, x509.Certificate) or not isinstance(priv_key, RSAPrivateKey):
        msg = 'Issuig CA not created properly'
        raise TypeError(msg)

    ee_cert, _ = CertificateGenerator.create_ee(
        issuer_private_key=priv_key,
        issuer_cn=COMMON_NAME,
        subject_cn='subject_cn'
    )
    CertificateModel.save_certificate(ee_cert)

    ee_cert2, _ = CertificateGenerator.create_ee(
        issuer_private_key=priv_key,
        issuer_cn=COMMON_NAME,
        subject_cn='subject_cn2'
    )
    CertificateModel.save_certificate(ee_cert2)

    issuing_ca.revoke_all_issued_certificates(reason=RevokedCertificateModel.ReasonCode.UNSPECIFIED)
    revoked = RevokedCertificateModel.objects.filter(ca=issuing_ca)

    assert revoked.exists()
    assert {qs.certificate.common_name for qs in revoked} == {'subject_cn', 'subject_cn2'}


    assert issuing_ca.issue_crl()

    crl_object = x509.load_pem_x509_crl(str.encode(issuing_ca.crl_pem), default_backend())
    revoked_serials = {r.serial_number for r in crl_object}
    assert revoked_serials == {ee_cert.serial_number, ee_cert2.serial_number}
