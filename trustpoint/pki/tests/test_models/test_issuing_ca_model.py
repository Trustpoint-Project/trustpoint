"""Tests for the CaModel class."""

import datetime
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from django.db.models import ProtectedError
from django.utils import timezone
from trustpoint_core import oid

from pki.models.certificate import CertificateModel, RevokedCertificateModel
from pki.models.truststore import TruststoreModel, TruststoreOrderModel
from pki.models import CaModel
from pki.util.x509 import CertificateGenerator

COMMON_NAME = 'Root CA'
UNIQUE_NAME = COMMON_NAME.replace(' ', '_').lower()
CA_TYPE = CaModel.CaTypeChoice.LOCAL_UNPROTECTED


def test_attributes_and_properties(issuing_ca_instance: dict[str, Any]) -> None:
    """Test that the common_name property returns the certificate's common name."""
    tz = timezone.get_current_timezone()
    current_time = datetime.datetime.now(tz)
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    priv_key = issuing_ca_instance.get('priv_key')
    cert = issuing_ca_instance.get('cert')
    if (
        not isinstance(issuing_ca, CaModel)
        or not isinstance(cert, x509.Certificate)
        or not isinstance(priv_key, RSAPrivateKey)
    ):
        msg = 'Issuig CA not created properly'
        raise TypeError(msg)
    assert issuing_ca.unique_name == UNIQUE_NAME
    assert issuing_ca.credential
    assert issuing_ca.ca_type == CA_TYPE
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
    if not isinstance(issuing_ca, CaModel) or not isinstance(priv_key, RSAPrivateKey):
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
    if (
        not isinstance(issuing_ca, CaModel)
        or not isinstance(cert, x509.Certificate)
        or not isinstance(priv_key, RSAPrivateKey)
    ):
        msg = 'Issuing CA not created properly'
        raise TypeError(msg)

    ee_cert, _ = CertificateGenerator.create_ee(
        issuer_private_key=priv_key, issuer_cn=COMMON_NAME, subject_name='subject_cn'
    )
    CertificateModel.save_certificate(ee_cert)

    ee_cert2, _ = CertificateGenerator.create_ee(
        issuer_private_key=priv_key, issuer_cn=COMMON_NAME, subject_name='subject_cn2'
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


def test_issuing_ca_delete(issuing_ca_instance: dict[str, Any], domain_instance: dict[str, Any]) -> None:
    """Tests that the issuing CA can be deleted only if it has no associated domains."""
    issuing_ca = issuing_ca_instance.get('issuing_ca')
    issuing_ca_id = issuing_ca.id
    domain = domain_instance.get('domain')
    with pytest.raises(ProtectedError):
        issuing_ca.delete()
    domain.delete()
    issuing_ca.delete()
    with pytest.raises(CaModel.DoesNotExist):
        CaModel.objects.get(id=issuing_ca_id)


@pytest.mark.django_db
def test_chain_truststore_creation_on_new_issuing_ca() -> None:
    """Test that a chain truststore is automatically created when creating a new issuing CA."""
    from trustpoint_core.serializer import CredentialSerializer
    from management.models import KeyStorageConfig

    # Ensure crypto storage config exists
    KeyStorageConfig.get_or_create_default()

    # Create a root CA first
    root_cert, root_priv_key = CertificateGenerator.create_root_ca(cn='Root CA')
    root_ca = CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=root_cert,
        private_key=root_priv_key,
        chain=[],
        unique_name='root_ca',
        ca_type=CaModel.CaTypeChoice.AUTOGEN_ROOT
    )

    # Create an intermediate CA that should get a chain truststore
    int_cert, int_priv_key = CertificateGenerator.create_issuing_ca(
        issuer_private_key=root_priv_key,
        issuer_cn='Root CA',
        subject_cn='Intermediate CA'
    )

    credential_serializer = CredentialSerializer(
        certificate=int_cert,
        private_key=int_priv_key,
        additional_certificates=[root_cert]
    )

    # Create the intermediate CA - this should automatically create a chain truststore
    intermediate_ca = CaModel.create_new_issuing_ca(
        credential_serializer=credential_serializer,
        ca_type=CaModel.CaTypeChoice.AUTOGEN,
        unique_name='intermediate_ca',
        parent_ca=root_ca
    )

    # Check that the chain truststore was created
    assert intermediate_ca.chain_truststore is not None
    truststore = intermediate_ca.chain_truststore

    # Check truststore properties
    assert truststore.unique_name == 'intermediate_ca_chain'
    assert truststore.intended_usage == TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN

    # Check that the truststore contains the full chain (root -> intermediate)
    certificates = truststore.truststoreordermodel_set.order_by('order')
    assert certificates.count() == 2

    # First certificate should be root CA
    assert certificates[0].certificate.common_name == 'Root CA'
    # Second certificate should be intermediate CA
    assert certificates[1].certificate.common_name == 'Intermediate CA'


@pytest.mark.django_db
def test_chain_truststore_single_ca() -> None:
    """Test that a chain truststore is created even for a single root CA."""
    from trustpoint_core.serializer import CredentialSerializer
    from management.models import KeyStorageConfig

    # Ensure crypto storage config exists
    KeyStorageConfig.get_or_create_default()

    # Create a root CA
    root_cert, root_priv_key = CertificateGenerator.create_root_ca(cn='Single Root CA')
    credential_serializer = CredentialSerializer(
        certificate=root_cert,
        private_key=root_priv_key
    )

    # Create the root CA - this should create a chain truststore with just itself
    root_ca = CaModel.create_new_issuing_ca(
        credential_serializer=credential_serializer,
        ca_type=CaModel.CaTypeChoice.AUTOGEN_ROOT,
        unique_name='single_root_ca'
    )

    # Check that the chain truststore was created
    assert root_ca.chain_truststore is not None
    truststore = root_ca.chain_truststore

    # Check truststore properties
    assert truststore.unique_name == 'single_root_ca_chain'
    assert truststore.intended_usage == TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN

    # Check that the truststore contains just the root CA
    certificates = truststore.truststoreordermodel_set.order_by('order')
    assert certificates.count() == 1
    assert certificates[0].certificate.common_name == 'Single Root CA'


@pytest.mark.django_db
def test_chain_truststore_three_level_hierarchy() -> None:
    """Test that chain truststore contains all certificates in a three-level hierarchy."""
    from trustpoint_core.serializer import CredentialSerializer
    from management.models import KeyStorageConfig

    # Ensure crypto storage config exists
    KeyStorageConfig.get_or_create_default()

    # Create root CA
    root_cert, root_priv_key = CertificateGenerator.create_root_ca(cn='Root CA')
    root_ca = CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=root_cert,
        private_key=root_priv_key,
        chain=[],
        unique_name='root_ca',
        ca_type=CaModel.CaTypeChoice.AUTOGEN_ROOT
    )

    # Create intermediate CA
    int_cert, int_priv_key = CertificateGenerator.create_issuing_ca(
        issuer_private_key=root_priv_key,
        issuer_cn='Root CA',
        subject_cn='Intermediate CA'
    )
    int_ca = CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=int_cert,
        private_key=int_priv_key,
        chain=[root_cert],
        unique_name='intermediate_ca',
        ca_type=CaModel.CaTypeChoice.AUTOGEN,
        parent_ca=root_ca
    )

    # Create sub-intermediate CA
    sub_int_cert, sub_int_priv_key = CertificateGenerator.create_issuing_ca(
        issuer_private_key=int_priv_key,
        issuer_cn='Intermediate CA',
        subject_cn='Sub Intermediate CA'
    )
    
    credential_serializer = CredentialSerializer(
        certificate=sub_int_cert,
        private_key=sub_int_priv_key,
        additional_certificates=[root_cert, int_cert]
    )

    sub_int_ca = CaModel.create_new_issuing_ca(
        credential_serializer=credential_serializer,
        ca_type=CaModel.CaTypeChoice.AUTOGEN,
        unique_name='sub_intermediate_ca',
        parent_ca=int_ca
    )

    # Verify the chain truststore
    assert sub_int_ca.chain_truststore is not None
    truststore = sub_int_ca.chain_truststore

    # Check that the truststore contains all three levels
    certificates = truststore.truststoreordermodel_set.order_by('order')
    assert certificates.count() == 3

    # Verify the order: root -> intermediate -> sub-intermediate
    assert certificates[0].certificate.common_name == 'Root CA'
    assert certificates[1].certificate.common_name == 'Intermediate CA'
    assert certificates[2].certificate.common_name == 'Sub Intermediate CA'


@pytest.mark.django_db
def test_chain_truststore_ordering() -> None:
    """Test that certificates in chain truststore are ordered correctly (root to leaf)."""
    from trustpoint_core.serializer import CredentialSerializer
    from management.models import KeyStorageConfig

    KeyStorageConfig.get_or_create_default()

    # Create two-level hierarchy
    root_cert, root_priv_key = CertificateGenerator.create_root_ca(cn='Root CA')
    root_ca = CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=root_cert,
        private_key=root_priv_key,
        chain=[],
        unique_name='root_ca',
        ca_type=CaModel.CaTypeChoice.AUTOGEN_ROOT
    )

    int_cert, int_priv_key = CertificateGenerator.create_issuing_ca(
        issuer_private_key=root_priv_key,
        issuer_cn='Root CA',
        subject_cn='Intermediate CA'
    )

    credential_serializer = CredentialSerializer(
        certificate=int_cert,
        private_key=int_priv_key,
        additional_certificates=[root_cert]
    )

    intermediate_ca = CaModel.create_new_issuing_ca(
        credential_serializer=credential_serializer,
        ca_type=CaModel.CaTypeChoice.AUTOGEN,
        unique_name='intermediate_ca',
        parent_ca=root_ca
    )

    # Verify ordering
    certificates = intermediate_ca.chain_truststore.truststoreordermodel_set.order_by('order')
    
    # Check the order field values
    assert certificates[0].order == 0
    assert certificates[1].order == 1
    
    # Verify root comes before intermediate
    assert certificates[0].certificate.common_name == 'Root CA'
    assert certificates[1].certificate.common_name == 'Intermediate CA'
