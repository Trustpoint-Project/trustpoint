"""Tests for PKI services."""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, UTC
from django.core.exceptions import ValidationError

from pki.models.certificate import CertificateModel
from pki.models.truststore import TruststoreModel
from pki.services.certificate import CertificateService
from pki.services.truststore import TruststoreService


@pytest.mark.django_db
class TestCertificateService:
    """Test the CertificateService class."""

    def test_init_without_user_id(self):
        """Test initializing CertificateService without user_id."""
        service = CertificateService()
        assert service.user_id is None

    def test_init_with_user_id(self):
        """Test initializing CertificateService with user_id."""
        service = CertificateService(user_id='test_user_123')
        assert service.user_id == 'test_user_123'

    def test_get_certificates_empty(self):
        """Test get_certificates returns empty queryset when no certificates exist."""
        service = CertificateService()
        certificates = service.get_certificates()
        assert certificates.count() == 0

    def test_get_certificates_ordering(self):
        """Test that get_certificates returns certificates ordered by created_at descending."""
        service = CertificateService()
        
        # Create certificates with different timestamps
        # Note: We can't directly manipulate created_at, so we'll check the queryset behavior
        queryset = service.get_certificates()
        assert queryset.query.order_by == ('-created_at',)

    def test_get_certificates_returns_queryset(self):
        """Test that get_certificates returns a QuerySet."""
        service = CertificateService()
        from django.db.models.query import QuerySet
        certificates = service.get_certificates()
        assert isinstance(certificates, QuerySet)


@pytest.mark.django_db
class TestTruststoreService:
    """Test the TruststoreService class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.service = TruststoreService()

    def create_test_certificate_pem(self) -> bytes:
        """Create a test certificate in PEM format."""
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create a self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'test-ca.example.com'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, 'Test Org'),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(UTC)
        ).not_valid_after(
            datetime.now(UTC) + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).sign(private_key, hashes.SHA256())
        
        # Return PEM-encoded certificate
        return cert.public_bytes(serialization.Encoding.PEM)

    def test_init(self):
        """Test initializing TruststoreService."""
        service = TruststoreService()
        assert service is not None

    def test_get_all_empty(self):
        """Test get_all returns empty queryset when no truststores exist."""
        truststores = self.service.get_all()
        assert truststores.count() == 0

    def test_get_all_returns_queryset(self):
        """Test that get_all returns a QuerySet."""
        from django.db.models.query import QuerySet
        truststores = self.service.get_all()
        assert isinstance(truststores, QuerySet)

    def test_get_all_ordering(self):
        """Test that get_all returns truststores ordered by created_at descending."""
        queryset = self.service.get_all()
        assert queryset.query.order_by == ('-created_at',)

    def test_get_all_with_existing_truststore(self):
        """Test get_all returns existing truststores."""
        # Create a truststore
        TruststoreModel.objects.create(
            unique_name='test-truststore',
            intended_usage=TruststoreModel.IntendedUsage.IDEVID
        )
        
        truststores = self.service.get_all()
        assert truststores.count() == 1

    def test_create_with_invalid_cert_data(self):
        """Test create raises ValidationError with invalid certificate data."""
        with pytest.raises(ValidationError) as exc_info:
            self.service.create(
                unique_name='test-truststore',
                intended_usage='0',
                trust_store_file=b'invalid certificate data'
            )
        assert 'Unable to process the Truststore' in str(exc_info.value)

    def test_create_with_duplicate_name(self):
        """Test create raises ValidationError with duplicate unique_name."""
        # Create existing truststore
        TruststoreModel.objects.create(
            unique_name='duplicate-name',
            intended_usage=TruststoreModel.IntendedUsage.IDEVID
        )
        
        cert_pem = self.create_test_certificate_pem()
        
        with pytest.raises(ValidationError) as exc_info:
            self.service.create(
                unique_name='duplicate-name',
                intended_usage='0',
                trust_store_file=cert_pem
            )
        assert 'already exists' in str(exc_info.value)

    def test_create_with_empty_unique_name_generates_name(self):
        """Test create generates name from certificate when unique_name is empty."""
        cert_pem = self.create_test_certificate_pem()
        
        # Empty unique_name should auto-generate from certificate
        truststore = self.service.create(
            unique_name='',
            intended_usage='0',
            trust_store_file=cert_pem
        )
        
        # Name should be generated from certificate subject
        assert truststore.unique_name != ''
        assert 'test-ca.example.com' in truststore.unique_name.lower()

    def test_create_with_valid_data(self):
        """Test successful truststore creation."""
        cert_pem = self.create_test_certificate_pem()
        
        truststore = self.service.create(
            unique_name='new-truststore',
            intended_usage='0',  # IDEVID
            trust_store_file=cert_pem
        )
        
        assert truststore is not None
        assert truststore.unique_name == 'new-truststore'
        assert truststore.intended_usage == TruststoreModel.IntendedUsage.IDEVID

    def test_create_multiple_certificates_in_file(self):
        """Test create with multiple certificates in trust store file."""
        # Create two certificates
        cert1_pem = self.create_test_certificate_pem()
        cert2_pem = self.create_test_certificate_pem()
        
        # Combine them
        combined_pem = cert1_pem + cert2_pem
        
        truststore = self.service.create(
            unique_name='multi-cert-truststore',
            intended_usage='2',  # GENERIC
            trust_store_file=combined_pem
        )
        
        assert truststore is not None
        # Should have imported multiple certificates
        assert truststore.certificates.count() >= 1


class TestTruststoreServiceIntendedUsage:
    """Test TruststoreService with different intended usage values."""

    def setup_method(self):
        """Set up test fixtures."""
        self.service = TruststoreService()

    def create_test_certificate_pem(self) -> bytes:
        """Create a test certificate in PEM format."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'test.example.com'),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(UTC)
        ).not_valid_after(
            datetime.now(UTC) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())
        
        return cert.public_bytes(serialization.Encoding.PEM)

    @pytest.mark.django_db
    def test_create_with_idevid_usage(self):
        """Test create with IDEVID intended usage."""
        cert_pem = self.create_test_certificate_pem()
        
        truststore = self.service.create(
            unique_name='idevid-truststore',
            intended_usage='0',
            trust_store_file=cert_pem
        )
        
        assert truststore.intended_usage == TruststoreModel.IntendedUsage.IDEVID

    @pytest.mark.django_db
    def test_create_with_tls_usage(self):
        """Test create with TLS intended usage."""
        cert_pem = self.create_test_certificate_pem()
        
        truststore = self.service.create(
            unique_name='tls-truststore',
            intended_usage='1',
            trust_store_file=cert_pem
        )
        
        assert truststore.intended_usage == TruststoreModel.IntendedUsage.TLS

    @pytest.mark.django_db
    def test_create_with_generic_usage(self):
        """Test create with GENERIC intended usage."""
        cert_pem = self.create_test_certificate_pem()
        
        truststore = self.service.create(
            unique_name='generic-truststore',
            intended_usage='2',
            trust_store_file=cert_pem
        )
        
        assert truststore.intended_usage == TruststoreModel.IntendedUsage.GENERIC

    @pytest.mark.django_db
    def test_create_with_device_owner_id_usage(self):
        """Test create with DEVICE_OWNER_ID intended usage."""
        cert_pem = self.create_test_certificate_pem()
        
        truststore = self.service.create(
            unique_name='device-owner-truststore',
            intended_usage='3',
            trust_store_file=cert_pem
        )
        
        assert truststore.intended_usage == TruststoreModel.IntendedUsage.DEVICE_OWNER_ID
