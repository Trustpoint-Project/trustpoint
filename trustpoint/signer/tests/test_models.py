"""Tests for signer.models module."""

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.hashes import SHA256
from django.db import IntegrityError
from trustpoint_core.serializer import CredentialSerializer, CertificateSerializer, PrivateKeySerializer

from management.models import KeyStorageConfig
from pki.models.credential import CredentialModel
from signer.models import SignedMessageModel, SignerModel


@pytest.fixture
def key_storage_config():
    """Create a software key storage configuration."""
    return KeyStorageConfig.objects.create(storage_type='software')


@pytest.fixture
def sample_rsa_credential_serializer(key_storage_config):
    """Create a sample RSA credential serializer for testing."""
    from datetime import datetime, timedelta, timezone as dt_timezone
    
    # Generate RSA key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # Create certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Test Signer'),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, 'Test Organization'),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(dt_timezone.utc))
        .not_valid_after(datetime.now(dt_timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, SHA256())
    )
    
    # Create credential serializer using from_serializers
    pk_serializer = PrivateKeySerializer(private_key)
    cert_serializer = CertificateSerializer(cert)
    
    return CredentialSerializer.from_serializers(
        private_key_serializer=pk_serializer,
        certificate_serializer=cert_serializer,
    )


@pytest.fixture
def sample_ec_credential_serializer(key_storage_config):
    """Create a sample EC credential serializer for testing."""
    from datetime import datetime, timedelta, timezone as dt_timezone
    
    # Generate EC key
    private_key = ec.generate_private_key(ec.SECP256R1())
    
    # Create certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Test EC Signer'),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, 'Test Organization'),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(dt_timezone.utc))
        .not_valid_after(datetime.now(dt_timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, SHA256())
    )
    
    # Create credential serializer using from_serializers
    pk_serializer = PrivateKeySerializer(private_key)
    cert_serializer = CertificateSerializer(cert)
    
    return CredentialSerializer.from_serializers(
        private_key_serializer=pk_serializer,
        certificate_serializer=cert_serializer,
    )


@pytest.mark.django_db
class TestSignerModel:
    """Test cases for SignerModel."""

    def test_create_signer_model(self, sample_rsa_credential_serializer):
        """Test creating a SignerModel instance."""
        credential = CredentialModel.save_credential_serializer(
            credential_serializer=sample_rsa_credential_serializer,
            credential_type=CredentialModel.CredentialTypeChoice.SIGNER,
        )
        
        signer = SignerModel.objects.create(
            unique_name='test-signer',
            credential=credential,
            is_active=True,
        )
        
        assert signer.unique_name == 'test-signer'
        assert signer.credential == credential
        assert signer.is_active is True
        assert signer.created_at is not None
        assert signer.updated_at is not None

    def test_signer_str_representation(self, sample_rsa_credential_serializer):
        """Test __str__ method returns unique name."""
        credential = CredentialModel.save_credential_serializer(
            credential_serializer=sample_rsa_credential_serializer,
            credential_type=CredentialModel.CredentialTypeChoice.SIGNER,
        )
        
        signer = SignerModel.objects.create(
            unique_name='my-test-signer',
            credential=credential,
        )
        
        assert str(signer) == 'my-test-signer'

    def test_signer_unique_name_constraint(self, sample_rsa_credential_serializer, sample_ec_credential_serializer):
        """Test that unique_name must be unique."""
        credential1 = CredentialModel.save_credential_serializer(
            credential_serializer=sample_rsa_credential_serializer,
            credential_type=CredentialModel.CredentialTypeChoice.SIGNER,
        )
        
        SignerModel.objects.create(
            unique_name='duplicate-name',
            credential=credential1,
        )
        
        # Try to create another signer with same unique_name (using different credential)
        credential2 = CredentialModel.save_credential_serializer(
            credential_serializer=sample_ec_credential_serializer,
            credential_type=CredentialModel.CredentialTypeChoice.SIGNER,
        )
        
        with pytest.raises(IntegrityError):
            SignerModel.objects.create(
                unique_name='duplicate-name',
                credential=credential2,
            )

    def test_common_name_property(self, sample_rsa_credential_serializer):
        """Test common_name property returns certificate common name."""
        credential = CredentialModel.save_credential_serializer(
            credential_serializer=sample_rsa_credential_serializer,
            credential_type=CredentialModel.CredentialTypeChoice.SIGNER,
        )
        
        signer = SignerModel.objects.create(
            unique_name='test-signer',
            credential=credential,
        )
        
        assert signer.common_name == 'Test Signer'

    def test_signature_suite_property(self, sample_rsa_credential_serializer):
        """Test signature_suite property."""
        credential = CredentialModel.save_credential_serializer(
            credential_serializer=sample_rsa_credential_serializer,
            credential_type=CredentialModel.CredentialTypeChoice.SIGNER,
        )
        
        signer = SignerModel.objects.create(
            unique_name='test-signer',
            credential=credential,
        )
        
        signature_suite = signer.signature_suite
        assert signature_suite is not None

    def test_public_key_info_property(self, sample_rsa_credential_serializer):
        """Test public_key_info property."""
        credential = CredentialModel.save_credential_serializer(
            credential_serializer=sample_rsa_credential_serializer,
            credential_type=CredentialModel.CredentialTypeChoice.SIGNER,
        )
        
        signer = SignerModel.objects.create(
            unique_name='test-signer',
            credential=credential,
        )
        
        public_key_info = signer.public_key_info
        assert public_key_info is not None

    def test_hash_algorithm_property_with_algorithm(self, sample_rsa_credential_serializer):
        """Test hash_algorithm property returns algorithm name."""
        credential = CredentialModel.save_credential_serializer(
            credential_serializer=sample_rsa_credential_serializer,
            credential_type=CredentialModel.CredentialTypeChoice.SIGNER,
        )
        
        signer = SignerModel.objects.create(
            unique_name='test-signer',
            credential=credential,
        )
        
        hash_algorithm = signer.hash_algorithm
        assert hash_algorithm is not None
        assert isinstance(hash_algorithm, str)

    def test_hash_algorithm_property_returns_name(self, sample_rsa_credential_serializer):
        """Test hash_algorithm property returns algorithm name when available."""
        credential = CredentialModel.save_credential_serializer(
            credential_serializer=sample_rsa_credential_serializer,
            credential_type=CredentialModel.CredentialTypeChoice.SIGNER,
        )
        
        signer = SignerModel.objects.create(
            unique_name='test-signer',
            credential=credential,
        )
        
        # The hash algorithm should be extracted from the certificate signature
        hash_algorithm = signer.hash_algorithm
        assert hash_algorithm is not None
        assert isinstance(hash_algorithm, str)
        # Should return the algorithm name (e.g., 'SHA256', 'SHA384', etc.)
        assert len(hash_algorithm) > 0

    def test_create_new_signer_classmethod(self, sample_rsa_credential_serializer):
        """Test create_new_signer classmethod."""
        signer = SignerModel.create_new_signer(
            unique_name='new-signer',
            credential_serializer=sample_rsa_credential_serializer,
        )
        
        assert signer.unique_name == 'new-signer'
        assert signer.credential is not None
        assert signer.credential.credential_type == CredentialModel.CredentialTypeChoice.SIGNER
        assert signer.is_active is True
        assert signer.id is not None  # Saved to database

    def test_create_new_signer_with_ec_key(self, sample_ec_credential_serializer):
        """Test create_new_signer with EC key."""
        signer = SignerModel.create_new_signer(
            unique_name='ec-signer',
            credential_serializer=sample_ec_credential_serializer,
        )
        
        assert signer.unique_name == 'ec-signer'
        assert signer.common_name == 'Test EC Signer'

    def test_signer_is_active_default(self, sample_rsa_credential_serializer):
        """Test that is_active defaults to True."""
        signer = SignerModel.create_new_signer(
            unique_name='active-signer',
            credential_serializer=sample_rsa_credential_serializer,
        )
        
        assert signer.is_active is True

    def test_signer_can_be_deactivated(self, sample_rsa_credential_serializer):
        """Test that signer can be deactivated."""
        signer = SignerModel.create_new_signer(
            unique_name='deactivatable-signer',
            credential_serializer=sample_rsa_credential_serializer,
        )
        
        signer.is_active = False
        signer.save()
        
        signer.refresh_from_db()
        assert signer.is_active is False

    def test_signer_timestamps(self, sample_rsa_credential_serializer):
        """Test that created_at and updated_at are set correctly."""
        import time
        
        signer = SignerModel.create_new_signer(
            unique_name='timestamp-signer',
            credential_serializer=sample_rsa_credential_serializer,
        )
        
        created_at = signer.created_at
        updated_at = signer.updated_at
        
        assert created_at is not None
        assert updated_at is not None
        
        # Wait a bit and update
        time.sleep(0.1)
        signer.is_active = False
        signer.save()
        
        signer.refresh_from_db()
        assert signer.created_at == created_at  # Should not change
        assert signer.updated_at > updated_at  # Should be updated


@pytest.mark.django_db
class TestSignedMessageModel:
    """Test cases for SignedMessageModel."""

    def test_create_signed_message(self, sample_rsa_credential_serializer):
        """Test creating a SignedMessageModel instance."""
        signer = SignerModel.create_new_signer(
            unique_name='test-signer',
            credential_serializer=sample_rsa_credential_serializer,
        )
        
        signed_message = SignedMessageModel.objects.create(
            signer=signer,
            hash_value='abcd1234',
            signature='signature_data_here',
        )
        
        assert signed_message.signer == signer
        assert signed_message.hash_value == 'abcd1234'
        assert signed_message.signature == 'signature_data_here'
        assert signed_message.created_at is not None

    def test_signed_message_str_representation(self, sample_rsa_credential_serializer):
        """Test __str__ method returns formatted string."""
        signer = SignerModel.create_new_signer(
            unique_name='test-signer',
            credential_serializer=sample_rsa_credential_serializer,
        )
        
        signed_message = SignedMessageModel.objects.create(
            signer=signer,
            hash_value='hash123',
            signature='sig123',
        )
        
        str_repr = str(signed_message)
        assert 'test-signer' in str_repr
        assert 'Signature by' in str_repr
        # Check that date is in the string
        assert signed_message.created_at.strftime("%Y-%m-%d") in str_repr

    def test_signed_message_relationship(self, sample_rsa_credential_serializer):
        """Test relationship between Signer and SignedMessage."""
        signer = SignerModel.create_new_signer(
            unique_name='test-signer',
            credential_serializer=sample_rsa_credential_serializer,
        )
        
        # Create multiple signed messages
        msg1 = SignedMessageModel.objects.create(
            signer=signer,
            hash_value='hash1',
            signature='sig1',
        )
        
        msg2 = SignedMessageModel.objects.create(
            signer=signer,
            hash_value='hash2',
            signature='sig2',
        )
        
        # Test reverse relationship
        assert signer.signed_messages.count() == 2
        assert msg1 in signer.signed_messages.all()
        assert msg2 in signer.signed_messages.all()

    def test_signed_message_cascade_delete(self, sample_rsa_credential_serializer):
        """Test that signed messages are deleted when signer is deleted."""
        signer = SignerModel.create_new_signer(
            unique_name='test-signer',
            credential_serializer=sample_rsa_credential_serializer,
        )
        
        SignedMessageModel.objects.create(
            signer=signer,
            hash_value='hash1',
            signature='sig1',
        )
        
        SignedMessageModel.objects.create(
            signer=signer,
            hash_value='hash2',
            signature='sig2',
        )
        
        assert SignedMessageModel.objects.filter(signer=signer).count() == 2
        
        # Delete the signer
        signer.delete()
        
        # Signed messages should be deleted too (CASCADE)
        assert SignedMessageModel.objects.filter(signer_id=signer.id).count() == 0

    def test_signed_message_long_hash_value(self, sample_rsa_credential_serializer):
        """Test that hash_value can store up to 256 characters."""
        signer = SignerModel.create_new_signer(
            unique_name='test-signer',
            credential_serializer=sample_rsa_credential_serializer,
        )
        
        long_hash = 'a' * 256
        signed_message = SignedMessageModel.objects.create(
            signer=signer,
            hash_value=long_hash,
            signature='sig',
        )
        
        assert signed_message.hash_value == long_hash
        assert len(signed_message.hash_value) == 256

    def test_signed_message_long_signature(self, sample_rsa_credential_serializer):
        """Test that signature can store long text."""
        signer = SignerModel.create_new_signer(
            unique_name='test-signer',
            credential_serializer=sample_rsa_credential_serializer,
        )
        
        long_signature = 'x' * 10000
        signed_message = SignedMessageModel.objects.create(
            signer=signer,
            hash_value='hash',
            signature=long_signature,
        )
        
        assert signed_message.signature == long_signature
        assert len(signed_message.signature) == 10000
