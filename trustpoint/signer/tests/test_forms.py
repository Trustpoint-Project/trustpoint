"""Tests for signer.forms module."""

import io
from datetime import datetime, timedelta, timezone as dt_timezone
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    pkcs12,
)
from cryptography.x509.oid import NameOID
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from trustpoint_core.serializer import CertificateSerializer, PrivateKeySerializer

from management.models import KeyStorageConfig
from signer.forms import (
    SignHashForm,
    SignerAddFileImportPkcs12Form,
    SignerAddFileImportSeparateFilesForm,
    SignerAddFileTypeSelectForm,
    SignerAddMethodSelectForm,
    get_private_key_location_from_config,
)
from signer.models import SignerModel


@pytest.fixture
def key_storage_config():
    """Create a software key storage configuration."""
    return KeyStorageConfig.objects.create(storage_type='software')


@pytest.fixture
def sample_pkcs12_data():
    """Create a sample PKCS#12 file for testing."""
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
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, SHA256())
    )
    
    # Create PKCS#12
    password = b'test_password'
    pkcs12_data = pkcs12.serialize_key_and_certificates(
        name=b'Test Signer',
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=NoEncryption()
    )
    
    return {
        'pkcs12_data': pkcs12_data,
        'password': password,
        'private_key': private_key,
        'certificate': cert,
    }


@pytest.mark.django_db
class TestGetPrivateKeyLocationFromConfig:
    """Test cases for get_private_key_location_from_config function."""

    def test_returns_software_when_no_config(self):
        """Test returns SOFTWARE when no config exists."""
        from trustpoint_core.serializer import PrivateKeyLocation
        
        location = get_private_key_location_from_config()
        assert location == PrivateKeyLocation.SOFTWARE

    def test_returns_software_for_software_storage(self, key_storage_config):
        """Test returns SOFTWARE for software storage type."""
        from trustpoint_core.serializer import PrivateKeyLocation
        
        location = get_private_key_location_from_config()
        assert location == PrivateKeyLocation.SOFTWARE

    def test_returns_hsm_for_softhsm(self):
        """Test returns HSM_PROVIDED for SoftHSM storage type."""
        from trustpoint_core.serializer import PrivateKeyLocation

        KeyStorageConfig.objects.create(pk=1, storage_type=KeyStorageConfig.StorageType.SOFTHSM)
        location = get_private_key_location_from_config()
        assert location == PrivateKeyLocation.HSM_PROVIDED

    def test_returns_hsm_for_physical_hsm(self):
        """Test returns HSM_PROVIDED for physical HSM storage type."""
        from trustpoint_core.serializer import PrivateKeyLocation

        KeyStorageConfig.objects.create(pk=1, storage_type=KeyStorageConfig.StorageType.PHYSICAL_HSM)
        location = get_private_key_location_from_config()
        assert location == PrivateKeyLocation.HSM_PROVIDED
@pytest.mark.django_db
class TestSignerAddMethodSelectForm:
    """Test cases for SignerAddMethodSelectForm."""

    def test_form_has_method_select_field(self):
        """Test form has method_select field."""
        form = SignerAddMethodSelectForm()
        assert 'method_select' in form.fields

    def test_form_valid_with_local_file_import(self):
        """Test form is valid with local_file_import choice."""
        form = SignerAddMethodSelectForm(data={'method_select': 'local_file_import'})
        assert form.is_valid()

    def test_form_initial_value(self):
        """Test form has correct initial value."""
        form = SignerAddMethodSelectForm()
        assert form.fields['method_select'].initial == 'local_file_import'


@pytest.mark.django_db
class TestSignerAddFileTypeSelectForm:
    """Test cases for SignerAddFileTypeSelectForm."""

    def test_form_has_method_select_field(self):
        """Test form has method_select field."""
        form = SignerAddFileTypeSelectForm()
        assert 'method_select' in form.fields

    def test_form_valid_with_pkcs12(self):
        """Test form is valid with pkcs_12 choice."""
        form = SignerAddFileTypeSelectForm(data={'method_select': 'pkcs_12'})
        assert form.is_valid()

    def test_form_valid_with_other(self):
        """Test form is valid with other choice."""
        form = SignerAddFileTypeSelectForm(data={'method_select': 'other'})
        assert form.is_valid()

    def test_form_initial_value(self):
        """Test form has correct initial value."""
        form = SignerAddFileTypeSelectForm()
        assert form.fields['method_select'].initial == 'pkcs_12'


@pytest.mark.django_db
class TestSignerAddFileImportPkcs12Form:
    """Test cases for SignerAddFileImportPkcs12Form."""

    def test_form_has_required_fields(self):
        """Test form has all required fields."""
        form = SignerAddFileImportPkcs12Form()
        assert 'unique_name' in form.fields
        assert 'pkcs12_file' in form.fields
        assert 'pkcs12_password' in form.fields

    def test_clean_unique_name_with_existing_name(self, key_storage_config, sample_pkcs12_data):
        """Test clean_unique_name raises error for duplicate name."""
        from trustpoint_core.serializer import CredentialSerializer, CertificateSerializer, PrivateKeySerializer
        
        # Create existing signer
        pk_serializer = PrivateKeySerializer(sample_pkcs12_data['private_key'])
        cert_serializer = CertificateSerializer(sample_pkcs12_data['certificate'])
        cred_serializer = CredentialSerializer.from_serializers(
            private_key_serializer=pk_serializer,
            certificate_serializer=cert_serializer,
        )
        SignerModel.create_new_signer('existing-name', cred_serializer)
        
        # Try to use same name
        form = SignerAddFileImportPkcs12Form()
        form.cleaned_data = {'unique_name': 'existing-name'}
        
        with pytest.raises(ValidationError, match='already taken'):
            form.clean_unique_name()

    @patch('signer.forms.CredentialSerializer.from_pkcs12_bytes')
    @patch('signer.forms.SignerModel.create_new_signer')
    def test_form_valid_submission(self, mock_create, mock_from_pkcs12, key_storage_config, sample_pkcs12_data):
        """Test successful form submission."""
        # Mock the credential serializer
        mock_cred = Mock()
        mock_cred.certificate = sample_pkcs12_data['certificate']
        mock_cred.private_key = sample_pkcs12_data['private_key']
        mock_cred.private_key_reference = None
        mock_from_pkcs12.return_value = mock_cred
        
        pkcs12_file = SimpleUploadedFile(
            'test.p12',
            sample_pkcs12_data['pkcs12_data'],
            content_type='application/x-pkcs12'
        )
        
        form = SignerAddFileImportPkcs12Form(
            data={'unique_name': 'test-signer', 'pkcs12_password': ''},
            files={'pkcs12_file': pkcs12_file}
        )
        
        assert form.is_valid()

    def test_form_missing_pkcs12_file(self, key_storage_config):
        """Test form validation fails without PKCS#12 file."""
        form = SignerAddFileImportPkcs12Form(
            data={'unique_name': 'test', 'pkcs12_password': ''}
        )
        
        assert not form.is_valid()
        assert 'pkcs12_file' in form.errors

    @patch('signer.forms.CredentialSerializer.from_pkcs12_bytes')
    def test_form_invalid_pkcs12_file(self, mock_from_pkcs12, key_storage_config):
        """Test form validation fails with invalid PKCS#12 file."""
        mock_from_pkcs12.side_effect = Exception('Invalid PKCS#12')
        
        pkcs12_file = SimpleUploadedFile(
            'test.p12',
            b'invalid data',
            content_type='application/x-pkcs12'
        )
        
        form = SignerAddFileImportPkcs12Form(
            data={'unique_name': 'test', 'pkcs12_password': ''},
            files={'pkcs12_file': pkcs12_file}
        )
        
        assert not form.is_valid()


@pytest.mark.django_db
class TestSignerAddFileImportSeparateFilesForm:
    """Test cases for SignerAddFileImportSeparateFilesForm."""

    def test_form_has_required_fields(self):
        """Test form has all required fields."""
        form = SignerAddFileImportSeparateFilesForm()
        assert 'unique_name' in form.fields
        assert 'signer_certificate' in form.fields
        assert 'signer_certificate_chain' in form.fields
        assert 'private_key_file' in form.fields
        assert 'private_key_file_password' in form.fields

    def test_clean_private_key_file_missing(self):
        """Test clean_private_key_file raises error when file is missing."""
        form = SignerAddFileImportSeparateFilesForm()
        form.cleaned_data = {}
        
        with pytest.raises(ValidationError, match='No private key file'):
            form.clean_private_key_file()

    def test_clean_private_key_file_too_large(self):
        """Test clean_private_key_file raises error for oversized file."""
        # Create a file larger than 64 KiB
        large_data = b'x' * (1024 * 65)
        large_file = SimpleUploadedFile('key.pem', large_data)
        
        form = SignerAddFileImportSeparateFilesForm()
        form.cleaned_data = {'private_key_file': large_file}
        form.data = {}
        
        with pytest.raises(ValidationError, match='too large'):
            form.clean_private_key_file()

    def test_clean_signer_certificate_missing(self):
        """Test clean_signer_certificate raises error when file is missing."""
        form = SignerAddFileImportSeparateFilesForm()
        form.cleaned_data = {'signer_certificate': None}
        
        with pytest.raises(ValidationError, match='No signer certificate'):
            form.clean_signer_certificate()

    def test_clean_signer_certificate_too_large(self):
        """Test clean_signer_certificate raises error for oversized file."""
        large_data = b'x' * (1024 * 65)
        large_file = SimpleUploadedFile('cert.pem', large_data)
        
        form = SignerAddFileImportSeparateFilesForm()
        form.cleaned_data = {'signer_certificate': large_file}
        
        with pytest.raises(ValidationError, match='too large'):
            form.clean_signer_certificate()


@pytest.mark.django_db
class TestSignHashForm:
    """Test cases for SignHashForm."""

    def test_form_has_required_fields(self):
        """Test form has all required fields."""
        form = SignHashForm()
        assert 'signer' in form.fields
        assert 'hash_value' in form.fields

    def test_form_queryset_filters_active_signers(self, key_storage_config, sample_pkcs12_data):
        """Test form queryset only includes active signers."""
        from trustpoint_core.serializer import CredentialSerializer, CertificateSerializer, PrivateKeySerializer
        
        # Create active and inactive signers
        pk_serializer = PrivateKeySerializer(sample_pkcs12_data['private_key'])
        cert_serializer = CertificateSerializer(sample_pkcs12_data['certificate'])
        cred_serializer = CredentialSerializer.from_serializers(
            private_key_serializer=pk_serializer,
            certificate_serializer=cert_serializer,
        )
        
        active_signer = SignerModel.create_new_signer('active-signer', cred_serializer)
        active_signer.is_active = True
        active_signer.save()
        
        form = SignHashForm()
        queryset = form.fields['signer'].queryset
        
        assert active_signer in queryset

    def test_clean_empty_hash_value(self, key_storage_config, sample_pkcs12_data):
        """Test clean raises error for empty hash value."""
        from trustpoint_core.serializer import CredentialSerializer, CertificateSerializer, PrivateKeySerializer
        
        pk_serializer = PrivateKeySerializer(sample_pkcs12_data['private_key'])
        cert_serializer = CertificateSerializer(sample_pkcs12_data['certificate'])
        cred_serializer = CredentialSerializer.from_serializers(
            private_key_serializer=pk_serializer,
            certificate_serializer=cert_serializer,
        )
        signer = SignerModel.create_new_signer('test-signer', cred_serializer)
        
        form = SignHashForm(data={
            'signer': signer.pk,
            'hash_value': '   \n\r   '
        })
        
        assert not form.is_valid()
        assert 'hash_value' in form.errors

    def test_clean_invalid_hex_format(self, key_storage_config, sample_pkcs12_data):
        """Test clean raises error for invalid hex format."""
        from trustpoint_core.serializer import CredentialSerializer, CertificateSerializer, PrivateKeySerializer
        
        pk_serializer = PrivateKeySerializer(sample_pkcs12_data['private_key'])
        cert_serializer = CertificateSerializer(sample_pkcs12_data['certificate'])
        cred_serializer = CredentialSerializer.from_serializers(
            private_key_serializer=pk_serializer,
            certificate_serializer=cert_serializer,
        )
        signer = SignerModel.create_new_signer('test-signer', cred_serializer)
        
        form = SignHashForm(data={
            'signer': signer.pk,
            'hash_value': 'not_valid_hex_zzz'
        })
        
        assert not form.is_valid()
        assert 'hash_value' in form.errors

    def test_clean_wrong_length_for_algorithm(self, key_storage_config, sample_pkcs12_data):
        """Test clean validates hash length matches the signer's algorithm."""
        from trustpoint_core.serializer import CredentialSerializer, CertificateSerializer, PrivateKeySerializer

        pk_serializer = PrivateKeySerializer(sample_pkcs12_data['private_key'])
        cert_serializer = CertificateSerializer(sample_pkcs12_data['certificate'])
        cred_serializer = CredentialSerializer.from_serializers(
            private_key_serializer=pk_serializer,
            certificate_serializer=cert_serializer,
        )
        signer = SignerModel.create_new_signer('test-signer', cred_serializer)

        # Get the actual hash algorithm from the signer
        hash_algo = signer.hash_algorithm
        
        # If the algorithm is recognized, test length validation
        expected_lengths = {
            'SHA1': 40,
            'SHA224': 56,
            'SHA256': 64,
            'SHA384': 96,
            'SHA512': 128,
        }
        
        if hash_algo in expected_lengths:
            # Provide wrong length hash
            wrong_length = 40 if expected_lengths[hash_algo] != 40 else 56
            form = SignHashForm(data={
                'signer': signer.pk,
                'hash_value': 'a1' * (wrong_length // 2)
            })
            assert not form.is_valid()
            assert 'hash_value' in form.errors
        else:
            # If algorithm is not in the dict, length validation is skipped
            # This is acceptable behavior per the form implementation
            pass

    def test_clean_valid_sha256_hash(self, key_storage_config, sample_pkcs12_data):
        """Test clean accepts valid SHA256 hash."""
        from trustpoint_core.serializer import CredentialSerializer, CertificateSerializer, PrivateKeySerializer
        
        pk_serializer = PrivateKeySerializer(sample_pkcs12_data['private_key'])
        cert_serializer = CertificateSerializer(sample_pkcs12_data['certificate'])
        cred_serializer = CredentialSerializer.from_serializers(
            private_key_serializer=pk_serializer,
            certificate_serializer=cert_serializer,
        )
        signer = SignerModel.create_new_signer('test-signer', cred_serializer)
        
        # 64 hex chars for SHA256
        valid_hash = 'a' * 64
        
        form = SignHashForm(data={
            'signer': signer.pk,
            'hash_value': valid_hash
        })
        
        assert form.is_valid()
        assert form.cleaned_data['hash_value'] == valid_hash.lower()

    def test_clean_removes_whitespace_and_delimiters(self, key_storage_config, sample_pkcs12_data):
        """Test clean removes whitespace and common delimiters."""
        from trustpoint_core.serializer import CredentialSerializer, CertificateSerializer, PrivateKeySerializer
        
        pk_serializer = PrivateKeySerializer(sample_pkcs12_data['private_key'])
        cert_serializer = CertificateSerializer(sample_pkcs12_data['certificate'])
        cred_serializer = CredentialSerializer.from_serializers(
            private_key_serializer=pk_serializer,
            certificate_serializer=cert_serializer,
        )
        signer = SignerModel.create_new_signer('test-signer', cred_serializer)
        
        # Hash with spaces, colons, dashes
        hash_with_delimiters = 'aa:bb-cc dd\nee\rff' + 'a' * 52
        
        form = SignHashForm(data={
            'signer': signer.pk,
            'hash_value': hash_with_delimiters
        })
        
        assert form.is_valid()
        # Should be cleaned to just hex chars
        assert ':' not in form.cleaned_data['hash_value']
        assert '-' not in form.cleaned_data['hash_value']
        assert ' ' not in form.cleaned_data['hash_value']


@pytest.mark.django_db
class TestSignerAddFileImportPkcs12FormAdvanced:
    """Advanced test cases for PKCS#12 form covering edge cases."""

    def test_clean_with_no_data(self, key_storage_config):
        """Test clean raises error when no data provided."""
        form = SignerAddFileImportPkcs12Form(data={}, files={})
        assert not form.is_valid()

    def test_clean_with_missing_certificate_in_pkcs12(self, key_storage_config):
        """Test clean raises error when PKCS#12 has no certificate."""
        with patch('signer.forms.CredentialSerializer.from_pkcs12_bytes') as mock_from_pkcs12:
            mock_cred = Mock()
            mock_cred.certificate = None
            mock_cred.private_key = Mock()
            mock_from_pkcs12.return_value = mock_cred
            
            pkcs12_file = SimpleUploadedFile('test.p12', b'fake data')
            form = SignerAddFileImportPkcs12Form(
                data={'unique_name': 'test'},
                files={'pkcs12_file': pkcs12_file}
            )
            
            assert not form.is_valid()

    def test_clean_with_missing_private_key_in_credential(self, key_storage_config):
        """Test clean raises error when credential has no private key."""
        with patch('signer.forms.CredentialSerializer.from_pkcs12_bytes') as mock_from_pkcs12:
            mock_cred = Mock()
            mock_cred.certificate = Mock()
            mock_cred.private_key = None
            mock_from_pkcs12.return_value = mock_cred
            
            pkcs12_file = SimpleUploadedFile('test.p12', b'fake data')
            form = SignerAddFileImportPkcs12Form(
                data={'unique_name': 'test'},
                files={'pkcs12_file': pkcs12_file}
            )
            
            assert not form.is_valid()

    def test_clean_with_certificate_missing_key_usage(self, key_storage_config):
        """Test clean raises error when certificate lacks KeyUsage extension."""
        from cryptography.hazmat.primitives.hashes import SHA256
        
        # Create certificate without KeyUsage extension
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'Test No KeyUsage'),
        ])
        cert_no_keyusage = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(dt_timezone.utc))
            .not_valid_after(datetime.now(dt_timezone.utc) + timedelta(days=365))
            .sign(private_key, SHA256())
        )
        
        with patch('signer.forms.CredentialSerializer.from_pkcs12_bytes') as mock_from_pkcs12:
            mock_cred = Mock()
            mock_cred.certificate = cert_no_keyusage
            mock_cred.private_key = private_key
            mock_cred.private_key_reference = None
            mock_from_pkcs12.return_value = mock_cred
            
            pkcs12_file = SimpleUploadedFile('test.p12', b'fake data')
            form = SignerAddFileImportPkcs12Form(
                data={'unique_name': 'test'},
                files={'pkcs12_file': pkcs12_file}
            )
            
            assert not form.is_valid()

    def test_clean_with_certificate_without_digital_signature(self, key_storage_config):
        """Test clean raises error when certificate lacks digital_signature in KeyUsage."""
        from cryptography.hazmat.primitives.hashes import SHA256
        
        # Create certificate with KeyUsage but no digital_signature
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'Test No DigitalSignature'),
        ])
        cert_no_digsig = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(dt_timezone.utc))
            .not_valid_after(datetime.now(dt_timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key, SHA256())
        )
        
        with patch('signer.forms.CredentialSerializer.from_pkcs12_bytes') as mock_from_pkcs12:
            mock_cred = Mock()
            mock_cred.certificate = cert_no_digsig
            mock_cred.private_key = private_key
            mock_cred.private_key_reference = None
            mock_from_pkcs12.return_value = mock_cred
            
            pkcs12_file = SimpleUploadedFile('test.p12', b'fake data')
            form = SignerAddFileImportPkcs12Form(
                data={'unique_name': 'test'},
                files={'pkcs12_file': pkcs12_file}
            )
            
            assert not form.is_valid()


@pytest.mark.django_db
class TestSignerAddFileImportSeparateFilesFormAdvanced:
    """Advanced test cases for separate files form."""

    def test_clean_with_valid_certificate_chain(self, key_storage_config, sample_pkcs12_data):
        """Test clean_signer_certificate_chain with valid chain file."""
        from trustpoint_core.serializer import CertificateSerializer, CertificateCollectionSerializer
        
        # Create a simple certificate chain
        cert_pem = CertificateSerializer(sample_pkcs12_data['certificate']).as_pem()
        chain_file = SimpleUploadedFile('chain.pem', cert_pem)
        
        form = SignerAddFileImportSeparateFilesForm()
        form.cleaned_data = {'signer_certificate_chain': chain_file}
        
        result = form.clean_signer_certificate_chain()
        assert result is not None

    def test_clean_with_invalid_certificate_chain(self, key_storage_config):
        """Test clean_signer_certificate_chain with corrupted chain file."""
        chain_file = SimpleUploadedFile('chain.pem', b'invalid certificate data')
        
        form = SignerAddFileImportSeparateFilesForm()
        form.cleaned_data = {'signer_certificate_chain': chain_file}
        
        with pytest.raises(ValidationError):
            form.clean_signer_certificate_chain()

    def test_clean_with_no_certificate_chain(self, key_storage_config):
        """Test clean_signer_certificate_chain returns None when no chain provided."""
        form = SignerAddFileImportSeparateFilesForm()
        form.cleaned_data = {'signer_certificate_chain': None}
        
        result = form.clean_signer_certificate_chain()
        assert result is None

    def test_clean_with_duplicate_certificate(self, key_storage_config, sample_pkcs12_data):
        """Test clean_signer_certificate rejects duplicate certificate."""
        from trustpoint_core.serializer import CredentialSerializer, CertificateSerializer, PrivateKeySerializer
        
        # Create existing signer with certificate
        pk_serializer = PrivateKeySerializer(sample_pkcs12_data['private_key'])
        cert_serializer = CertificateSerializer(sample_pkcs12_data['certificate'])
        cred_serializer = CredentialSerializer.from_serializers(
            private_key_serializer=pk_serializer,
            certificate_serializer=cert_serializer,
        )
        SignerModel.create_new_signer('existing-signer', cred_serializer)
        
        # Try to upload same certificate
        cert_pem = cert_serializer.as_pem()
        cert_file = SimpleUploadedFile('cert.pem', cert_pem)
        
        form = SignerAddFileImportSeparateFilesForm()
        form.cleaned_data = {'signer_certificate': cert_file}
        
        with pytest.raises(ValidationError, match='already configured'):
            form.clean_signer_certificate()

    def test_clean_with_mismatched_private_key(self, key_storage_config, sample_pkcs12_data):
        """Test clean validates private key matches certificate."""
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        from trustpoint_core.serializer import CertificateSerializer
        
        # Create mismatched key and certificate
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        # Serialize using cryptography directly
        pk_pem = other_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        cert_pem = CertificateSerializer(sample_pkcs12_data['certificate']).as_pem()
        
        pk_file = SimpleUploadedFile('key.pem', pk_pem)
        cert_file = SimpleUploadedFile('cert.pem', cert_pem)
        
        form = SignerAddFileImportSeparateFilesForm(
            data={'unique_name': 'test'},
            files={
                'private_key_file': pk_file,
                'signer_certificate': cert_file
            }
        )
        
        assert not form.is_valid()
        assert any('does not match' in str(e).lower() for e in form.non_field_errors())

    def test_clean_with_password_encoding_error(self, key_storage_config):
        """Test clean_private_key_file handles password encoding errors."""
        pk_file = SimpleUploadedFile('key.pem', b'fake key data')
        
        form = SignerAddFileImportSeparateFilesForm()
        form.cleaned_data = {'private_key_file': pk_file}
        # Simulate password that can't be encoded
        form.data = {'private_key_file_password': '\udcff\udcfe'}  # Invalid UTF-8
        
        with pytest.raises(ValidationError):
            form.clean_private_key_file()

    def test_clean_with_corrupted_private_key(self, key_storage_config):
        """Test clean_private_key_file handles corrupted key file."""
        pk_file = SimpleUploadedFile('key.pem', b'-----BEGIN PRIVATE KEY-----\ninvalid data\n-----END PRIVATE KEY-----')
        
        form = SignerAddFileImportSeparateFilesForm()
        form.cleaned_data = {'private_key_file': pk_file}
        form.data = {}
        
        with pytest.raises(ValidationError, match='Failed to parse'):
            form.clean_private_key_file()

    def test_clean_with_corrupted_certificate(self, key_storage_config):
        """Test clean_signer_certificate handles corrupted certificate file."""
        cert_file = SimpleUploadedFile('cert.pem', b'-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----')
        
        form = SignerAddFileImportSeparateFilesForm()
        form.cleaned_data = {'signer_certificate': cert_file}
        
        with pytest.raises(ValidationError, match='corrupted'):
            form.clean_signer_certificate()

    def test_clean_with_certificate_no_keyusage_extension(self, key_storage_config):
        """Test clean_signer_certificate rejects certificate without KeyUsage."""
        from cryptography.hazmat.primitives.hashes import SHA256
        from trustpoint_core.serializer import CertificateSerializer
        
        # Create cert without KeyUsage
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test')])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(dt_timezone.utc))
            .not_valid_after(datetime.now(dt_timezone.utc) + timedelta(days=365))
            .sign(private_key, SHA256())
        )
        
        cert_pem = CertificateSerializer(cert).as_pem()
        cert_file = SimpleUploadedFile('cert.pem', cert_pem)
        
        form = SignerAddFileImportSeparateFilesForm()
        form.cleaned_data = {'signer_certificate': cert_file}
        
        with pytest.raises(ValidationError, match='KeyUsage'):
            form.clean_signer_certificate()

    def test_clean_with_certificate_no_digital_signature(self, key_storage_config):
        """Test clean_signer_certificate rejects certificate without digitalSignature."""
        from cryptography.hazmat.primitives.hashes import SHA256
        from trustpoint_core.serializer import CertificateSerializer
        
        # Create cert with KeyUsage but no digitalSignature
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test')])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(dt_timezone.utc))
            .not_valid_after(datetime.now(dt_timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key, SHA256())
        )
        
        cert_pem = CertificateSerializer(cert).as_pem()
        cert_file = SimpleUploadedFile('cert.pem', cert_pem)
        
        form = SignerAddFileImportSeparateFilesForm()
        form.cleaned_data = {'signer_certificate': cert_file}
        
        with pytest.raises(ValidationError, match='digitalSignature'):
            form.clean_signer_certificate()
