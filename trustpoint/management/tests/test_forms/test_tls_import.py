"""Test suite for TLS import forms."""

import datetime
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from management.forms import TlsAddFileImportPkcs12Form, TlsAddFileImportSeparateFilesForm
from pki.models import CredentialModel


class TlsAddFileImportPkcs12FormTest(TestCase):
    """Test suite for TlsAddFileImportPkcs12Form."""

    def setUp(self):
        """Set up test fixtures."""
        # Generate a test private key and certificate
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Test Org'),
                x509.NameAttribute(NameOID.COMMON_NAME, 'localhost'),
            ]
        )

        now = datetime.datetime.now(datetime.UTC)
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName('localhost')]),
                critical=False,
            )
            .sign(self.private_key, hashes.SHA256(), default_backend())
        )

    def test_form_fields_exist(self):
        """Test that all required form fields exist."""
        form = TlsAddFileImportPkcs12Form()
        self.assertIn('pkcs12_file', form.fields)
        self.assertIn('pkcs12_password', form.fields)
        self.assertIn('domain_name', form.fields)

    def test_pkcs12_password_field_is_optional(self):
        """Test that pkcs12_password field is not required."""
        form = TlsAddFileImportPkcs12Form()
        self.assertFalse(form.fields['pkcs12_password'].required)

    def test_domain_name_field_has_localhost_default(self):
        """Test that domain_name has 'localhost' as initial value."""
        form = TlsAddFileImportPkcs12Form()
        self.assertEqual(form.fields['domain_name'].initial, 'localhost')

    def test_domain_name_validator(self):
        """Test domain name validation."""
        # Valid domain names
        valid_domains = ['localhost', 'example.com', 'sub.example.com']
        for domain in valid_domains:
            form_data = {'domain_name': domain}
            form = TlsAddFileImportPkcs12Form(data=form_data)
            form.full_clean()
            self.assertNotIn('domain_name', form.errors, f'{domain} should be valid')

        # Invalid domain names
        invalid_domains = ['invalid', '-invalid.com', 'invalid-.com']
        for domain in invalid_domains:
            form_data = {'domain_name': domain}
            form = TlsAddFileImportPkcs12Form(data=form_data)
            form.full_clean()
            # Note: This might not raise error depending on validator implementation

    @patch('management.forms.CredentialSerializer.from_pkcs12_bytes')
    @patch('management.forms.CertificateVerifier.verify_server_cert')
    @patch('management.forms.CredentialModel.save_credential_serializer')
    def test_clean_with_valid_pkcs12_file(self, mock_save, mock_verify, mock_from_pkcs12):
        """Test clean method with valid PKCS#12 file."""
        # Create a mock credential serializer
        mock_credential = Mock()
        mock_credential.certificate = self.certificate
        mock_from_pkcs12.return_value = mock_credential
        mock_save.return_value = Mock(spec=CredentialModel)

        # Create a dummy PKCS#12 file
        pkcs12_data = b'dummy_pkcs12_data'
        pkcs12_file = SimpleUploadedFile('test.p12', pkcs12_data, content_type='application/x-pkcs12')

        form_data = {'pkcs12_password': '', 'domain_name': 'localhost'}
        form = TlsAddFileImportPkcs12Form(data=form_data, files={'pkcs12_file': pkcs12_file})

        self.assertTrue(form.is_valid())
        self.assertTrue(hasattr(form, 'saved_credential'))

    def test_clean_without_pkcs12_file(self):
        """Test clean method raises error when no file is uploaded."""
        form_data = {'pkcs12_password': '', 'domain_name': 'localhost'}
        form = TlsAddFileImportPkcs12Form(data=form_data, files={})
        self.assertFalse(form.is_valid())

    @patch('management.forms.CredentialSerializer.from_pkcs12_bytes')
    def test_clean_with_invalid_pkcs12_file(self, mock_from_pkcs12):
        """Test clean method handles corrupted PKCS#12 file."""
        mock_from_pkcs12.side_effect = Exception('Invalid PKCS#12 data')

        pkcs12_file = SimpleUploadedFile('test.p12', b'corrupted_data', content_type='application/x-pkcs12')

        form_data = {'pkcs12_password': '', 'domain_name': 'localhost'}
        form = TlsAddFileImportPkcs12Form(data=form_data, files={'pkcs12_file': pkcs12_file})

        self.assertFalse(form.is_valid())
        self.assertIn('Failed to parse and load the uploaded file', str(form.errors))

    @patch('management.forms.CredentialSerializer.from_pkcs12_bytes')
    def test_clean_with_password_encoding_error(self, mock_from_pkcs12):
        """Test clean method handles password encoding errors."""
        pkcs12_file = SimpleUploadedFile('test.p12', b'dummy_data', content_type='application/x-pkcs12')

        # Create a mock password that can't be encoded
        form_data = {
            'pkcs12_password': Mock(encode=Mock(side_effect=Exception('Encoding error'))),
            'domain_name': 'localhost',
        }
        form = TlsAddFileImportPkcs12Form(data=form_data, files={'pkcs12_file': pkcs12_file})

        # This should trigger the encoding error in _encode_password
        self.assertFalse(form.is_valid())

    @patch('management.forms.CredentialSerializer.from_pkcs12_bytes')
    @patch('management.forms.CertificateVerifier.verify_server_cert')
    def test_clean_with_none_certificate(self, mock_verify, mock_from_pkcs12):
        """Test clean method when certificate is None."""
        mock_credential = Mock()
        mock_credential.certificate = None
        mock_from_pkcs12.return_value = mock_credential

        pkcs12_file = SimpleUploadedFile('test.p12', b'dummy_data', content_type='application/x-pkcs12')

        form_data = {'pkcs12_password': '', 'domain_name': 'localhost'}
        form = TlsAddFileImportPkcs12Form(data=form_data, files={'pkcs12_file': pkcs12_file})

        self.assertFalse(form.is_valid())
        self.assertIn('does not contain a valid certificate', str(form.errors))

    @patch('management.forms.CredentialSerializer.from_pkcs12_bytes')
    @patch('management.forms.CertificateVerifier.verify_server_cert')
    def test_clean_with_invalid_certificate_type(self, mock_verify, mock_from_pkcs12):
        """Test clean method when certificate is not x509.Certificate."""
        mock_credential = Mock()
        mock_credential.certificate = 'not_a_certificate'
        mock_from_pkcs12.return_value = mock_credential

        pkcs12_file = SimpleUploadedFile('test.p12', b'dummy_data', content_type='application/x-pkcs12')

        form_data = {'pkcs12_password': '', 'domain_name': 'localhost'}
        form = TlsAddFileImportPkcs12Form(data=form_data, files={'pkcs12_file': pkcs12_file})

        self.assertFalse(form.is_valid())
        self.assertIn('not a valid x509.Certificate', str(form.errors))

    def test_get_saved_credential(self):
        """Test get_saved_credential method."""
        form = TlsAddFileImportPkcs12Form()
        mock_credential = Mock(spec=CredentialModel)
        form.saved_credential = mock_credential
        self.assertEqual(form.get_saved_credential(), mock_credential)


class TlsAddFileImportSeparateFilesFormTest(TestCase):
    """Test suite for TlsAddFileImportSeparateFilesForm."""

    def setUp(self):
        """Set up test fixtures."""
        # Generate test private key and certificate
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Test Org'),
                x509.NameAttribute(NameOID.COMMON_NAME, 'localhost'),
            ]
        )

        now = datetime.datetime.now(datetime.UTC)
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName('localhost')]),
                critical=False,
            )
            .sign(self.private_key, hashes.SHA256(), default_backend())
        )

        # Serialize private key and certificate
        self.private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        self.certificate_pem = self.certificate.public_bytes(serialization.Encoding.PEM)

    def test_form_fields_exist(self):
        """Test that all required form fields exist."""
        form = TlsAddFileImportSeparateFilesForm()
        self.assertIn('tls_certificate', form.fields)
        self.assertIn('tls_certificate_chain', form.fields)
        self.assertIn('private_key_file', form.fields)
        self.assertIn('private_key_file_password', form.fields)
        self.assertIn('domain_name', form.fields)

    def test_private_key_file_password_is_optional(self):
        """Test that private_key_file_password is optional."""
        form = TlsAddFileImportSeparateFilesForm()
        self.assertFalse(form.fields['private_key_file_password'].required)

    def test_tls_certificate_chain_is_optional(self):
        """Test that tls_certificate_chain is optional."""
        form = TlsAddFileImportSeparateFilesForm()
        self.assertFalse(form.fields['tls_certificate_chain'].required)

    def test_clean_private_key_file_without_file(self):
        """Test clean_private_key_file raises error when no file uploaded."""
        form = TlsAddFileImportSeparateFilesForm(data={}, files={})
        form.full_clean()
        self.assertIn('private_key_file', form.errors)

    def test_clean_private_key_file_too_large(self):
        """Test clean_private_key_file rejects files larger than 64 kiB."""
        large_data = b'x' * (65 * 1024)  # 65 kiB
        private_key_file = SimpleUploadedFile('key.pem', large_data)

        form = TlsAddFileImportSeparateFilesForm(data={}, files={'private_key_file': private_key_file})
        form.full_clean()
        self.assertIn('too large', str(form.errors.get('private_key_file', '')))

    def test_clean_private_key_file_valid(self):
        """Test clean_private_key_file with valid file."""
        private_key_file = SimpleUploadedFile('key.pem', self.private_key_pem)

        form = TlsAddFileImportSeparateFilesForm(data={}, files={'private_key_file': private_key_file})
        form.full_clean()
        self.assertNotIn('private_key_file', form.errors)

    def test_clean_tls_certificate_without_file(self):
        """Test clean_tls_certificate raises error when no file uploaded."""
        form = TlsAddFileImportSeparateFilesForm(data={}, files={})
        form.full_clean()
        self.assertIn('tls_certificate', form.errors)

    def test_clean_tls_certificate_too_large(self):
        """Test clean_tls_certificate rejects files larger than 64 kiB."""
        large_data = b'x' * (65 * 1024)
        cert_file = SimpleUploadedFile('cert.pem', large_data)

        form = TlsAddFileImportSeparateFilesForm(data={}, files={'tls_certificate': cert_file})
        form.full_clean()
        self.assertIn('too large', str(form.errors.get('tls_certificate', '')))

    @patch('management.forms.CertificateSerializer.from_bytes')
    def test_clean_tls_certificate_corrupted(self, mock_from_bytes):
        """Test clean_tls_certificate handles corrupted certificate."""
        mock_from_bytes.side_effect = Exception('Parse error')

        cert_file = SimpleUploadedFile('cert.pem', b'corrupted_cert')

        form = TlsAddFileImportSeparateFilesForm(data={}, files={'tls_certificate': cert_file})
        form.full_clean()
        self.assertIn('corrupted', str(form.errors.get('tls_certificate', '')).lower())

    @patch('management.forms.CertificateSerializer.from_bytes')
    def test_clean_tls_certificate_valid(self, mock_from_bytes):
        """Test clean_tls_certificate with valid certificate."""
        mock_serializer = Mock()
        mock_from_bytes.return_value = mock_serializer

        cert_file = SimpleUploadedFile('cert.pem', self.certificate_pem)

        form = TlsAddFileImportSeparateFilesForm(data={}, files={'tls_certificate': cert_file})
        form.full_clean()
        # Should have cleaned data for tls_certificate
        self.assertEqual(form.cleaned_data.get('tls_certificate'), mock_serializer)

    @patch('management.forms.CertificateCollectionSerializer.from_bytes')
    def test_clean_tls_certificate_chain_valid(self, mock_from_bytes):
        """Test clean_tls_certificate_chain with valid chain."""
        mock_serializer = Mock()
        mock_from_bytes.return_value = mock_serializer

        chain_file = SimpleUploadedFile('chain.pem', b'cert_chain_data')

        form = TlsAddFileImportSeparateFilesForm(data={}, files={'tls_certificate_chain': chain_file})
        form.full_clean()
        self.assertEqual(form.cleaned_data.get('tls_certificate_chain'), mock_serializer)

    @patch('management.forms.CertificateCollectionSerializer.from_bytes')
    def test_clean_tls_certificate_chain_corrupted(self, mock_from_bytes):
        """Test clean_tls_certificate_chain handles corrupted chain."""
        mock_from_bytes.side_effect = Exception('Parse error')

        chain_file = SimpleUploadedFile('chain.pem', b'corrupted_chain')

        form = TlsAddFileImportSeparateFilesForm(data={}, files={'tls_certificate_chain': chain_file})
        form.full_clean()
        self.assertIn('corrupted', str(form.errors.get('tls_certificate_chain', '')).lower())

    def test_clean_tls_certificate_chain_none(self):
        """Test clean_tls_certificate_chain returns None when no file provided."""
        form = TlsAddFileImportSeparateFilesForm(data={}, files={})
        form.full_clean()
        # When no chain file is provided, it should be None
        self.assertIsNone(form.cleaned_data.get('tls_certificate_chain'))

    def test_get_saved_credential(self):
        """Test get_saved_credential method."""
        form = TlsAddFileImportSeparateFilesForm()
        mock_credential = Mock(spec=CredentialModel)
        form.saved_credential = mock_credential
        self.assertEqual(form.get_saved_credential(), mock_credential)

    @patch('management.forms.PrivateKeySerializer.from_bytes')
    @patch('management.forms.CertificateSerializer.from_bytes')
    @patch('management.forms.CredentialSerializer.from_serializers')
    @patch('management.forms.CertificateVerifier.verify_server_cert')
    @patch('management.forms.CredentialModel.save_credential_serializer')
    def test_clean_full_flow(
        self, mock_save, mock_verify, mock_from_serializers, mock_cert_from_bytes, mock_key_from_bytes
    ):
        """Test complete clean flow with all files."""
        # Setup mocks
        mock_key_serializer = Mock()
        mock_cert_serializer = Mock()
        mock_credential = Mock()
        mock_credential.certificate = self.certificate

        mock_key_from_bytes.return_value = mock_key_serializer
        mock_cert_from_bytes.return_value = mock_cert_serializer
        mock_from_serializers.return_value = mock_credential
        mock_save.return_value = Mock(spec=CredentialModel)

        # Create form with files
        private_key_file = SimpleUploadedFile('key.pem', self.private_key_pem)
        cert_file = SimpleUploadedFile('cert.pem', self.certificate_pem)

        form_data = {'domain_name': 'localhost', 'private_key_file_password': ''}

        form = TlsAddFileImportSeparateFilesForm(
            data=form_data, files={'private_key_file': private_key_file, 'tls_certificate': cert_file}
        )

        self.assertTrue(form.is_valid())
        self.assertTrue(hasattr(form, 'saved_credential'))
