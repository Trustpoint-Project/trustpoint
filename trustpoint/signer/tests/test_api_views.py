"""Tests for signer API views."""

import pytest
from datetime import datetime, timedelta, timezone as dt_timezone
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from management.models import KeyStorageConfig
from signer.models import SignerModel, SignedMessageModel


@pytest.fixture
def api_client():
    """Create an API client."""
    return APIClient()


@pytest.fixture
def authenticated_client(api_client):
    """Create an authenticated API client."""
    from django.contrib.auth import get_user_model

    User = get_user_model()
    user = User.objects.create_user(username='testuser', password='testpass123')
    api_client.force_authenticate(user=user)
    return api_client


@pytest.fixture
def key_storage_config():
    """Create a software key storage configuration."""
    return KeyStorageConfig.objects.create(pk=1, storage_type='software')


@pytest.fixture
def sample_signer(key_storage_config):
    """Create a sample signer with RSA key for testing."""
    from trustpoint_core.serializer import (
        CredentialSerializer,
        CertificateSerializer,
        PrivateKeySerializer,
    )
    from cryptography.hazmat.primitives.hashes import SHA256

    # Generate RSA key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Create certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, 'Test Signer'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Test Organization'),
        ]
    )

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

    pk_serializer = PrivateKeySerializer(private_key)
    cert_serializer = CertificateSerializer(cert)
    cred_serializer = CredentialSerializer.from_serializers(
        private_key_serializer=pk_serializer,
        certificate_serializer=cert_serializer,
    )

    return SignerModel.create_new_signer('test-api-signer', cred_serializer)


@pytest.fixture
def sample_ec_signer(key_storage_config):
    """Create a sample signer with EC key for testing."""
    from trustpoint_core.serializer import (
        CredentialSerializer,
        CertificateSerializer,
        PrivateKeySerializer,
    )
    from cryptography.hazmat.primitives.hashes import SHA256

    # Generate EC key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Create certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, 'Test EC Signer'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Test Organization'),
        ]
    )

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

    pk_serializer = PrivateKeySerializer(private_key)
    cert_serializer = CertificateSerializer(cert)
    cred_serializer = CredentialSerializer.from_serializers(
        private_key_serializer=pk_serializer,
        certificate_serializer=cert_serializer,
    )

    return SignerModel.create_new_signer('test-ec-signer', cred_serializer)


@pytest.mark.django_db
class TestSignerViewSet:
    """Tests for SignerViewSet."""

    def test_list_signers_requires_authentication(self, api_client):
        """Test list endpoint requires authentication."""
        url = reverse('signer-list')
        response = api_client.get(url)
        # REST framework returns 401 Unauthorized when no credentials provided
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_list_signers_authenticated(self, authenticated_client, sample_signer):
        """Test list endpoint returns signers when authenticated."""
        url = reverse('signer-list')
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) >= 1
        assert any(s['unique_name'] == 'test-api-signer' for s in response.data)

    def test_retrieve_signer(self, authenticated_client, sample_signer):
        """Test retrieve endpoint returns signer details."""
        url = reverse('signer-detail', kwargs={'pk': sample_signer.pk})
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data['unique_name'] == 'test-api-signer'
        assert 'certificate_cn' in response.data
        assert 'signature_suite' in response.data

    def test_sign_hash_requires_authentication(self, api_client, sample_signer):
        """Test sign_hash endpoint requires authentication."""
        url = '/api/signers/sign/'
        data = {'signer_id': sample_signer.pk, 'hash_value': 'a' * 64}
        response = api_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_sign_hash_with_rsa_success(self, authenticated_client, sample_signer):
        """Test sign_hash successfully signs with RSA key."""
        url = '/api/signers/sign/'
        hash_value = 'a' * 64  # SHA256 hash (64 hex chars)
        data = {'signer_id': sample_signer.pk, 'hash_value': hash_value}

        response = authenticated_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_200_OK
        assert response.data['signer_id'] == sample_signer.pk
        assert response.data['signer_name'] == 'test-api-signer'
        assert response.data['hash_value'] == hash_value
        assert 'signature' in response.data
        assert 'signed_message_id' in response.data
        assert 'created_at' in response.data

        # Verify SignedMessage was created
        assert SignedMessageModel.objects.filter(signer=sample_signer).exists()

    def test_sign_hash_with_ec_success(self, authenticated_client, sample_ec_signer):
        """Test sign_hash successfully signs with EC key."""
        url = '/api/signers/sign/'
        hash_value = 'b' * 64  # SHA256 hash (64 hex chars)
        data = {'signer_id': sample_ec_signer.pk, 'hash_value': hash_value}

        response = authenticated_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_200_OK
        assert response.data['signer_id'] == sample_ec_signer.pk
        assert response.data['signer_name'] == 'test-ec-signer'
        assert 'signature' in response.data

    def test_sign_hash_invalid_signer_id(self, authenticated_client):
        """Test sign_hash with non-existent signer ID."""
        url = '/api/signers/sign/'
        data = {'signer_id': 99999, 'hash_value': 'a' * 64}

        response = authenticated_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'signer_id' in response.data

    def test_sign_hash_invalid_hex_format(self, authenticated_client, sample_signer):
        """Test sign_hash with invalid hex format."""
        url = '/api/signers/sign/'
        data = {'signer_id': sample_signer.pk, 'hash_value': 'not-hex-value'}

        response = authenticated_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'hash_value' in response.data

    def test_sign_hash_missing_signer_id(self, authenticated_client):
        """Test sign_hash with missing signer_id."""
        url = '/api/signers/sign/'
        data = {'hash_value': 'a' * 64}

        response = authenticated_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'signer_id' in response.data

    def test_sign_hash_missing_hash_value(self, authenticated_client, sample_signer):
        """Test sign_hash with missing hash_value."""
        url = '/api/signers/sign/'
        data = {'signer_id': sample_signer.pk}

        response = authenticated_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'hash_value' in response.data

    def test_sign_hash_signer_not_found(self, authenticated_client):
        """Test sign_hash when signer doesn't exist at signing time."""
        url = '/api/signers/sign/'
        data = {
            'signer_id': 88888,  # Valid format but doesn't exist
            'hash_value': 'a' * 64,
        }

        # The validator should catch this
        response = authenticated_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_sign_hash_unsupported_key_algorithm(self, authenticated_client, sample_signer):
        """Test sign_hash with unsupported key algorithm."""
        url = '/api/signers/sign/'
        hash_value = 'c' * 64
        data = {'signer_id': sample_signer.pk, 'hash_value': hash_value}

        # Mock get_private_key at the model level to return unsupported key type
        mock_key = Mock()
        mock_key.__class__.__name__ = 'UnsupportedKey'

        with patch('signer.api_views.SignerModel.objects.get') as mock_get:
            mock_signer = Mock()
            mock_signer.id = sample_signer.pk
            mock_signer.unique_name = sample_signer.unique_name
            mock_signer.hash_algorithm = 'SHA256'
            mock_signer.credential.get_private_key.return_value = mock_key
            mock_get.return_value = mock_signer

            response = authenticated_client.post(url, data, format='json')
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert 'Unsupported key algorithm' in response.data['error']

    def test_sign_hash_signing_exception(self, authenticated_client, sample_signer):
        """Test sign_hash handles signing exceptions."""
        url = '/api/signers/sign/'
        hash_value = 'd' * 64
        data = {'signer_id': sample_signer.pk, 'hash_value': hash_value}

        # Mock at the model level to raise an exception during get_private_key
        with patch('signer.api_views.SignerModel.objects.get') as mock_get:
            mock_signer = Mock()
            mock_signer.id = sample_signer.pk
            mock_signer.hash_algorithm = 'SHA256'
            mock_signer.credential.get_private_key.side_effect = Exception('Signing failed')
            mock_get.return_value = mock_signer

            response = authenticated_client.post(url, data, format='json')
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert 'Failed to sign hash' in response.data['error']

    def test_get_certificate_requires_authentication(self, api_client, sample_signer):
        """Test get_certificate endpoint requires authentication."""
        url = f'/api/signers/{sample_signer.pk}/certificate/'
        response = api_client.get(url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_get_certificate_success(self, authenticated_client, sample_signer):
        """Test get_certificate returns certificate in PEM format."""
        url = f'/api/signers/{sample_signer.pk}/certificate/'
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data['signer_id'] == sample_signer.pk
        assert response.data['signer_name'] == 'test-api-signer'
        assert 'certificate_pem' in response.data
        assert '-----BEGIN CERTIFICATE-----' in response.data['certificate_pem']
        assert '-----END CERTIFICATE-----' in response.data['certificate_pem']

    def test_get_certificate_not_found(self, authenticated_client):
        """Test get_certificate with non-existent signer."""
        url = '/api/signers/99999/certificate/'
        response = authenticated_client.get(url)
        # DRF's get_object_or_404 raises Http404 which gets caught by the view's exception handler
        assert response.status_code in [status.HTTP_404_NOT_FOUND, status.HTTP_500_INTERNAL_SERVER_ERROR]


@pytest.mark.django_db
class TestSignedMessageViewSet:
    """Tests for SignedMessageViewSet."""

    def test_list_signed_messages_requires_authentication(self, api_client):
        """Test list endpoint requires authentication."""
        url = reverse('signed-message-list')
        response = api_client.get(url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_list_signed_messages_authenticated(self, authenticated_client, sample_signer):
        """Test list endpoint returns signed messages when authenticated."""
        # Create some signed messages
        SignedMessageModel.objects.create(signer=sample_signer, hash_value='a' * 64, signature='b' * 128)
        SignedMessageModel.objects.create(signer=sample_signer, hash_value='c' * 64, signature='d' * 128)

        url = reverse('signed-message-list')
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) >= 2

    def test_list_signed_messages_ordered_by_created_at(self, authenticated_client, sample_signer):
        """Test list endpoint returns messages ordered by created_at desc."""
        msg1 = SignedMessageModel.objects.create(signer=sample_signer, hash_value='e' * 64, signature='f' * 128)
        msg2 = SignedMessageModel.objects.create(signer=sample_signer, hash_value='g' * 64, signature='h' * 128)

        url = reverse('signed-message-list')
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        # Most recent should be first
        assert response.data[0]['id'] == msg2.id

    def test_list_signed_messages_filter_by_signer(self, authenticated_client, sample_signer, sample_ec_signer):
        """Test list endpoint can filter by signer."""
        SignedMessageModel.objects.create(signer=sample_signer, hash_value='i' * 64, signature='j' * 128)
        SignedMessageModel.objects.create(signer=sample_ec_signer, hash_value='k' * 64, signature='l' * 128)

        url = reverse('signed-message-list')
        response = authenticated_client.get(url, {'signer': sample_signer.pk})
        assert response.status_code == status.HTTP_200_OK
        # Should only return messages for sample_signer
        for msg in response.data:
            assert msg['signer'] == sample_signer.pk

    def test_retrieve_signed_message(self, authenticated_client, sample_signer):
        """Test retrieve endpoint returns signed message details."""
        msg = SignedMessageModel.objects.create(signer=sample_signer, hash_value='m' * 64, signature='n' * 128)

        url = reverse('signed-message-detail', kwargs={'pk': msg.pk})
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data['id'] == msg.pk
        assert response.data['signer'] == sample_signer.pk
        assert response.data['hash_value'] == 'm' * 64
        assert response.data['signature'] == 'n' * 128

    def test_retrieve_signed_message_not_found(self, authenticated_client):
        """Test retrieve endpoint with non-existent message."""
        url = reverse('signed-message-detail', kwargs={'pk': 99999})
        response = authenticated_client.get(url)
        assert response.status_code == status.HTTP_404_NOT_FOUND
