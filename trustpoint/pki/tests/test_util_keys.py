"""Tests for pki.util.keys module."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from unittest.mock import Mock, patch

from pki.util.keys import (
    AutoGenPkiKeyAlgorithm,
    KeyGenerator,
    CryptographyUtils,
    is_supported_public_key,
)
from trustpoint_core.oid import PublicKeyInfo, PublicKeyAlgorithmOid, NamedCurve


class TestAutoGenPkiKeyAlgorithm:
    """Test AutoGenPkiKeyAlgorithm enum methods."""

    def test_to_public_key_info_rsa2048(self):
        """Test to_public_key_info for RSA2048."""
        key_algo = AutoGenPkiKeyAlgorithm.RSA2048
        key_info = key_algo.to_public_key_info()

        assert key_info.public_key_algorithm_oid == PublicKeyAlgorithmOid.RSA
        assert key_info.key_size == 2048

    def test_to_public_key_info_rsa4096(self):
        """Test to_public_key_info for RSA4096."""
        key_algo = AutoGenPkiKeyAlgorithm.RSA4096
        key_info = key_algo.to_public_key_info()

        assert key_info.public_key_algorithm_oid == PublicKeyAlgorithmOid.RSA
        assert key_info.key_size == 4096

    def test_to_public_key_info_secp256r1(self):
        """Test to_public_key_info for SECP256R1."""
        key_algo = AutoGenPkiKeyAlgorithm.SECP256R1
        key_info = key_algo.to_public_key_info()

        assert key_info.public_key_algorithm_oid == PublicKeyAlgorithmOid.ECC
        assert key_info.named_curve == NamedCurve.SECP256R1


class TestCryptographyUtils:
    """Test CryptographyUtils methods."""

    def test_get_hash_algorithm_for_rsa_key(self):
        """Test get_hash_algorithm returns SHA256 for RSA keys."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        hash_algo = CryptographyUtils.get_hash_algorithm_for_private_key(private_key)

        assert isinstance(hash_algo, hashes.SHA256)

    def test_get_hash_algorithm_for_ec_secp256r1(self):
        """Test get_hash_algorithm returns SHA256 for SECP256R1."""
        private_key = ec.generate_private_key(ec.SECP256R1())

        hash_algo = CryptographyUtils.get_hash_algorithm_for_private_key(private_key)

        assert isinstance(hash_algo, hashes.SHA256)

    def test_get_hash_algorithm_for_ec_secp384r1(self):
        """Test get_hash_algorithm returns SHA384 for SECP384R1."""
        private_key = ec.generate_private_key(ec.SECP384R1())

        hash_algo = CryptographyUtils.get_hash_algorithm_for_private_key(private_key)

        assert isinstance(hash_algo, hashes.SHA384)

    def test_get_hash_algorithm_unsupported_key_raises(self):
        """Test get_hash_algorithm raises ValueError for unsupported key types."""
        # Use DSA as an unsupported key type
        private_key = dsa.generate_private_key(key_size=1024)

        with pytest.raises(ValueError) as exc_info:
            CryptographyUtils.get_hash_algorithm_for_private_key(private_key)

        assert 'not yet specified' in str(exc_info.value)


class TestIsSupportedPublicKey:
    """Test is_supported_public_key function."""

    def test_rsa_public_key_is_supported(self):
        """Test RSA public keys are supported."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        assert is_supported_public_key(public_key) is True

    def test_ec_public_key_is_supported(self):
        """Test EC public keys are supported."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        assert is_supported_public_key(public_key) is True

    def test_dsa_public_key_is_not_supported(self):
        """Test DSA public keys are not supported."""
        private_key = dsa.generate_private_key(key_size=1024)
        public_key = private_key.public_key()

        assert is_supported_public_key(public_key) is False

    def test_random_object_is_not_supported(self):
        """Test random objects are not supported public keys."""
        assert is_supported_public_key('not a key') is False
        assert is_supported_public_key(123) is False
        assert is_supported_public_key(None) is False


@pytest.mark.django_db
class TestKeyGenerator:
    """Test KeyGenerator methods."""

    @patch('pki.util.keys.KeyPairGenerator.generate_key_pair_for_public_key_info')
    def test_generate_private_key_for_public_key_info(self, mock_generate):
        """Test generate_private_key_for_public_key_info calls KeyPairGenerator."""
        mock_key_info = Mock(spec=PublicKeyInfo)
        mock_private_key = Mock()
        mock_generate.return_value = mock_private_key

        result = KeyGenerator.generate_private_key_for_public_key_info(mock_key_info)

        assert result == mock_private_key
        mock_generate.assert_called_once_with(mock_key_info)

    @patch('pki.util.keys.PrivateKeySerializer')
    @patch('pki.util.keys.KeyPairGenerator.generate_key_pair_for_certificate')
    def test_generate_private_key_for_domain(self, mock_generate, mock_serializer_class):
        """Test generate_private_key calls KeyPairGenerator with issuing CA cert."""
        # Create mock domain with issuing CA
        mock_domain = Mock()
        mock_issuing_ca = Mock()
        mock_credential = Mock()
        mock_cert_serializer = Mock()
        mock_cert = Mock()

        mock_domain.issuing_ca = mock_issuing_ca
        mock_issuing_ca.credential = mock_credential
        mock_credential.get_certificate_serializer.return_value = mock_cert_serializer
        mock_cert_serializer.as_crypto.return_value = mock_cert

        # Create a real RSA key for the mock to return
        real_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        mock_generate.return_value = real_private_key

        result = KeyGenerator.generate_private_key(mock_domain)

        # Verify the chain of calls
        mock_credential.get_certificate_serializer.assert_called_once()
        mock_cert_serializer.as_crypto.assert_called_once()
        mock_generate.assert_called_once_with(mock_cert)
        mock_serializer_class.assert_called_once_with(real_private_key)
