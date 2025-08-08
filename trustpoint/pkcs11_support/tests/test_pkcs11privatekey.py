"""Tests for the Pkcs11PrivateKey base class."""

import pytest
from unittest.mock import MagicMock, patch, call
from abc import ABC

import pkcs11
from pkcs11 import KeyType, Mechanism, ObjectClass, Attribute
from pkcs11.exceptions import NoSuchKey, PKCS11Error
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, ec

# Import the module to test
from pkcs11_support.pkcs11_util import Pkcs11PrivateKey


# Create a concrete implementation for testing the abstract base class
class ConcretePkcs11PrivateKey(Pkcs11PrivateKey):
    """Concrete implementation of Pkcs11PrivateKey for testing."""

    def sign(self, data: bytes, padding, algorithm: hashes.HashAlgorithm) -> bytes:
        return b"mock_signature"

    def public_key(self):
        return MagicMock()

    def key_size(self) -> int:
        return 2048


@pytest.fixture
def mock_lib_path():
    """Return a mock library path for testing."""
    return "/usr/lib/softhsm/libsofthsm2.so"


@pytest.fixture
def mock_token_label():
    """Return a mock token label for testing."""
    return "TestToken"


@pytest.fixture
def mock_user_pin():
    """Return a mock user PIN for testing."""
    return "1234"


@pytest.fixture
def mock_key_label():
    """Return a mock key label for testing."""
    return "test-key"


@pytest.fixture
def mock_pkcs11_lib():
    """Create a mock PKCS#11 library."""
    with patch('pkcs11_support.pkcs11_util.lib') as mock_lib_func:
        mock_lib_instance = MagicMock()
        mock_lib_func.return_value = mock_lib_instance
        yield mock_lib_instance


@pytest.fixture
def mock_token():
    """Create a mock PKCS#11 token."""
    token = MagicMock(spec=pkcs11.Token)
    token.label = "TestToken"
    return token


@pytest.fixture
def mock_session():
    """Create a mock PKCS#11 session."""
    session = MagicMock(spec=pkcs11.Session)
    session.close = MagicMock()
    return session


@pytest.fixture
def pkcs11_private_key(mock_lib_path, mock_token_label, mock_user_pin, mock_key_label,
                       mock_pkcs11_lib, mock_token, mock_session):
    """Create a ConcretePkcs11PrivateKey instance with mocked dependencies."""
    mock_pkcs11_lib.get_token.return_value = mock_token
    mock_token.open.return_value = mock_session

    return ConcretePkcs11PrivateKey(
        lib_path=mock_lib_path,
        token_label=mock_token_label,
        user_pin=mock_user_pin,
        key_label=mock_key_label
    )


class TestPkcs11PrivateKeyInitialization:
    """Test Pkcs11PrivateKey initialization."""

    def test_initialization_with_valid_parameters(self, pkcs11_private_key, mock_pkcs11_lib,
                                                  mock_token, mock_session):
        """Test that Pkcs11PrivateKey initializes correctly with valid parameters."""
        assert pkcs11_private_key._lib == mock_pkcs11_lib
        assert pkcs11_private_key._token == mock_token
        assert pkcs11_private_key._session == mock_session
        assert pkcs11_private_key._key_label == "test-key"
        assert pkcs11_private_key._key is None

        # Verify the initialization calls
        mock_pkcs11_lib.get_token.assert_called_once_with(token_label="TestToken")
        mock_token.open.assert_called_once_with(user_pin="1234", rw=True)

    def test_digest_mechanisms_constant(self):
        """Test that DIGEST_MECHANISMS is properly defined."""
        expected_mechanisms = {
            hashes.SHA256: Mechanism.SHA256,
            hashes.SHA384: Mechanism.SHA384,
            hashes.SHA512: Mechanism.SHA512,
            hashes.SHA224: Mechanism.SHA224,
        }
        assert Pkcs11PrivateKey.DIGEST_MECHANISMS == expected_mechanisms


class TestPkcs11PrivateKeyCopyKey:
    """Test copy_key method."""

    def test_copy_key_success(self, pkcs11_private_key, mock_session):
        """Test successful key copying."""
        mock_source_key = MagicMock()
        mock_session.get_key.return_value = mock_source_key

        pkcs11_private_key.copy_key(
            source_label="source-key",
            target_label="target-key",
            key_type=KeyType.RSA,
            object_class=ObjectClass.PRIVATE_KEY
        )

        mock_session.get_key.assert_called_once_with(
            label="source-key",
            key_type=KeyType.RSA,
            object_class=ObjectClass.PRIVATE_KEY
        )
        mock_source_key.copy.assert_called_once_with(
            template={Attribute.LABEL: "target-key"}
        )

    def test_copy_key_with_custom_template(self, pkcs11_private_key, mock_session):
        """Test key copying with custom template."""
        mock_source_key = MagicMock()
        mock_session.get_key.return_value = mock_source_key

        custom_template = {Attribute.EXTRACTABLE: False}

        pkcs11_private_key.copy_key(
            source_label="source-key",
            target_label="target-key",
            key_type=KeyType.RSA,
            object_class=ObjectClass.PRIVATE_KEY,
            template=custom_template
        )

        expected_template = {
            Attribute.LABEL: "target-key",
            Attribute.EXTRACTABLE: False
        }
        mock_source_key.copy.assert_called_once_with(template=expected_template)

    def test_copy_key_source_not_found(self, pkcs11_private_key, mock_session):
        """Test error when source key is not found."""
        mock_session.get_key.side_effect = NoSuchKey()

        with pytest.raises(NoSuchKey):
            pkcs11_private_key.copy_key(
                source_label="nonexistent-key",
                target_label="target-key",
                key_type=KeyType.RSA,
                object_class=ObjectClass.PRIVATE_KEY
            )


class TestPkcs11PrivateKeyDestroyObject:
    """Test destroy_object method."""

    def test_destroy_object_success(self, pkcs11_private_key, mock_session):
        """Test successful object destruction."""
        mock_obj = MagicMock()
        mock_session.get_key.return_value = mock_obj

        pkcs11_private_key.destroy_object(
            label="test-key",
            key_type=KeyType.RSA,
            object_class=ObjectClass.PRIVATE_KEY
        )

        mock_session.get_key.assert_called_once_with(
            label="test-key",
            key_type=KeyType.RSA,
            object_class=ObjectClass.PRIVATE_KEY
        )
        mock_obj.destroy.assert_called_once()

    def test_destroy_object_not_found(self, pkcs11_private_key, mock_session):
        """Test error when object to destroy is not found."""
        mock_session.get_key.side_effect = NoSuchKey()

        with pytest.raises(ValueError, match="Object .* with label 'nonexistent-key' not found"):
            pkcs11_private_key.destroy_object(
                label="nonexistent-key",
                key_type=KeyType.RSA,
                object_class=ObjectClass.PRIVATE_KEY
            )


class TestPkcs11PrivateKeyDigestData:
    """Test digest_data method."""

    def test_digest_data_sha256(self, pkcs11_private_key, mock_session):
        """Test data digesting with SHA256."""
        test_data = b"test data to hash"
        expected_digest = b"mock_digest_result"
        mock_session.digest.return_value = expected_digest

        result = pkcs11_private_key.digest_data(test_data, hashes.SHA256())

        assert result == expected_digest
        mock_session.digest.assert_called_once_with(Mechanism.SHA256, test_data)

    def test_digest_data_sha384(self, pkcs11_private_key, mock_session):
        """Test data digesting with SHA384."""
        test_data = b"test data to hash"
        expected_digest = b"mock_digest_result"
        mock_session.digest.return_value = expected_digest

        result = pkcs11_private_key.digest_data(test_data, hashes.SHA384())

        assert result == expected_digest
        mock_session.digest.assert_called_once_with(Mechanism.SHA384, test_data)

    def test_digest_data_sha512(self, pkcs11_private_key, mock_session):
        """Test data digesting with SHA512."""
        test_data = b"test data to hash"
        expected_digest = b"mock_digest_result"
        mock_session.digest.return_value = expected_digest

        result = pkcs11_private_key.digest_data(test_data, hashes.SHA512())

        assert result == expected_digest
        mock_session.digest.assert_called_once_with(Mechanism.SHA512, test_data)

    def test_digest_data_sha224(self, pkcs11_private_key, mock_session):
        """Test data digesting with SHA224."""
        test_data = b"test data to hash"
        expected_digest = b"mock_digest_result"
        mock_session.digest.return_value = expected_digest

        result = pkcs11_private_key.digest_data(test_data, hashes.SHA224())

        assert result == expected_digest
        mock_session.digest.assert_called_once_with(Mechanism.SHA224, test_data)

    def test_digest_data_unsupported_algorithm(self, pkcs11_private_key):
        """Test error with unsupported digest algorithm."""
        test_data = b"test data to hash"

        # Create a mock unsupported algorithm
        unsupported_algo = MagicMock()
        unsupported_algo.name = "UNSUPPORTED"

        with pytest.raises(ValueError, match="Unsupported digest algorithm: UNSUPPORTED"):
            pkcs11_private_key.digest_data(test_data, unsupported_algo)


class TestPkcs11PrivateKeyKeyExists:
    """Test _key_exists method."""

    def test_key_exists_true(self, pkcs11_private_key, mock_session):
        """Test _key_exists returns True when key exists."""
        mock_key = MagicMock()
        mock_session.get_key.return_value = mock_key

        result = pkcs11_private_key._key_exists(KeyType.RSA, ObjectClass.PRIVATE_KEY)

        assert result is True
        mock_session.get_key.assert_called_once_with(
            label="test-key",
            key_type=KeyType.RSA,
            object_class=ObjectClass.PRIVATE_KEY
        )

    def test_key_exists_false(self, pkcs11_private_key, mock_session):
        """Test _key_exists returns False when key does not exist."""
        mock_session.get_key.side_effect = NoSuchKey()

        result = pkcs11_private_key._key_exists(KeyType.RSA, ObjectClass.PRIVATE_KEY)

        assert result is False
        mock_session.get_key.assert_called_once_with(
            label="test-key",
            key_type=KeyType.RSA,
            object_class=ObjectClass.PRIVATE_KEY
        )


class TestPkcs11PrivateKeyDestroyKey:
    """Test destroy_key method."""

    def test_destroy_key_success(self, pkcs11_private_key):
        """Test successful key destruction."""
        mock_key = MagicMock()
        pkcs11_private_key._key = mock_key
        pkcs11_private_key._public_key = MagicMock()

        pkcs11_private_key.destroy_key()

        mock_key.destroy.assert_called_once()
        assert pkcs11_private_key._key is None
        assert pkcs11_private_key._public_key is None

    def test_destroy_key_no_current_key(self, pkcs11_private_key):
        """Test error when trying to destroy non-existent key."""
        pkcs11_private_key._key = None

        with pytest.raises(ValueError, match="Current key does not exist"):
            pkcs11_private_key.destroy_key()

    def test_destroy_key_pkcs11_error(self, pkcs11_private_key):
        """Test error handling when PKCS11 error occurs during destruction."""
        mock_key = MagicMock()
        mock_key.destroy.side_effect = PKCS11Error("Mock PKCS11 error")
        pkcs11_private_key._key = mock_key

        with pytest.raises(RuntimeError, match="Failed to destroy key: Mock PKCS11 error"):
            pkcs11_private_key.destroy_key()

    def test_destroy_key_without_public_key_attribute(self, pkcs11_private_key):
        """Test key destruction when public key attribute doesn't exist."""
        mock_key = MagicMock()
        pkcs11_private_key._key = mock_key
        # Don't set _public_key attribute

        pkcs11_private_key.destroy_key()

        mock_key.destroy.assert_called_once()
        assert pkcs11_private_key._key is None


class TestPkcs11PrivateKeyClose:
    """Test close method."""

    def test_close_session(self, pkcs11_private_key, mock_session):
        """Test closing the session."""
        pkcs11_private_key.close()

        mock_session.close.assert_called_once()

    def test_close_no_session(self, pkcs11_private_key):
        """Test closing when no session exists."""
        pkcs11_private_key._session = None

        # Should not raise an exception
        pkcs11_private_key.close()

    def test_close_session_not_set(self, pkcs11_private_key):
        """Test closing when session attribute doesn't exist."""
        delattr(pkcs11_private_key, '_session')

        # Should not raise an exception
        pkcs11_private_key.close()


class TestPkcs11PrivateKeyContextManager:
    """Test context manager behavior."""

    def test_context_manager_enter(self, pkcs11_private_key):
        """Test context manager __enter__ method."""
        result = pkcs11_private_key.__enter__()

        assert result is pkcs11_private_key

    def test_context_manager_exit_normal(self, pkcs11_private_key, mock_session):
        """Test context manager __exit__ method with normal exit."""
        pkcs11_private_key.__exit__(None, None, None)

        mock_session.close.assert_called_once()

    def test_context_manager_exit_with_exception(self, pkcs11_private_key, mock_session):
        """Test context manager __exit__ method with exception."""
        pkcs11_private_key.__exit__(ValueError, ValueError("test error"), None)

        mock_session.close.assert_called_once()

    def test_context_manager_usage(self, pkcs11_private_key, mock_session):
        """Test using the class as a context manager."""
        with pkcs11_private_key as key:
            assert key is pkcs11_private_key

        mock_session.close.assert_called_once()


class TestPkcs11PrivateKeyAbstractMethods:
    """Test abstract methods behavior."""

    def test_cannot_instantiate_abstract_class(self):
        """Test that Pkcs11PrivateKey cannot be instantiated directly."""
        with pytest.raises(TypeError):
            Pkcs11PrivateKey("/path/to/lib", "token", "pin", "label")

    def test_concrete_implementation_required_methods(self, pkcs11_private_key):
        """Test that concrete implementation has required methods."""
        # These should not raise NotImplementedError
        result = pkcs11_private_key.sign(b"test", None, hashes.SHA256())
        assert result == b"mock_signature"

        public_key = pkcs11_private_key.public_key()
        assert public_key is not None

        key_size = pkcs11_private_key.key_size()
        assert key_size == 2048


class TestPkcs11PrivateKeyEdgeCases:
    """Test edge cases and error conditions."""

    def test_digest_with_empty_data(self, pkcs11_private_key, mock_session):
        """Test digesting empty data."""
        empty_data = b""
        expected_digest = b"empty_digest"
        mock_session.digest.return_value = expected_digest

        result = pkcs11_private_key.digest_data(empty_data, hashes.SHA256())

        assert result == expected_digest
        mock_session.digest.assert_called_once_with(Mechanism.SHA256, empty_data)

    def test_copy_key_with_empty_template(self, pkcs11_private_key, mock_session):
        """Test key copying with empty custom template."""
        mock_source_key = MagicMock()
        mock_session.get_key.return_value = mock_source_key

        pkcs11_private_key.copy_key(
            source_label="source-key",
            target_label="target-key",
            key_type=KeyType.RSA,
            object_class=ObjectClass.PRIVATE_KEY,
            template={}
        )

        expected_template = {Attribute.LABEL: "target-key"}
        mock_source_key.copy.assert_called_once_with(template=expected_template)

    def test_multiple_destroy_key_calls(self, pkcs11_private_key):
        """Test calling destroy_key multiple times."""
        mock_key = MagicMock()
        pkcs11_private_key._key = mock_key

        # First call should work
        pkcs11_private_key.destroy_key()
        mock_key.destroy.assert_called_once()

        # Second call should raise ValueError
        with pytest.raises(ValueError, match="Current key does not exist"):
            pkcs11_private_key.destroy_key()