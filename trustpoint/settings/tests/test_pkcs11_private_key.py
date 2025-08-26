"""Tests for PKCS#11 Pkcs11PrivateKey class."""

from typing import Any
from unittest.mock import Mock, patch

import pkcs11
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import NoSuchKey, PKCS11Error

from settings.pkcs11_util import Pkcs11PrivateKey


class MockPkcs11PrivateKey(Pkcs11PrivateKey):
    """Mock implementation of Pkcs11PrivateKey for testing."""

    def sign(self, data: bytes, *args: Any, **kwargs: Any) -> bytes:
        """Mock sign method."""
        return b'mock_signature'

    def public_key(self) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
        """Mock public_key method."""
        return Mock(spec=rsa.RSAPublicKey)

    @property
    def key_size(self) -> int:
        """Mock key_size property."""
        return 2048


class TestPkcs11PrivateKey:
    """Test cases for the Pkcs11PrivateKey abstract base class."""

    @pytest.fixture
    def mock_session(self) -> Mock:
        """Mock PKCS#11 session."""
        return Mock()

    @pytest.fixture
    def mock_token(self, mock_session: Mock) -> Mock:
        """Mock PKCS#11 token."""
        mock_token = Mock()
        mock_token.open.return_value = mock_session
        return mock_token

    @pytest.fixture
    def mock_lib(self, mock_token: Mock) -> Mock:
        """Mock PKCS#11 library."""
        mock_lib = Mock()
        mock_lib.get_token.return_value = mock_token
        return mock_lib

    @pytest.fixture
    def pkcs11_key(self, mock_session: Mock) -> MockPkcs11PrivateKey:
        """Create MockPkcs11PrivateKey instance with mocked dependencies."""
        with patch('pkcs11.lib') as mock_lib_func:
            mock_lib = Mock()
            mock_token = Mock()
            mock_token.open.return_value = mock_session
            mock_lib.get_token.return_value = mock_token
            mock_lib_func.return_value = mock_lib

            key = MockPkcs11PrivateKey('/path/to/lib.so', 'test_token', '1234', 'test_key')
            # Manually set the session to avoid accessing private members
            object.__setattr__(key, '_session', mock_session)
            return key

    def test_digest_mechanisms_mapping(self) -> None:
        """Test that DIGEST_MECHANISMS contains expected mappings."""
        expected_mechanisms = {
            hashes.SHA256: Mechanism.SHA256,
            hashes.SHA384: Mechanism.SHA384,
            hashes.SHA512: Mechanism.SHA512,
            hashes.SHA224: Mechanism.SHA224,
        }

        assert expected_mechanisms == Pkcs11PrivateKey.DIGEST_MECHANISMS

    def test_digest_data_success(self, pkcs11_key: MockPkcs11PrivateKey, mock_session: Mock) -> None:
        """Test digest_data method with successful operation."""
        mock_session.digest.return_value = b'digest_result'
        algorithm = hashes.SHA256()

        result = pkcs11_key.digest_data(b'test_data', algorithm)

        assert result == b'digest_result'
        mock_session.digest.assert_called_once_with(Mechanism.SHA256, b'test_data')

    def test_digest_data_unsupported_algorithm(self, pkcs11_key: MockPkcs11PrivateKey) -> None:
        """Test digest_data with unsupported algorithm."""
        algorithm = hashes.MD5()  # Not in DIGEST_MECHANISMS

        with pytest.raises(ValueError, match='Unsupported digest algorithm'):
            pkcs11_key.digest_data(b'test_data', algorithm)

    def test_digest_data_no_session(self) -> None:
        """Test digest_data when session is None."""
        # Create key without initializing session
        with patch('pkcs11.lib'), \
             patch.object(MockPkcs11PrivateKey, '_initialize'):
                key = MockPkcs11PrivateKey('/path/to/lib.so', 'test_token', '1234', 'test_key')
                object.__setattr__(key, '_session', None)

                algorithm = hashes.SHA256()
                with pytest.raises(RuntimeError, match='PKCS#11 session is not initialized'):
                    key.digest_data(b'test_data', algorithm)

    def test_copy_key_success(self, pkcs11_key: MockPkcs11PrivateKey, mock_session: Mock) -> None:
        """Test copy_key method with successful operation."""
        mock_source_key = Mock()
        mock_session.get_key.return_value = mock_source_key

        pkcs11_key.copy_key('source_label', 'target_label', KeyType.RSA, ObjectClass.PRIVATE_KEY)

        mock_source_key.copy.assert_called_once_with(template={Attribute.LABEL: 'target_label'})

    def test_copy_key_with_template(self, pkcs11_key: MockPkcs11PrivateKey, mock_session: Mock) -> None:
        """Test copy_key with additional template."""
        mock_source_key = Mock()
        mock_session.get_key.return_value = mock_source_key
        template = {Attribute.DECRYPT: True}

        pkcs11_key.copy_key('source_label', 'target_label', KeyType.RSA, ObjectClass.PRIVATE_KEY, template)

        expected_template = {Attribute.LABEL: 'target_label', Attribute.DECRYPT: True}
        mock_source_key.copy.assert_called_once_with(template=expected_template)

    def test_copy_key_no_session(self) -> None:
        """Test copy_key when session is None."""
        with patch('pkcs11.lib'), patch.object(MockPkcs11PrivateKey, '_initialize'):
                key = MockPkcs11PrivateKey('/path/to/lib.so', 'test_token', '1234', 'test_key')
                object.__setattr__(key, '_session', None)

                with pytest.raises(RuntimeError, match='PKCS#11 session is not initialized'):
                    key.copy_key('source_label', 'target_label', KeyType.RSA, ObjectClass.PRIVATE_KEY)

    def test_destroy_object_success(self, pkcs11_key: MockPkcs11PrivateKey, mock_session: Mock) -> None:
        """Test destroy_object method with successful operation."""
        mock_object = Mock()
        mock_session.get_key.return_value = mock_object

        pkcs11_key.destroy_object('test_label', KeyType.RSA, ObjectClass.PRIVATE_KEY)

        mock_object.destroy.assert_called_once()

    def test_destroy_object_not_found(self, pkcs11_key: MockPkcs11PrivateKey, mock_session: Mock) -> None:
        """Test destroy_object when object not found."""
        mock_session.get_key.side_effect = NoSuchKey('Key not found')

        with pytest.raises(ValueError, match='Object .* with label test_label not found'):
            pkcs11_key.destroy_object('test_label', KeyType.RSA, ObjectClass.PRIVATE_KEY)

    def test_key_exists_true(self, pkcs11_key: MockPkcs11PrivateKey, mock_session: Mock) -> None:
        """Test _key_exists when key exists."""
        mock_session.get_key.return_value = Mock()

        # Access the method through the instance to test it
        result = pkcs11_key._key_exists(KeyType.RSA, ObjectClass.PRIVATE_KEY)  # noqa: SLF001

        assert result is True

    def test_key_exists_false(self, pkcs11_key: MockPkcs11PrivateKey, mock_session: Mock) -> None:
        """Test _key_exists when key does not exist."""
        mock_session.get_key.side_effect = NoSuchKey('Key not found')

        result = pkcs11_key._key_exists(KeyType.RSA, ObjectClass.PRIVATE_KEY)  # noqa: SLF001

        assert result is False

    def test_destroy_key_success(self, pkcs11_key: MockPkcs11PrivateKey) -> None:
        """Test destroy_key method with successful operation."""
        mock_key = Mock()
        object.__setattr__(pkcs11_key, '_key', mock_key)
        object.__setattr__(pkcs11_key, '_public_key', Mock())

        pkcs11_key.destroy_key()

        mock_key.destroy.assert_called_once()
        # Verify attributes are set to None
        assert getattr(pkcs11_key, '_key', 'not_none') is None
        assert getattr(pkcs11_key, '_public_key', 'not_none') is None

    def test_destroy_key_no_key(self, pkcs11_key: MockPkcs11PrivateKey) -> None:
        """Test destroy_key when no key exists."""
        object.__setattr__(pkcs11_key, '_key', None)

        with pytest.raises(ValueError, match='Current key does not exist'):
            pkcs11_key.destroy_key()

    def test_destroy_key_pkcs11_error(self, pkcs11_key: MockPkcs11PrivateKey) -> None:
        """Test destroy_key when PKCS11Error occurs."""
        mock_key = Mock()
        mock_key.destroy.side_effect = PKCS11Error('Destroy failed')
        object.__setattr__(pkcs11_key, '_key', mock_key)

        with pytest.raises(RuntimeError, match='Failed to destroy key'):
            pkcs11_key.destroy_key()

    def test_close_with_session(self, pkcs11_key: MockPkcs11PrivateKey, mock_session: Mock) -> None:
        """Test close method when session exists."""
        pkcs11_key.close()
        mock_session.close.assert_called_once()

    def test_close_no_session(self) -> None:
        """Test close when no session exists."""
        with patch('pkcs11.lib'), patch.object(MockPkcs11PrivateKey, '_initialize'):
                key = MockPkcs11PrivateKey('/path/to/lib.so', 'test_token', '1234', 'test_key')
                object.__setattr__(key, '_session', None)

                # Should not raise exception
                key.close()

    def test_context_manager(self, pkcs11_key: MockPkcs11PrivateKey) -> None:
        """Test context manager functionality."""
        with patch.object(pkcs11_key, 'close') as mock_close:
            with pkcs11_key as key:
                assert key == pkcs11_key
            mock_close.assert_called_once()

    def test_abstract_methods(self) -> None:
        """Test that abstract methods are defined."""
        # Verify that the abstract methods exist
        assert hasattr(Pkcs11PrivateKey, 'sign')
        assert hasattr(Pkcs11PrivateKey, 'public_key')
        assert hasattr(Pkcs11PrivateKey, 'key_size')

        # Verify they cannot be instantiated directly
        with pytest.raises(TypeError):
            Pkcs11PrivateKey('/path/to/lib.so', 'token', '1234', 'key')  # type: ignore[abstract]

    def test_mock_implementation_methods(self, pkcs11_key: MockPkcs11PrivateKey) -> None:
        """Test that the mock implementation works correctly."""
        # Test sign method
        signature = pkcs11_key.sign(b'test_data')
        assert signature == b'mock_signature'

        # Test public_key method
        pub_key = pkcs11_key.public_key()
        assert pub_key is not None

        # Test key_size property
        assert pkcs11_key.key_size == 2048

    def test_initialization_success(self) -> None:
        """Test successful initialization of Pkcs11PrivateKey."""
        mock_session = Mock()
        mock_token = Mock()
        mock_token.open.return_value = mock_session
        mock_lib = Mock()
        mock_lib.get_token.return_value = mock_token

        with patch('pkcs11.lib', return_value=mock_lib):
            key = MockPkcs11PrivateKey('/path/to/lib.so', 'test_token', '1234', 'test_key')

            # Verify initialization was called correctly
            mock_lib.get_token.assert_called_once_with(token_label='test_token')  # noqa: S106
            mock_token.open.assert_called_once_with(user_pin='1234', rw=True)
            assert key is not None

    def test_initialization_user_already_logged_in(self) -> None:
        """Test initialization when user is already logged in."""
        mock_token = Mock()
        mock_token.open.side_effect = pkcs11.exceptions.UserAlreadyLoggedIn('Already logged in')
        mock_lib = Mock()
        mock_lib.get_token.return_value = mock_token

        with patch('pkcs11.lib', return_value=mock_lib):
            # Should not raise exception
            key = MockPkcs11PrivateKey('/path/to/lib.so', 'test_token', '1234', 'test_key')
            assert key is not None

    def test_initialization_failure(self) -> None:
        """Test initialization failure."""
        with patch('pkcs11.lib', side_effect=Exception('Library error')), \
             pytest.raises(RuntimeError, match='Failed to initialize PKCS#11 session'):
                MockPkcs11PrivateKey('/path/to/lib.so', 'test_token', '1234', 'test_key')

    def test_raise_methods(self, pkcs11_key: MockPkcs11PrivateKey) -> None:
        """Test the private _raise methods work correctly."""
        with pytest.raises(ValueError, match='test message'):
            pkcs11_key._raise_value_error('test message')  # noqa: SLF001

        with pytest.raises(TypeError, match='test message'):
            pkcs11_key._raise_type_error('test message')  # noqa: SLF001

        with pytest.raises(RuntimeError, match='test message'):
            pkcs11_key._raise_runtime_error('test message')  # noqa: SLF001
