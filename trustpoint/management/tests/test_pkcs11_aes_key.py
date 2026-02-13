"""Tests for PKCS#11 Pkcs11AESKey class."""

from unittest.mock import Mock, patch

import pkcs11
import pytest

from management.pkcs11_util import Pkcs11AESKey


class TestPkcs11AESKey:
    """Test cases for the Pkcs11AESKey class."""

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
    def aes_key(self) -> Pkcs11AESKey:
        """Create Pkcs11AESKey instance without initializing session."""
        with patch.object(Pkcs11AESKey, '_initialize'):
            return Pkcs11AESKey('/path/to/lib.so', 'test_token', '1234', 'test_aes_key')

    @pytest.fixture
    def aes_key_with_session(self, mock_session: Mock) -> Pkcs11AESKey:
        """Create Pkcs11AESKey instance with mocked session."""
        with patch('pkcs11.lib') as mock_lib_func:
            mock_lib = Mock()
            mock_token = Mock()
            mock_token.open.return_value = mock_session
            mock_lib.get_token.return_value = mock_token
            mock_lib_func.return_value = mock_lib

            aes_key = Pkcs11AESKey('/path/to/lib.so', 'test_token', '1234', 'test_aes_key')
            # Manually set the session to avoid accessing private members
            object.__setattr__(aes_key, '_session', mock_session)
            return aes_key

    def test_init(self, aes_key: Pkcs11AESKey) -> None:
        """Test Pkcs11AESKey initialization."""
        # Use getattr to access private attributes in tests
        assert aes_key._lib_path == '/path/to/lib.so'
        assert aes_key._token_label == 'test_token'
        assert aes_key._user_pin == '1234'
        assert aes_key._key_label == 'test_aes_key'
        assert aes_key._lib is None
        assert aes_key._session is None
        assert aes_key._key is None

    def test_supported_key_lengths(self) -> None:
        def test_initialize_success(self) -> None:
            """Test successful _initialize method."""
            mock_session = Mock()
            mock_token = Mock()
            mock_token.open.return_value = mock_session
            mock_lib = Mock()
            mock_lib.get_token.return_value = mock_token

            with patch('pkcs11.lib', return_value=mock_lib):
                aes_key = Pkcs11AESKey('/path/to/lib.so', 'test_token', '1234', 'test_aes_key')

                # Manually call _initialize to test it
                aes_key._initialize()

                # Verify initialization was called correctly
                mock_lib.get_token.assert_called_once_with(token_label='test_token')
                mock_token.open.assert_called_once_with(user_pin='1234', rw=True)
                assert aes_key._lib == mock_lib
                assert aes_key._token == mock_token
                assert aes_key._session == mock_session

        def test_initialize_with_slot_id(self) -> None:
            """Test _initialize method with specific slot_id."""
            mock_session = Mock()
            mock_token = Mock()
            mock_token.open.return_value = mock_session
            mock_lib = Mock()
            mock_lib.get_token.return_value = mock_token

            with patch('pkcs11.lib', return_value=mock_lib):
                aes_key = Pkcs11AESKey('/path/to/lib.so', 'test_token', '1234', 'test_aes_key')
                # Set slot_id before initialization
                object.__setattr__(aes_key, '_slot_id', 5)

                aes_key._initialize()

                mock_lib.get_token.assert_called_once_with(token_label='test_token', slot_id=5)

        def test_lazy_initialization_on_load_key(self) -> None:
            """Test that initialization happens lazily when load_key is called."""
            mock_session = Mock()
            mock_token = Mock()
            mock_token.open.return_value = mock_session
            mock_lib = Mock()
            mock_lib.get_token.return_value = mock_token
            mock_key = Mock()
            mock_session.get_key.return_value = mock_key

            with patch('pkcs11.lib', return_value=mock_lib):
                aes_key = Pkcs11AESKey('/path/to/lib.so', 'test_token', '1234', 'test_aes_key')

                # Session should be None initially
                assert aes_key._session is None

                # Load key should trigger initialization
                aes_key.load_key()

                # Verify initialization happened
                mock_lib.get_token.assert_called_once_with(token_label='test_token')
                mock_token.open.assert_called_once_with(user_pin='1234', rw=True)
                assert aes_key._session == mock_session

        def test_lazy_initialization_on_generate_key(self) -> None:
            """Test that initialization happens lazily when generate_key is called."""
            mock_session = Mock()
            mock_token = Mock()
            mock_token.open.return_value = mock_session
            mock_lib = Mock()
            mock_lib.get_token.return_value = mock_token
            mock_key = Mock()
            mock_session.generate_key.return_value = mock_key

            with patch('pkcs11.lib', return_value=mock_lib):
                aes_key = Pkcs11AESKey('/path/to/lib.so', 'test_token', '1234', 'test_aes_key')

                # Session should be None initially
                assert aes_key._session is None

                # Generate key should trigger initialization
                aes_key.generate_key(256)

                # Verify initialization happened
                mock_lib.get_token.assert_called_once_with(token_label='test_token')
                mock_token.open.assert_called_once_with(user_pin='1234', rw=True)
                assert aes_key._session == mock_session

        def test_generate_key_with_invalid_type(self, aes_key_with_session: Pkcs11AESKey) -> None:
            """Test generate_key with invalid key length type."""
            with pytest.raises(TypeError):
                aes_key_with_session.generate_key('256')  # type: ignore

        def test_generate_key_with_float_length(self, aes_key_with_session: Pkcs11AESKey) -> None:
            """Test generate_key with float key length."""
            with pytest.raises(ValueError, match='Unsupported key length: 256.5'):
                aes_key_with_session.generate_key(256.5)  # type: ignore

        def test_load_key_with_wrong_key_type(self, aes_key_with_session: Pkcs11AESKey, mock_session: Mock) -> None:
            """Test load_key when wrong key type is found."""
            mock_session.get_key.side_effect = pkcs11.exceptions.AttributeTypeInvalid('Wrong key type')

            with pytest.raises(RuntimeError, match="Failed to load AES key 'test_aes_key'"):
                aes_key_with_session.load_key()

        def test_session_reuse(self, aes_key_with_session: Pkcs11AESKey, mock_session: Mock) -> None:
            """Test that existing session is reused and not reinitialized."""
            mock_key = Mock()
            mock_session.get_key.return_value = mock_key

            # First operation
            aes_key_with_session.load_key()

            # Second operation - should reuse same session
            mock_session.generate_key.return_value = mock_key
            aes_key_with_session.generate_key(128)

            # Session should be the same instance
            assert aes_key_with_session._session == mock_session

        def test_concurrent_operations_same_instance(
            self, aes_key_with_session: Pkcs11AESKey, mock_session: Mock
        ) -> None:
            """Test multiple operations on same instance work correctly."""
            mock_key1 = Mock()
            mock_key2 = Mock()

            # First generate a key
            mock_session.generate_key.return_value = mock_key1
            aes_key_with_session.generate_key(256)
            assert aes_key_with_session._key == mock_key1

            # Then load a different key (overwrites the generated one)
            mock_session.get_key.return_value = mock_key2
            aes_key_with_session.load_key()
            assert aes_key_with_session._key == mock_key2

        def test_key_attribute_after_generation(self, aes_key_with_session: Pkcs11AESKey, mock_session: Mock) -> None:
            """Test that key attribute is properly set after generation."""
            mock_key = Mock()
            mock_session.generate_key.return_value = mock_key

            # Before generation
            assert aes_key_with_session._key is None

            # After generation
            aes_key_with_session.generate_key(192)
            assert aes_key_with_session._key == mock_key
            assert aes_key_with_session._key is not None

        def test_key_attribute_after_loading(self, aes_key_with_session: Pkcs11AESKey, mock_session: Mock) -> None:
            """Test that key attribute is properly set after loading."""
            mock_key = Mock()
            mock_session.get_key.return_value = mock_key

            # Before loading
            assert aes_key_with_session._key is None

            # After loading
            aes_key_with_session.load_key()
            assert aes_key_with_session._key == mock_key
            assert aes_key_with_session._key is not None

        def test_exception_handling_in_initialize(self) -> None:
            """Test various exception scenarios during initialization."""
            # Test token not found
            mock_lib = Mock()
            mock_lib.get_token.side_effect = pkcs11.exceptions.TokenNotRecognised('Token not found')

            with patch('pkcs11.lib', return_value=mock_lib):
                with pytest.raises(RuntimeError, match='Failed to initialize PKCS#11 session'):
                    aes_key = Pkcs11AESKey('/path/to/lib.so', 'bad_token', '1234', 'test_aes_key')
                    aes_key._initialize()

        def test_pin_incorrect_exception(self) -> None:
            """Test initialization with incorrect PIN."""
            mock_token = Mock()
            mock_token.open.side_effect = pkcs11.exceptions.PinIncorrect('Invalid PIN')
            mock_lib = Mock()
            mock_lib.get_token.return_value = mock_token

            with patch('pkcs11.lib', return_value=mock_lib):
                aes_key = Pkcs11AESKey('/path/to/lib.so', 'test_token', 'wrong_pin', 'test_aes_key')
                with pytest.raises(RuntimeError, match='Failed to initialize PKCS#11 session'):
                    aes_key._initialize()

        def test_multiple_close_calls(self, aes_key_with_session: Pkcs11AESKey, mock_session: Mock) -> None:
            """Test that multiple close calls don't cause issues."""
            # First close
            aes_key_with_session.close()
            mock_session.close.assert_called_once()
            assert aes_key_with_session._session is None

            # Second close should not raise exception
            aes_key_with_session.close()
            # close() should still have been called only once from before
            mock_session.close.assert_called_once()

        def test_operations_after_close(self, aes_key_with_session: Pkcs11AESKey, mock_session: Mock) -> None:
            """Test operations after close reinitialize the session."""
            # Close the session
            aes_key_with_session.close()
            assert aes_key_with_session._session is None

            # Mock new session for reinitialization
            new_mock_session = Mock()
            new_mock_token = Mock()
            new_mock_token.open.return_value = new_mock_session
            new_mock_lib = Mock()
            new_mock_lib.get_token.return_value = new_mock_token
            mock_key = Mock()
            new_mock_session.get_key.return_value = mock_key

            with patch('pkcs11.lib', return_value=new_mock_lib):
                # This should reinitialize and work
                aes_key_with_session.load_key()

                # Verify new session was created
                assert aes_key_with_session._session == new_mock_session

        def test_context_manager_ensures_cleanup(self) -> None:
            """Test context manager properly cleans up resources."""
            mock_session = Mock()
            mock_token = Mock()
            mock_token.open.return_value = mock_session
            mock_lib = Mock()
            mock_lib.get_token.return_value = mock_token

            with patch('pkcs11.lib', return_value=mock_lib):
                aes_key = Pkcs11AESKey('/path/to/lib.so', 'test_token', '1234', 'test_aes_key')

                with aes_key as key_context:
                    # Use the key within context
                    assert key_context == aes_key
                    # Force initialization by accessing a method
                    mock_key = Mock()
                    mock_session.get_key.return_value = mock_key
                    key_context.load_key()

                    # Session should be active
                    assert key_context._session == mock_session

                # After context, session should be closed
                mock_session.close.assert_called_once()
                assert aes_key._session is None
            aes_key_with_session.load_key()

    def test_load_key_general_error(self, aes_key_with_session: Pkcs11AESKey, mock_session: Mock) -> None:
        """Test load_key with general error."""
        mock_session.get_key.side_effect = Exception('General error')

        with pytest.raises(RuntimeError, match="Failed to load AES key 'test_aes_key'"):
            aes_key_with_session.load_key()

    def test_load_key_initializes_session(self, aes_key: Pkcs11AESKey) -> None:
        """Test load_key initializes session if None."""
        mock_session = Mock()
        mock_key = Mock()
        mock_session.get_key.return_value = mock_key

        with patch.object(aes_key, '_initialize') as mock_init:
            # Set session after initialization
            def set_session() -> None:
                object.__setattr__(aes_key, '_session', mock_session)

            mock_init.side_effect = set_session

            aes_key.load_key()

            mock_init.assert_called_once()
            assert aes_key._key == mock_key

    def test_generate_key_default_length(self, aes_key_with_session: Pkcs11AESKey, mock_session: Mock) -> None:
        """Test generate_key with default key length."""
        mock_key = Mock()
        mock_session.generate_key.return_value = mock_key

        aes_key_with_session.generate_key()

        assert aes_key_with_session._key == mock_key
        mock_session.generate_key.assert_called_once_with(
            pkcs11.KeyType.AES, key_length=256, label='test_aes_key', store=True
        )

    def test_generate_key_custom_length(self, aes_key_with_session: Pkcs11AESKey, mock_session: Mock) -> None:
        """Test generate_key with custom key length."""
        mock_key = Mock()
        mock_session.generate_key.return_value = mock_key

        aes_key_with_session.generate_key(128)

        assert aes_key_with_session._key == mock_key
        mock_session.generate_key.assert_called_once_with(
            pkcs11.KeyType.AES, key_length=128, label='test_aes_key', store=True
        )

    def test_generate_key_192_length(self, aes_key_with_session: Pkcs11AESKey, mock_session: Mock) -> None:
        """Test generate_key with 192-bit key length."""
        mock_key = Mock()
        mock_session.generate_key.return_value = mock_key

        aes_key_with_session.generate_key(192)

        mock_session.generate_key.assert_called_once_with(
            pkcs11.KeyType.AES, key_length=192, label='test_aes_key', store=True
        )

    def test_generate_key_unsupported_length(self, aes_key_with_session: Pkcs11AESKey) -> None:
        """Test generate_key with unsupported key length."""
        with pytest.raises(ValueError, match='Unsupported key length: 64. Must be one of \\[128, 192, 256\\]'):
            aes_key_with_session.generate_key(64)

    def test_generate_key_another_unsupported_length(self, aes_key_with_session: Pkcs11AESKey) -> None:
        """Test generate_key with another unsupported key length."""
        with pytest.raises(ValueError, match='Unsupported key length: 512'):
            aes_key_with_session.generate_key(512)

    def test_generate_key_initializes_session(self, aes_key: Pkcs11AESKey) -> None:
        """Test generate_key initializes session if None."""
        mock_session = Mock()
        mock_key = Mock()
        mock_session.generate_key.return_value = mock_key

        with patch.object(aes_key, '_initialize') as mock_init:
            # Set session after initialization
            def set_session() -> None:
                object.__setattr__(aes_key, '_session', mock_session)

            mock_init.side_effect = set_session

            aes_key.generate_key()

            mock_init.assert_called_once()
            assert aes_key._key == mock_key

    def test_generate_key_failure(self, aes_key_with_session: Pkcs11AESKey, mock_session: Mock) -> None:
        """Test generate_key when key generation fails."""
        mock_session.generate_key.side_effect = Exception('Generation failed')

        with pytest.raises(RuntimeError, match='Failed to generate AES key'):
            aes_key_with_session.generate_key()

    def test_close_with_session(self, aes_key_with_session: Pkcs11AESKey, mock_session: Mock) -> None:
        """Test close method when session exists."""
        aes_key_with_session.close()

        mock_session.close.assert_called_once()
        assert aes_key_with_session._session is None

    def test_close_no_session(self, aes_key: Pkcs11AESKey) -> None:
        """Test close when no session exists."""
        # Should not raise exception
        aes_key.close()

    def test_close_with_exception(self, aes_key_with_session: Pkcs11AESKey, mock_session: Mock) -> None:
        """Test close when session.close() raises exception."""
        mock_session.close.side_effect = Exception('Close failed')

        # Should not raise exception due to contextlib.suppress
        aes_key_with_session.close()

        mock_session.close.assert_called_once()
        assert aes_key_with_session._session is None

    def test_context_manager(self, aes_key: Pkcs11AESKey) -> None:
        """Test context manager functionality."""
        with patch.object(aes_key, 'close') as mock_close:
            with aes_key as key:
                assert key == aes_key
            mock_close.assert_called_once()

    def test_context_manager_with_exception(self, aes_key: Pkcs11AESKey) -> None:
        """Test context manager functionality when exception occurs."""
        with patch.object(aes_key, 'close') as mock_close:
            try:
                with aes_key as key:
                    assert key == aes_key
                    raise ValueError('Test exception')
            except ValueError:
                pass
            mock_close.assert_called_once()

    def test_multiple_operations_workflow(self, mock_session: Mock) -> None:
        """Test a complete workflow with multiple operations."""
        with patch('pkcs11.lib') as mock_lib_func:
            mock_lib = Mock()
            mock_token = Mock()
            mock_token.open.return_value = mock_session
            mock_lib.get_token.return_value = mock_token
            mock_lib_func.return_value = mock_lib

            # Create AES key instance
            aes_key = Pkcs11AESKey('/path/to/lib.so', 'test_token', '1234', 'test_aes_key')

            # Generate key
            mock_generated_key = Mock()
            mock_session.generate_key.return_value = mock_generated_key
            aes_key.generate_key(256)

            # Verify key was generated and stored
            assert aes_key._key == mock_generated_key
            mock_session.generate_key.assert_called_once_with(
                pkcs11.KeyType.AES, key_length=256, label='test_aes_key', store=True
            )

            # Close the session
            aes_key.close()
            mock_session.close.assert_called_once()

    def test_load_then_generate_error(self, aes_key_with_session: Pkcs11AESKey, mock_session: Mock) -> None:
        """Test that we can handle both load and generate operations."""
        # First, try to load a key that doesn't exist
        mock_session.get_key.side_effect = pkcs11.NoSuchKey('Key not found')

        with pytest.raises(pkcs11.NoSuchKey):
            aes_key_with_session.load_key()

        # Then generate a new key
        mock_key = Mock()
        mock_session.generate_key.return_value = mock_key
        aes_key_with_session.generate_key(128)

        assert aes_key_with_session._key == mock_key

    def test_all_supported_key_lengths(self, aes_key_with_session: Pkcs11AESKey, mock_session: Mock) -> None:
        """Test that all supported key lengths work."""
        mock_key = Mock()
        mock_session.generate_key.return_value = mock_key

        for length in Pkcs11AESKey.SUPPORTED_KEY_LENGTHS:
            # Reset the key
            object.__setattr__(aes_key_with_session, '_key', None)
            mock_session.generate_key.reset_mock()

            aes_key_with_session.generate_key(length)

            mock_session.generate_key.assert_called_once_with(
                pkcs11.KeyType.AES, key_length=length, label='test_aes_key', store=True
            )

    def test_string_representation_attributes(self, aes_key: Pkcs11AESKey) -> None:
        """Test that all expected attributes are present."""
        # Verify all expected private attributes exist
        expected_attrs = [
            '_lib_path',
            '_token_label',
            '_user_pin',
            '_key_label',
            '_lib',
            '_slot_id',
            '_token',
            '_session',
            '_key',
            '_key_length',
        ]

        for attr in expected_attrs:
            assert hasattr(aes_key, attr), f'Missing attribute: {attr}'
