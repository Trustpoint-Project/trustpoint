"""Tests for the pkcs11_keys module - Pkcs11Utilities class."""

import pytest
from unittest import mock
from unittest.mock import MagicMock, patch, call

import pkcs11
from pkcs11 import KeyType, Mechanism, ObjectClass, Attribute
from pkcs11.exceptions import NoSuchKey, PKCS11Error

# Import the module to test
from pkcs11_support.pkcs11_util import Pkcs11Utilities


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
def mock_pkcs11_lib():
    """Create a mock PKCS#11 library."""
    with patch('pkcs11_support.pkcs11_util.lib') as mock_lib_func:
        mock_lib_instance = MagicMock()
        mock_lib_func.return_value = mock_lib_instance
        yield mock_lib_instance

@pytest.fixture
def mock_slot():
    """Create a mock PKCS#11 slot."""
    slot = MagicMock(spec=pkcs11.Slot)
    slot.token = MagicMock(spec=pkcs11.Token)
    slot.token.label = "TestToken"
    return slot


@pytest.fixture
def mock_token():
    """Create a mock PKCS#11 token."""
    token = MagicMock(spec=pkcs11.Token)
    token.label = "TestToken"
    token.get_mechanisms = MagicMock()
    return token


@pytest.fixture
def mock_session():
    """Create a mock PKCS#11 session."""
    session = MagicMock(spec=pkcs11.Session)
    session.__enter__ = MagicMock(return_value=session)
    session.__exit__ = MagicMock()
    return session


@pytest.fixture
def pkcs11_utils(mock_lib_path, mock_pkcs11_lib):
    """Create a Pkcs11Utilities instance with mocked dependencies."""
    return Pkcs11Utilities(mock_lib_path)


class TestPkcs11UtilitiesInitialization:
    """Test Pkcs11Utilities initialization."""

    def test_initialization_with_valid_lib_path(self, mock_lib_path, mock_pkcs11_lib):
        """Test that Pkcs11Utilities initializes correctly with valid library path."""
        utils = Pkcs11Utilities(mock_lib_path)

        assert utils._lib == mock_pkcs11_lib
        assert utils._slots_cache is None
        assert utils._tokens_cache is None

    def test_initialization_calls_lib_function(self, mock_lib_path):
        """Test that initialization calls the lib function with correct path."""
        with patch('pkcs11_support.pkcs11_util.lib') as mock_lib_func:
            Pkcs11Utilities(mock_lib_path)
            mock_lib_func.assert_called_once_with(mock_lib_path)


class TestPkcs11UtilitiesSlotManagement:
    """Test slot and token management methods."""

    def test_get_slots_without_cache(self, pkcs11_utils, mock_pkcs11_lib, mock_slot):
        """Test getting slots when cache is empty."""
        mock_pkcs11_lib.get_slots.return_value = [mock_slot]

        slots = pkcs11_utils.get_slots()

        assert slots == [mock_slot]
        assert pkcs11_utils._slots_cache == [mock_slot]
        mock_pkcs11_lib.get_slots.assert_called_once()

    def test_get_slots_with_cache(self, pkcs11_utils, mock_pkcs11_lib, mock_slot):
        """Test getting slots when cache is populated."""
        cached_slots = [mock_slot]
        pkcs11_utils._slots_cache = cached_slots

        slots = pkcs11_utils.get_slots()

        assert slots == cached_slots
        mock_pkcs11_lib.get_slots.assert_not_called()

    def test_get_tokens_without_cache(self, pkcs11_utils, mock_slot, mock_token):
        """Test getting tokens when cache is empty."""
        mock_slot.token = mock_token
        with patch.object(pkcs11_utils, 'get_slots', return_value=[mock_slot]):
            tokens = pkcs11_utils.get_tokens()

            assert tokens == [mock_token]
            assert pkcs11_utils._tokens_cache == [mock_token]

    def test_get_tokens_with_cache(self, pkcs11_utils, mock_token):
        """Test getting tokens when cache is populated."""
        cached_tokens = [mock_token]
        pkcs11_utils._tokens_cache = cached_tokens

        tokens = pkcs11_utils.get_tokens()

        assert tokens == cached_tokens

    def test_get_token_by_label_success(self, pkcs11_utils, mock_token):
        """Test successfully finding a token by label."""
        mock_token.label = "TestToken"
        with patch.object(pkcs11_utils, 'get_tokens', return_value=[mock_token]):
            token = pkcs11_utils.get_token_by_label("TestToken")

            assert token == mock_token

    def test_get_token_by_label_not_found(self, pkcs11_utils, mock_token):
        """Test error when token label is not found."""
        mock_token.label = "DifferentToken"
        with patch.object(pkcs11_utils, 'get_tokens', return_value=[mock_token]):
            with pytest.raises(ValueError, match="Token with label 'NonExistentToken' not found"):
                pkcs11_utils.get_token_by_label("NonExistentToken")

    def test_get_token_by_label_multiple_tokens(self, pkcs11_utils):
        """Test finding correct token when multiple tokens exist."""
        token1 = MagicMock()
        token1.label = "Token1"
        token2 = MagicMock()
        token2.label = "Token2"

        with patch.object(pkcs11_utils, 'get_tokens', return_value=[token1, token2]):
            token = pkcs11_utils.get_token_by_label("Token2")

            assert token == token2


class TestPkcs11UtilitiesMechanisms:
    """Test mechanism-related methods."""

    def test_get_mechanisms(self, pkcs11_utils, mock_token):
        """Test getting mechanisms for a token."""
        expected_mechanisms = [Mechanism.RSA_PKCS, Mechanism.ECDSA_SHA256]
        mock_token.get_mechanisms.return_value = expected_mechanisms

        with patch.object(pkcs11_utils, 'get_token_by_label', return_value=mock_token):
            mechanisms = pkcs11_utils.get_mechanisms("TestToken")

            assert mechanisms == expected_mechanisms
            mock_token.get_mechanisms.assert_called_once()


class TestPkcs11UtilitiesSessionManagement:
    """Test session management methods."""

    def test_open_session(self, pkcs11_utils, mock_token, mock_session):
        """Test opening a session with a token."""
        mock_token.open.return_value = mock_session

        with patch.object(pkcs11_utils, 'get_token_by_label', return_value=mock_token):
            session = pkcs11_utils.open_session("TestToken", "1234")

            assert session == mock_session
            mock_token.open.assert_called_once_with("1234", rw=True)


class TestPkcs11UtilitiesRandomGeneration:
    """Test random number generation methods."""

    def test_generate_random(self, pkcs11_utils, mock_session):
        """Test generating random bytes."""
        expected_random = b'\x01\x02\x03\x04'
        mock_session.generate_random.return_value = expected_random

        with patch.object(pkcs11_utils, 'open_session', return_value=mock_session):
            random_bytes = pkcs11_utils.generate_random("TestToken", "1234", 4)

            assert random_bytes == expected_random
            mock_session.generate_random.assert_called_once_with(4)

    def test_seed_random(self, pkcs11_utils, mock_session):
        """Test seeding random number generator."""
        seed_data = b'\xaa\xbb\xcc\xdd'

        with patch.object(pkcs11_utils, 'open_session', return_value=mock_session):
            pkcs11_utils.seed_random("TestToken", "1234", seed_data)

            mock_session.seed_random.assert_called_once_with(seed_data)


class TestPkcs11UtilitiesObjectDestruction:
    """Test object destruction methods."""

    def test_destroy_object_success(self, pkcs11_utils, mock_session):
        """Test successfully destroying an object."""
        mock_obj = MagicMock()
        mock_session.get_key.return_value = mock_obj

        with patch.object(pkcs11_utils, 'open_session', return_value=mock_session):
            pkcs11_utils.destroy_object(
                "TestToken",
                "1234",
                "test-key",
                KeyType.RSA,
                ObjectClass.PRIVATE_KEY
            )

            mock_session.get_key.assert_called_once_with(
                label="test-key",
                key_type=KeyType.RSA,
                object_class=ObjectClass.PRIVATE_KEY
            )
            mock_obj.destroy.assert_called_once()

    def test_destroy_object_not_found(self, pkcs11_utils, mock_session):
        """Test error when object to destroy is not found."""
        mock_session.get_key.side_effect = NoSuchKey()
        mock_session.__enter__.return_value = mock_session
        mock_session.__exit__.return_value = None

        with patch.object(pkcs11_utils, 'open_session', return_value=mock_session):
            with pytest.raises(ValueError,
                               match="Object .* with label 'nonexistent-key' not found on token 'TestToken'"):
                pkcs11_utils.destroy_object(
                    "TestToken",
                    "1234",
                    "nonexistent-key",
                    KeyType.RSA,
                    ObjectClass.PRIVATE_KEY
                )


class TestPkcs11UtilitiesContextManager:
    """Test context manager behavior with sessions."""

    def test_session_context_manager(self, pkcs11_utils, mock_session):
        """Test that sessions are used as context managers properly."""
        with patch.object(pkcs11_utils, 'open_session', return_value=mock_session):
            pkcs11_utils.generate_random("TestToken", "1234", 16)

            # Verify the session was used as a context manager
            mock_session.__enter__.assert_called_once()
            mock_session.__exit__.assert_called_once()


class TestPkcs11UtilitiesEdgeCases:
    """Test edge cases and error conditions."""

    def test_get_slots_empty_list(self, pkcs11_utils, mock_pkcs11_lib):
        """Test handling of empty slots list."""
        mock_pkcs11_lib.get_slots.return_value = []

        slots = pkcs11_utils.get_slots()

        assert slots == []
        assert pkcs11_utils._slots_cache == []

    def test_get_tokens_empty_slots(self, pkcs11_utils):
        """Test handling when no slots are available."""
        with patch.object(pkcs11_utils, 'get_slots', return_value=[]):
            tokens = pkcs11_utils.get_tokens()

            assert tokens == []
            assert pkcs11_utils._tokens_cache == []

    def test_generate_random_zero_length(self, pkcs11_utils, mock_session):
        """Test generating zero-length random data."""
        mock_session.generate_random.return_value = b''

        with patch.object(pkcs11_utils, 'open_session', return_value=mock_session):
            random_bytes = pkcs11_utils.generate_random("TestToken", "1234", 0)

            assert random_bytes == b''
            mock_session.generate_random.assert_called_once_with(0)

    def test_seed_random_empty_data(self, pkcs11_utils, mock_session):
        """Test seeding with empty data."""
        with patch.object(pkcs11_utils, 'open_session', return_value=mock_session):
            pkcs11_utils.seed_random("TestToken", "1234", b'')

            mock_session.seed_random.assert_called_once_with(b'')


class TestPkcs11UtilitiesCaching:
    """Test caching behavior."""

    def test_slots_caching_persistence(self, pkcs11_utils, mock_pkcs11_lib, mock_slot):
        """Test that slots cache persists across calls."""
        mock_pkcs11_lib.get_slots.return_value = [mock_slot]

        # First call should populate cache
        slots1 = pkcs11_utils.get_slots()
        # Second call should use cache
        slots2 = pkcs11_utils.get_slots()

        assert slots1 == slots2
        assert slots1 is slots2  # Same object reference
        mock_pkcs11_lib.get_slots.assert_called_once()  # Called only once

    def test_tokens_caching_persistence(self, pkcs11_utils, mock_slot, mock_token):
        """Test that tokens cache persists across calls."""
        mock_slot.token = mock_token
        with patch.object(pkcs11_utils, 'get_slots', return_value=[mock_slot]):
            # First call should populate cache
            tokens1 = pkcs11_utils.get_tokens()
            # Second call should use cache
            tokens2 = pkcs11_utils.get_tokens()

            assert tokens1 == tokens2
            assert tokens1 is tokens2  # Same object reference

    def test_cache_independence(self, pkcs11_utils, mock_pkcs11_lib, mock_slot):
        """Test that slots and tokens caches are independent."""
        mock_pkcs11_lib.get_slots.return_value = [mock_slot]

        # Populate slots cache
        pkcs11_utils.get_slots()
        assert pkcs11_utils._slots_cache is not None
        assert pkcs11_utils._tokens_cache is None

        # Populate tokens cache
        pkcs11_utils.get_tokens()
        assert pkcs11_utils._slots_cache is not None
        assert pkcs11_utils._tokens_cache is not None