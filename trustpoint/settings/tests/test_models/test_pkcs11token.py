"""Tests for PKCS11Token model methods."""
import os
from unittest import mock

import pkcs11
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase

from settings.models import PKCS11Token


class PKCS11TokenTestCase(TestCase):
    def setUp(self):
        """Set up a PKCS11Token instance for testing."""
        self.token = PKCS11Token.objects.create(
            label='TestToken',
            slot=1,
            module_path='/usr/local/lib/libpkcs11-proxy.so',
        )

    def tearDown(self):
        """Clear the cache after each test."""
        cache.clear()

    @mock.patch.object(PKCS11Token, 'get_pin', return_value='1234')
    @mock.patch('settings.models.pkcs11.lib')
    def test_generate_kek(self, mock_pkcs11_lib, mock_get_pin):
        """Test KEK generation."""
        mock_session = mock.Mock()
        mock_wrap_key = mock.Mock()
        mock_pkcs11_lib.return_value.get_token.return_value.open.return_value = mock_session
        mock_session.get_key.return_value = mock_wrap_key

        result = self.token.generate_kek()
        self.assertTrue(result)
        mock_pkcs11_lib.assert_called_once()
        mock_session.get_key.assert_called_with(
            key_type=mock.ANY, label=self.token.KEK_ENCRYPTION_KEY_LABEL
        )

    @mock.patch.object(PKCS11Token, 'get_pin', return_value='1234')
    @mock.patch('settings.models.pkcs11.lib')
    def test_wrap_dek(self, mock_pkcs11_lib, mock_get_pin):
        """Test wrapping a DEK."""
        mock_session = mock.Mock()
        mock_wrap_key = mock.Mock()
        mock_pkcs11_lib.return_value.get_token.return_value.open.return_value = mock_session
        mock_session.get_key.return_value = mock_wrap_key

        mock_wrap_key.encrypt.return_value = b'encrypted_data'

        dek_bytes = os.urandom(32)
        wrapped_data = self.token.wrap_dek(dek_bytes)

        assert len(wrapped_data) == 16 + len(b'encrypted_data')
        assert wrapped_data[16:] == b'encrypted_data'

        mock_wrap_key.encrypt.assert_called_once()

    @mock.patch('settings.models.pkcs11.lib')
    def test_get_dek_cache_hit(self, mock_pkcs11_lib):
        """Test retrieving DEK from cache."""
        cache_key = f'{self.token.DEK_CACHE_LABEL}-{self.token.label}'
        cache.set(cache_key, b'cached_dek')

        dek = self.token.get_dek()
        self.assertEqual(dek, b'cached_dek')
        mock_pkcs11_lib.assert_not_called()

    @mock.patch.object(PKCS11Token, 'get_pin', return_value='1234')  # Mock get_pin to return a valid PIN
    @mock.patch('settings.models.pkcs11.lib')
    def test_get_dek_cache_miss(self, mock_pkcs11_lib, mock_get_pin):
        """Test retrieving DEK when cache is empty."""
        # Set up the mock session and wrapping key
        mock_session = mock.Mock()
        mock_wrap_key = mock.Mock()
        mock_unwrapped_key = mock.MagicMock()

        # Configure the mock to return a valid 32-byte DEK when accessing pkcs11.Attribute.VALUE
        mock_unwrapped_key.__getitem__.side_effect = lambda attr: os.urandom(32) if attr == pkcs11.Attribute.VALUE else None

        mock_pkcs11_lib.return_value.get_token.return_value.open.return_value = mock_session
        mock_session.get_key.return_value = mock_wrap_key

        # Create a valid padded DEK for the mock decrypt method
        def create_padded_dek(data: bytes, block_size: int) -> bytes:
            padding_length = block_size - (len(data) % block_size)
            padding = bytes([padding_length] * padding_length)
            return data + padding

        valid_dek = os.urandom(32)  # Simulate a valid DEK
        padded_dek = create_padded_dek(valid_dek, 16)  # Add PKCS#7 padding
        mock_wrap_key.decrypt.return_value = padded_dek  # Return the padded DEK

        # Simulate that the token has an encrypted DEK
        self.token.encrypted_dek = b'mock_encrypted_dek'

        # Call the method under test
        dek = self.token.get_dek()

        # Assert that the unwrapped DEK is returned
        assert dek == valid_dek  # Ensure the DEK matches the original unpadded data
        mock_wrap_key.decrypt.assert_called_once()

    def test_get_pin_from_env(self):
        """Test retrieving PIN from environment variable."""
        with mock.patch.dict(os.environ, {'HSM_PIN': '1234'}):
            pin = self.token.get_pin()
            self.assertEqual(pin, '1234')

    @mock.patch('pathlib.Path.exists', return_value=True)  # Mock Path.exists
    @mock.patch('os.access', return_value=True)  # Mock os.access
    @mock.patch('pathlib.Path.open', new_callable=mock.mock_open, read_data='1234')  # Mock Path.open
    @mock.patch.dict(os.environ, {'HSM_PIN_FILE': '/run/secrets/hsm_pin'})  # Mock the environment variable
    def test_get_pin_from_file(self, mock_open, mock_access, mock_exists):
        """Test retrieving PIN from a file."""
        pin = self.token.get_pin()
        self.assertEqual(pin, '1234')
        mock_open.assert_called_once_with('r')

    def test_get_pin_no_pin(self):
        """Test error when no PIN is configured."""
        with self.assertRaises(ImproperlyConfigured):
            self.token.get_pin()

    @mock.patch.object(PKCS11Token, 'generate_and_wrap_dek', return_value=b'wrapped_dek')
    @mock.patch.object(PKCS11Token, '_unwrap_dek', return_value=os.urandom(32))
    @mock.patch.object(PKCS11Token, '_derive_bek_from_password', return_value=os.urandom(32))
    @mock.patch.object(PKCS11Token, '_encrypt_dek_with_bek', return_value=b'encrypted_dek')
    def test_set_backup_password(self, mock_encrypt, mock_derive, mock_unwrap, mock_generate):
        """Test setting a backup password."""
        # Simulate that a DEK has already been generated and wrapped
        self.token.encrypted_dek = b'wrapped_dek'

        # Call the method under test
        self.token.set_backup_password('password')

        # Assert that the BEK-encrypted DEK was set correctly
        self.assertEqual(self.token.bek_encrypted_dek, b'encrypted_dek')

        # Verify that the mocked methods were called
        mock_unwrap.assert_called_once()
        mock_derive.assert_called_once_with('password')
        mock_encrypt.assert_called_once()

    def test_verify_backup_password(self):
        """Test verifying a backup password."""
        with mock.patch.object(self.token, 'get_dek_with_backup_password', return_value=os.urandom(32)):
            result = self.token.verify_backup_password('password')
            self.assertTrue(result)

    def test_remove_backup_encryption(self):
        """Test removing backup encryption."""
        self.token.bek_encrypted_dek = b'encrypted_dek'
        self.token.remove_backup_encryption()
        self.assertIsNone(self.token.bek_encrypted_dek)

    def test_has_backup_encryption(self):
        """Test checking if backup encryption exists."""
        self.token.bek_encrypted_dek = b'encrypted_dek'
        self.assertTrue(self.token.has_backup_encryption())
        self.token.bek_encrypted_dek = None
        self.assertFalse(self.token.has_backup_encryption())
