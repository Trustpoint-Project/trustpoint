"""Tests for encrypted fields module."""

import base64
import os
from unittest.mock import Mock, patch

import pytest
from django.core.exceptions import ValidationError
from django.test import TestCase

from util.encrypted_fields import EncryptedCharField, EncryptedTextField


class TestEncryptedTextField(TestCase):
    """Test cases for EncryptedTextField."""

    def setUp(self):
        """Set up test fixtures."""
        self.field = EncryptedTextField()
        self.test_dek = os.urandom(32)  # 32-byte DEK for AES-256
        self.test_plaintext = 'sensitive_data_123'

    def test_init(self):
        """Test field initialization."""
        field = EncryptedTextField()
        assert isinstance(field, EncryptedTextField)

    def test_raise_validation_error(self):
        """Test raise_validation_error method."""
        with pytest.raises(ValidationError) as cm:
            self.field.raise_validation_error('Test error message')
        assert str(cm.value.message) == 'Test error message'

    @patch('util.encrypted_fields.KeyStorageConfig')
    def test_should_encrypt_softhsm(self, mock_config):
        """Test should_encrypt returns True for SoftHSM storage type."""
        mock_storage = Mock()
        mock_storage.storage_type = Mock()
        mock_storage.storage_type = 'SOFTHSM'
        mock_config.objects.first.return_value = mock_storage
        mock_config.StorageType.SOFTHSM = 'SOFTHSM'
        mock_config.StorageType.PHYSICAL_HSM = 'PHYSICAL_HSM'

        result = self.field.should_encrypt()
        self.assertTrue(result)

    @patch('util.encrypted_fields.KeyStorageConfig')
    def test_should_encrypt_physical_hsm(self, mock_config: Mock):
        """Test should_encrypt returns True for Physical HSM storage type."""
        mock_storage = Mock()
        mock_storage.storage_type = 'PHYSICAL_HSM'
        mock_config.objects.first.return_value = mock_storage
        mock_config.StorageType.SOFTHSM = 'SOFTHSM'
        mock_config.StorageType.PHYSICAL_HSM = 'PHYSICAL_HSM'

        result = self.field.should_encrypt()
        self.assertTrue(result)

    @patch('util.encrypted_fields.KeyStorageConfig')
    def test_should_encrypt_software_storage(self, mock_config):
        """Test should_encrypt returns False for software storage type."""
        mock_storage = Mock()
        mock_storage.storage_type = 'SOFTWARE'
        mock_config.objects.first.return_value = mock_storage
        mock_config.StorageType.SOFTHSM = 'SOFTHSM'
        mock_config.StorageType.PHYSICAL_HSM = 'PHYSICAL_HSM'

        result = self.field.should_encrypt()
        self.assertFalse(result)

    @patch('util.encrypted_fields.KeyStorageConfig')
    def test_should_encrypt_no_config(self, mock_config):
        """Test should_encrypt raises ValidationError when no config found."""
        mock_config.objects.first.return_value = None

        with self.assertRaises(ValidationError) as cm:
            self.field.should_encrypt()
        self.assertIn('No crypto storage configuration found', str(cm.exception.message))

    @patch('util.encrypted_fields.KeyStorageConfig')
    def test_should_encrypt_database_error(self, mock_config):
        """Test should_encrypt handles database errors."""
        mock_config.objects.first.side_effect = Exception('Database error')

        with self.assertRaises(ValidationError) as cm:
            self.field.should_encrypt()
        self.assertIn('Failed to check crypto storage configuration', str(cm.exception.message))

    @patch('util.encrypted_fields.PKCS11Token')
    def test_get_dek_from_cache(self, mock_token_model):
        """Test get_dek returns cached DEK when available."""
        mock_token = Mock()
        mock_token.get_dek_cache.return_value = self.test_dek
        mock_token_model.objects.first.return_value = mock_token

        result = self.field.get_dek()
        self.assertEqual(result, self.test_dek)
        mock_token.get_dek_cache.assert_called_once()
        mock_token.get_dek.assert_not_called()

    @patch('util.encrypted_fields.PKCS11Token')
    def test_get_dek_from_token(self, mock_token_model):
        """Test get_dek retrieves DEK from token when cache is empty."""
        mock_token = Mock()
        mock_token.get_dek_cache.return_value = None
        mock_token.get_dek.return_value = self.test_dek
        mock_token_model.objects.first.return_value = mock_token

        result = self.field.get_dek()
        self.assertEqual(result, self.test_dek)
        mock_token.get_dek_cache.assert_called_once()
        mock_token.get_dek.assert_called_once()

    @patch('util.encrypted_fields.PKCS11Token')
    def test_get_dek_no_token(self, mock_token_model):
        """Test get_dek raises ValidationError when no token configured."""
        mock_token_model.objects.first.return_value = None

        with self.assertRaises(ValidationError) as cm:
            self.field.get_dek()
        self.assertIn('No PKCS#11 token configured', str(cm.exception.message))

    @patch('util.encrypted_fields.PKCS11Token')
    def test_get_dek_token_error(self, mock_token_model):
        """Test get_dek handles token retrieval errors."""
        mock_token = Mock()
        mock_token.get_dek_cache.return_value = None
        mock_token.get_dek.side_effect = Exception('Token error')
        mock_token_model.objects.first.return_value = mock_token

        with self.assertRaises(ValidationError) as cm:
            self.field.get_dek()
        self.assertIn('Failed to retrieve DEK', str(cm.exception.message))

    @patch.object(EncryptedTextField, 'should_encrypt')
    @patch.object(EncryptedTextField, 'get_dek')
    def test_encrypt_value_success(self, mock_get_dek, mock_should_encrypt):
        """Test successful encryption of a value."""
        mock_should_encrypt.return_value = True
        mock_get_dek.return_value = self.test_dek

        encrypted = self.field.encrypt_value(self.test_plaintext)

        self.assertIsInstance(encrypted, str)
        self.assertNotEqual(encrypted, self.test_plaintext)
        # Verify it's valid base64
        base64.b64decode(encrypted.encode('ascii'))

    @patch.object(EncryptedTextField, 'should_encrypt')
    def test_encrypt_value_no_encryption(self, mock_should_encrypt):
        """Test encrypt_value returns original value when encryption disabled."""
        mock_should_encrypt.return_value = False

        result = self.field.encrypt_value(self.test_plaintext)
        self.assertEqual(result, self.test_plaintext)

    def test_encrypt_value_empty_string(self):
        """Test encrypt_value handles empty strings."""
        result = self.field.encrypt_value('')
        self.assertEqual(result, '')

    def test_encrypt_value_none(self):
        """Test encrypt_value handles None values."""
        result = self.field.encrypt_value(None)
        self.assertIsNone(result)

    @patch.object(EncryptedTextField, 'should_encrypt')
    @patch.object(EncryptedTextField, 'get_dek')
    def test_encrypt_value_dek_error(self, mock_get_dek, mock_should_encrypt):
        """Test encrypt_value handles DEK retrieval errors."""
        mock_should_encrypt.return_value = True
        mock_get_dek.side_effect = ValidationError('DEK error')

        with self.assertRaises(ValidationError):
            self.field.encrypt_value(self.test_plaintext)

    @patch.object(EncryptedTextField, 'should_encrypt')
    @patch.object(EncryptedTextField, 'get_dek')
    def test_decrypt_value_success(self, mock_get_dek, mock_should_encrypt):
        """Test successful decryption of a value."""
        mock_should_encrypt.return_value = True
        mock_get_dek.return_value = self.test_dek

        # First encrypt the value
        encrypted = self.field.encrypt_value(self.test_plaintext)

        # Then decrypt it
        decrypted = self.field.decrypt_value(encrypted)
        self.assertEqual(decrypted, self.test_plaintext)

    @patch.object(EncryptedTextField, 'should_encrypt')
    def test_decrypt_value_no_encryption(self, mock_should_encrypt):
        """Test decrypt_value returns original value when encryption disabled."""
        mock_should_encrypt.return_value = False

        result = self.field.decrypt_value(self.test_plaintext)
        self.assertEqual(result, self.test_plaintext)

    def test_decrypt_value_empty_string(self):
        """Test decrypt_value handles empty strings."""
        result = self.field.decrypt_value('')
        self.assertEqual(result, '')

    def test_decrypt_value_none(self):
        """Test decrypt_value handles None values."""
        result = self.field.decrypt_value(None)
        self.assertIsNone(result)

    @patch.object(EncryptedTextField, 'should_encrypt')
    @patch.object(EncryptedTextField, 'get_dek')
    def test_decrypt_value_invalid_data(self, mock_get_dek, mock_should_encrypt):
        """Test decrypt_value handles invalid encrypted data."""
        mock_should_encrypt.return_value = True
        mock_get_dek.return_value = self.test_dek

        with self.assertRaises(ValidationError) as cm:
            self.field.decrypt_value('invalid_base64_data')
        self.assertIn('Failed to decrypt field value', str(cm.exception.message))

    @patch.object(EncryptedTextField, 'should_encrypt')
    @patch.object(EncryptedTextField, 'get_dek')
    def test_decrypt_value_wrong_dek(self, mock_get_dek, mock_should_encrypt):
        """Test decrypt_value handles decryption with wrong DEK."""
        mock_should_encrypt.return_value = True

        # Encrypt with one DEK
        mock_get_dek.return_value = self.test_dek
        encrypted = self.field.encrypt_value(self.test_plaintext)

        # Try to decrypt with different DEK
        wrong_dek = os.urandom(32)
        mock_get_dek.return_value = wrong_dek

        with self.assertRaises(ValidationError) as cm:
            self.field.decrypt_value(encrypted)
        self.assertIn('Failed to decrypt field value', str(cm.exception.message))

    @patch.object(EncryptedTextField, 'decrypt_value')
    def test_from_db_value(self, mock_decrypt):
        """Test from_db_value method."""
        mock_decrypt.return_value = self.test_plaintext

        result = self.field.from_db_value('encrypted_value', None, None)
        self.assertEqual(result, self.test_plaintext)
        mock_decrypt.assert_called_once_with('encrypted_value')

    def test_from_db_value_none(self):
        """Test from_db_value with None value."""
        result = self.field.from_db_value(None, None, None)
        self.assertIsNone(result)

    def test_to_python_string(self):
        """Test to_python with string value."""
        result = self.field.to_python(self.test_plaintext)
        self.assertEqual(result, self.test_plaintext)

    def test_to_python_none(self):
        """Test to_python with None value."""
        result = self.field.to_python(None)
        self.assertIsNone(result)

    def test_to_python_non_string(self):
        """Test to_python with non-string value."""
        result = self.field.to_python(123)
        self.assertEqual(result, '123')

    @patch.object(EncryptedTextField, 'encrypt_value')
    def test_get_prep_value(self, mock_encrypt):
        """Test get_prep_value method."""
        mock_encrypt.return_value = 'encrypted_value'

        result = self.field.get_prep_value(self.test_plaintext)
        self.assertEqual(result, 'encrypted_value')
        mock_encrypt.assert_called_once_with(self.test_plaintext)

    def test_get_prep_value_none(self):
        """Test get_prep_value with None value."""
        result = self.field.get_prep_value(None)
        self.assertIsNone(result)

    @patch.object(EncryptedTextField, 'encrypt_value')
    def test_get_prep_value_non_string(self, mock_encrypt):
        """Test get_prep_value with non-string value."""
        mock_encrypt.return_value = 'encrypted_123'

        result = self.field.get_prep_value(123)
        self.assertEqual(result, 'encrypted_123')
        mock_encrypt.assert_called_once_with('123')


class TestEncryptedCharField(TestCase):
    """Test cases for EncryptedCharField."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dek = os.urandom(32)
        self.test_plaintext = 'sensitive_data'

    def test_init_with_max_length(self):
        """Test field initialization with max_length parameter."""
        original_length = 50
        field = EncryptedCharField(max_length=original_length)

        # The max_length should be increased to accommodate encryption overhead
        self.assertGreater(field.max_length, original_length)

    def test_init_without_max_length(self):
        """Test field initialization without max_length parameter."""
        field = EncryptedCharField()
        self.assertIsInstance(field, EncryptedCharField)

    def test_max_length_calculation(self):
        """Test that max_length is correctly calculated for encryption overhead."""
        original_length = 100
        field = EncryptedCharField(max_length=original_length)

        # Calculate expected encrypted length
        expected_padded = ((original_length + 16 + 15) // 16) * 16
        expected_with_iv = expected_padded + 16
        expected_base64 = int(expected_with_iv * 4/3) + 4

        self.assertEqual(field.max_length, expected_base64)

    def test_raise_validation_error(self):
        """Test raise_validation_error method."""
        field = EncryptedCharField()
        with self.assertRaises(ValidationError) as cm:
            field.raise_validation_error('Test error message')
        self.assertEqual(str(cm.exception.message), 'Test error message')

    @patch('util.encrypted_fields.KeyStorageConfig')
    def test_should_encrypt_inherits_from_textfield(self, mock_config):
        """Test that EncryptedCharField should_encrypt works like EncryptedTextField."""
        mock_storage = Mock()
        mock_storage.storage_type = 'SOFTHSM'
        mock_config.objects.first.return_value = mock_storage
        mock_config.StorageType.SOFTHSM = 'SOFTHSM'
        mock_config.StorageType.PHYSICAL_HSM = 'PHYSICAL_HSM'

        field = EncryptedCharField()
        result = field.should_encrypt()
        self.assertTrue(result)

    @patch.object(EncryptedCharField, 'should_encrypt')
    @patch.object(EncryptedCharField, 'get_dek')
    def test_encrypt_decrypt_roundtrip(self, mock_get_dek, mock_should_encrypt):
        """Test complete encrypt/decrypt roundtrip for EncryptedCharField."""
        mock_should_encrypt.return_value = True
        mock_get_dek.return_value = self.test_dek

        field = EncryptedCharField(max_length=100)

        # Encrypt then decrypt
        encrypted = field.encrypt_value(self.test_plaintext)
        decrypted = field.decrypt_value(encrypted)

        self.assertEqual(decrypted, self.test_plaintext)

    @patch.object(EncryptedCharField, 'decrypt_value')
    def test_from_db_value_charfield(self, mock_decrypt):
        """Test from_db_value method for EncryptedCharField."""
        mock_decrypt.return_value = self.test_plaintext

        field = EncryptedCharField()
        result = field.from_db_value('encrypted_value', None, None)
        self.assertEqual(result, self.test_plaintext)
        mock_decrypt.assert_called_once_with('encrypted_value')

    def test_to_python_charfield(self):
        """Test to_python method for EncryptedCharField."""
        field = EncryptedCharField()

        # Test string value
        result = field.to_python(self.test_plaintext)
        self.assertEqual(result, self.test_plaintext)

        # Test None value
        result = field.to_python(None)
        self.assertIsNone(result)

        # Test non-string value
        result = field.to_python(123)
        self.assertEqual(result, '123')

    @patch.object(EncryptedCharField, 'encrypt_value')
    def test_get_prep_value_charfield(self, mock_encrypt):
        """Test get_prep_value method for EncryptedCharField."""
        mock_encrypt.return_value = 'encrypted_value'

        field = EncryptedCharField()
        result = field.get_prep_value(self.test_plaintext)
        self.assertEqual(result, 'encrypted_value')
        mock_encrypt.assert_called_once_with(self.test_plaintext)


class TestEncryptionDecryptionIntegration(TestCase):
    """Integration tests for encryption/decryption functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dek = os.urandom(32)
        self.test_values = [
            'short',
            'medium_length_text_here',
            'very_long_text_that_should_test_the_padding_and_encryption_properly_with_various_characters_123!@#$%^&*()',
            'unicode_test_äöü_中文_🚀',
            'special\nchars\tand\rlinebreaks',
        ]

    @patch.object(EncryptedTextField, 'should_encrypt')
    @patch.object(EncryptedTextField, 'get_dek')
    def test_encrypt_decrypt_various_texts(self, mock_get_dek, mock_should_encrypt):
        """Test encryption/decryption with various text inputs."""
        mock_should_encrypt.return_value = True
        mock_get_dek.return_value = self.test_dek

        field = EncryptedTextField()

        for test_value in self.test_values:
            with self.subTest(value=test_value):
                encrypted = field.encrypt_value(test_value)
                decrypted = field.decrypt_value(encrypted)
                self.assertEqual(decrypted, test_value)

    @patch.object(EncryptedTextField, 'should_encrypt')
    @patch.object(EncryptedTextField, 'get_dek')
    def test_encryption_produces_different_outputs(self, mock_get_dek, mock_should_encrypt):
        """Test that encryption produces different outputs for same input (due to random nonce)."""
        mock_should_encrypt.return_value = True
        mock_get_dek.return_value = self.test_dek

        field = EncryptedTextField()

        encrypted1 = field.encrypt_value('same_text')
        encrypted2 = field.encrypt_value('same_text')

        # Should be different due to random nonce
        self.assertNotEqual(encrypted1, encrypted2)

        # But both should decrypt to same value
        decrypted1 = field.decrypt_value(encrypted1)
        decrypted2 = field.decrypt_value(encrypted2)
        self.assertEqual(decrypted1, 'same_text')
        self.assertEqual(decrypted2, 'same_text')

    @patch.object(EncryptedTextField, 'should_encrypt')
    @patch.object(EncryptedTextField, 'get_dek')
    def test_encrypted_data_format(self, mock_get_dek, mock_should_encrypt):
        """Test that encrypted data has correct format (nonce + tag + ciphertext)."""
        mock_should_encrypt.return_value = True
        mock_get_dek.return_value = self.test_dek

        field = EncryptedTextField()
        encrypted = field.encrypt_value('test_data')

        # Decode and check structure
        combined = base64.b64decode(encrypted.encode('ascii'))

        # Should have at least 28 bytes (12 nonce + 16 tag + some ciphertext)
        self.assertGreaterEqual(len(combined), 28)

        # Nonce should be 12 bytes
        nonce = combined[:12]
        self.assertEqual(len(nonce), 12)

        # Tag should be 16 bytes
        tag = combined[12:28]
        self.assertEqual(len(tag), 16)

        # Should have some ciphertext
        ciphertext = combined[28:]
        self.assertGreater(len(ciphertext), 0)
