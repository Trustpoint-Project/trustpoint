"""Tests for encrypted field wrappers over the app-secret subsystem."""

from unittest.mock import patch

import pytest
from django.core.exceptions import ValidationError
from django.test import TestCase

from util.encrypted_fields import EncryptedCharField, EncryptedTextField


class TestEncryptedTextField(TestCase):
    """Test cases for EncryptedTextField."""

    def setUp(self) -> None:
        self.field = EncryptedTextField()
        self.test_plaintext = 'sensitive_data_123'

    def test_raise_validation_error(self) -> None:
        with pytest.raises(ValidationError) as cm:
            self.field.raise_validation_error('Test error message')
        assert str(cm.value.message) == 'Test error message'

    @patch('util.encrypted_fields.encrypt_app_secret', return_value='tpsec:v1:encrypted')
    def test_encrypt_value_success(self, mock_encrypt) -> None:
        encrypted = self.field.encrypt_value(self.test_plaintext)
        self.assertEqual(encrypted, 'tpsec:v1:encrypted')
        mock_encrypt.assert_called_once_with(self.test_plaintext)

    def test_encrypt_value_empty_string(self) -> None:
        self.assertEqual(self.field.encrypt_value(''), '')

    def test_encrypt_value_none(self) -> None:
        self.assertIsNone(self.field.encrypt_value(None))

    @patch('util.encrypted_fields.encrypt_app_secret', side_effect=RuntimeError('boom'))
    def test_encrypt_value_wraps_service_errors(self, _mock_encrypt) -> None:
        with self.assertRaises(ValidationError) as cm:
            self.field.encrypt_value(self.test_plaintext)
        self.assertIn('Failed to encrypt field value', str(cm.exception.message))

    @patch('util.encrypted_fields.decrypt_app_secret', return_value='plaintext')
    def test_decrypt_value_success(self, mock_decrypt) -> None:
        decrypted = self.field.decrypt_value('tpsec:v1:encrypted')
        self.assertEqual(decrypted, 'plaintext')
        mock_decrypt.assert_called_once_with('tpsec:v1:encrypted')

    def test_decrypt_value_empty_string(self) -> None:
        self.assertEqual(self.field.decrypt_value(''), '')

    def test_decrypt_value_none(self) -> None:
        self.assertIsNone(self.field.decrypt_value(None))

    @patch('util.encrypted_fields.decrypt_app_secret', side_effect=RuntimeError('boom'))
    def test_decrypt_value_wraps_service_errors(self, _mock_decrypt) -> None:
        with self.assertRaises(ValidationError) as cm:
            self.field.decrypt_value('tpsec:v1:encrypted')
        self.assertIn('Failed to decrypt field value', str(cm.exception.message))

    @patch.object(EncryptedTextField, 'decrypt_value', return_value='plaintext')
    def test_from_db_value(self, mock_decrypt) -> None:
        result = self.field.from_db_value('tpsec:v1:encrypted', None, None)
        self.assertEqual(result, 'plaintext')
        mock_decrypt.assert_called_once_with('tpsec:v1:encrypted')

    def test_from_db_value_none(self) -> None:
        self.assertIsNone(self.field.from_db_value(None, None, None))

    def test_to_python(self) -> None:
        self.assertEqual(self.field.to_python(self.test_plaintext), self.test_plaintext)
        self.assertIsNone(self.field.to_python(None))
        self.assertEqual(self.field.to_python(42), '42')

    @patch.object(EncryptedTextField, 'encrypt_value', return_value='tpsec:v1:encrypted')
    def test_get_prep_value(self, mock_encrypt) -> None:
        result = self.field.get_prep_value(self.test_plaintext)
        self.assertEqual(result, 'tpsec:v1:encrypted')
        mock_encrypt.assert_called_once_with(self.test_plaintext)


class TestEncryptedCharField(TestCase):
    """Test cases for EncryptedCharField."""

    def test_initialization_preserves_plaintext_max_length(self) -> None:
        field = EncryptedCharField(max_length=128)
        self.assertEqual(field._plaintext_max_length, 128)

    def test_calculate_encrypted_length_exceeds_plaintext_length(self) -> None:
        encrypted_length = EncryptedCharField._calculate_encrypted_length(128)
        self.assertGreater(encrypted_length, 128)

    def test_deconstruct_returns_plaintext_length(self) -> None:
        field = EncryptedCharField(max_length=128)
        _name, _path, _args, kwargs = field.deconstruct()
        self.assertEqual(kwargs['max_length'], 128)

    def test_db_type_uses_encrypted_length(self) -> None:
        field = EncryptedCharField(max_length=128)
        self.assertEqual(field.db_type(None), f'varchar({field._calculate_encrypted_length(128)})')

    @patch('util.encrypted_fields.encrypt_app_secret', return_value='tpsec:v1:encrypted')
    @patch('util.encrypted_fields.decrypt_app_secret', return_value='plaintext')
    def test_round_trip_uses_service(self, mock_decrypt, mock_encrypt) -> None:
        field = EncryptedCharField(max_length=100)
        encrypted = field.encrypt_value('plaintext')
        decrypted = field.decrypt_value(encrypted)
        self.assertEqual(encrypted, 'tpsec:v1:encrypted')
        self.assertEqual(decrypted, 'plaintext')
        mock_encrypt.assert_called_once_with('plaintext')
        mock_decrypt.assert_called_once_with('tpsec:v1:encrypted')
