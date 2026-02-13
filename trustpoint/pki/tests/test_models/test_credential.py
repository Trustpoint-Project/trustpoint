"""Tests for PKI credential models."""

from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError

from pki.models.credential import (
    PKCS11Key,
    CredentialAlreadyExistsError,
    CertificateChainOrderModel,
    IDevIDReferenceModel,
)


class TestCredentialAlreadyExistsError:
    """Test the CredentialAlreadyExistsError exception."""

    def test_error_creation(self):
        """Test creating a CredentialAlreadyExistsError."""
        error = CredentialAlreadyExistsError()
        assert isinstance(error, ValidationError)
        assert 'Credential already exists' in str(error)

    def test_error_can_be_raised(self):
        """Test that the error can be raised and caught."""
        with pytest.raises(CredentialAlreadyExistsError):
            raise CredentialAlreadyExistsError()

    def test_error_message(self):
        """Test that error has the correct message."""
        error = CredentialAlreadyExistsError()
        assert error.messages[0] == 'Credential already exists.'


@pytest.mark.django_db
class TestPKCS11Key:
    """Test the PKCS11Key model."""

    def test_create_pkcs11_key_rsa(self):
        """Test creating a PKCS11Key with RSA type."""
        key = PKCS11Key.objects.create(
            token_label='test_token', key_label='test_rsa_key', key_type=PKCS11Key.KeyType.RSA
        )
        assert key.id is not None
        assert key.token_label == 'test_token'
        assert key.key_label == 'test_rsa_key'
        assert key.key_type == PKCS11Key.KeyType.RSA
        assert key.created_at is not None

    def test_create_pkcs11_key_ec(self):
        """Test creating a PKCS11Key with EC type."""
        key = PKCS11Key.objects.create(token_label='test_token', key_label='test_ec_key', key_type=PKCS11Key.KeyType.EC)
        assert key.key_type == PKCS11Key.KeyType.EC

    def test_create_pkcs11_key_aes(self):
        """Test creating a PKCS11Key with AES type."""
        key = PKCS11Key.objects.create(
            token_label='test_token', key_label='test_aes_key', key_type=PKCS11Key.KeyType.AES
        )
        assert key.key_type == PKCS11Key.KeyType.AES

    def test_pkcs11_key_str(self):
        """Test string representation of PKCS11Key."""
        key = PKCS11Key.objects.create(token_label='my_token', key_label='my_key', key_type=PKCS11Key.KeyType.RSA)
        expected = 'my_token/my_key (rsa)'
        assert str(key) == expected

    def test_pkcs11_key_unique_together(self):
        """Test that token_label and key_label must be unique together."""
        PKCS11Key.objects.create(token_label='token1', key_label='key1', key_type=PKCS11Key.KeyType.RSA)

        # Try to create duplicate
        with pytest.raises(IntegrityError):
            PKCS11Key.objects.create(
                token_label='token1',
                key_label='key1',
                key_type=PKCS11Key.KeyType.EC,  # Different type but same labels
            )

    def test_pkcs11_key_different_tokens_same_label(self):
        """Test that same key_label can exist on different tokens."""
        key1 = PKCS11Key.objects.create(token_label='token1', key_label='shared_label', key_type=PKCS11Key.KeyType.RSA)
        key2 = PKCS11Key.objects.create(token_label='token2', key_label='shared_label', key_type=PKCS11Key.KeyType.RSA)
        assert key1.id != key2.id

    def test_pkcs11_key_type_choices(self):
        """Test that KeyType has all expected choices."""
        assert hasattr(PKCS11Key.KeyType, 'RSA')
        assert hasattr(PKCS11Key.KeyType, 'EC')
        assert hasattr(PKCS11Key.KeyType, 'AES')

        assert PKCS11Key.KeyType.RSA == 'rsa'
        assert PKCS11Key.KeyType.EC == 'ec'
        assert PKCS11Key.KeyType.AES == 'aes'

    def test_pkcs11_key_verbose_names(self):
        """Test that model has correct verbose names."""
        assert PKCS11Key._meta.verbose_name == 'PKCS#11 Private Key'
        assert PKCS11Key._meta.verbose_name_plural == 'PKCS#11 Private Keys'

    def test_pkcs11_key_field_max_lengths(self):
        """Test that fields have correct max lengths."""
        token_field = PKCS11Key._meta.get_field('token_label')
        key_field = PKCS11Key._meta.get_field('key_label')

        assert token_field.max_length == 255
        assert key_field.max_length == 255

    def test_pkcs11_key_created_at_auto(self):
        """Test that created_at is set automatically."""
        key = PKCS11Key.objects.create(token_label='test_token', key_label='test_key', key_type=PKCS11Key.KeyType.RSA)
        assert key.created_at is not None

    def test_pkcs11_key_can_be_deleted(self):
        """Test that PKCS11Key can be deleted."""
        key = PKCS11Key.objects.create(token_label='test_token', key_label='test_key', key_type=PKCS11Key.KeyType.RSA)
        key_id = key.id
        key.delete()
        assert not PKCS11Key.objects.filter(id=key_id).exists()


@pytest.mark.django_db
class TestCertificateChainOrderModel:
    """Test the CertificateChainOrderModel."""

    def test_certificate_chain_order_model_exists(self):
        """Test that CertificateChainOrderModel is importable."""
        assert CertificateChainOrderModel is not None

    def test_certificate_chain_order_has_order_field(self):
        """Test that model has an order field."""
        assert hasattr(CertificateChainOrderModel, 'order')


@pytest.mark.django_db
class TestIDevIDReferenceModel:
    """Test the IDevIDReferenceModel."""

    def test_idevid_reference_model_exists(self):
        """Test that IDevIDReferenceModel is importable."""
        assert IDevIDReferenceModel is not None

    def test_idevid_reference_model_name(self):
        """Test that model has correct name."""
        assert IDevIDReferenceModel.__name__ == 'IDevIDReferenceModel'

    def test_idevid_reference_has_meta(self):
        """Test that model has Meta class."""
        assert hasattr(IDevIDReferenceModel, '_meta')


class TestPKCS11KeyTypeEnum:
    """Test the PKCS11Key.KeyType enum."""

    def test_key_type_is_text_choices(self):
        """Test that KeyType is a TextChoices."""
        from django.db import models

        assert issubclass(PKCS11Key.KeyType, models.TextChoices)

    def test_key_type_values(self):
        """Test KeyType enum values."""
        assert PKCS11Key.KeyType.RSA.value == 'rsa'
        assert PKCS11Key.KeyType.EC.value == 'ec'
        assert PKCS11Key.KeyType.AES.value == 'aes'

    def test_key_type_labels(self):
        """Test KeyType enum labels."""
        assert PKCS11Key.KeyType.RSA.label == 'RSA'
        assert PKCS11Key.KeyType.EC.label == 'Elliptic Curve'
        assert PKCS11Key.KeyType.AES.label == 'AES'

    def test_key_type_choices(self):
        """Test that KeyType provides choices for forms."""
        choices = PKCS11Key.KeyType.choices
        assert len(choices) == 3
        assert ('rsa', 'RSA') in choices
        assert ('ec', 'Elliptic Curve') in choices
        assert ('aes', 'AES') in choices


@pytest.mark.django_db
class TestPKCS11KeyDatabaseConstraints:
    """Test database constraints and behaviors for PKCS11Key."""

    def test_token_label_required(self):
        """Test that token_label is required."""
        with pytest.raises(Exception):  # ValidationError or IntegrityError
            PKCS11Key.objects.create(token_label=None, key_label='test_key', key_type=PKCS11Key.KeyType.RSA)

    def test_key_label_required(self):
        """Test that key_label is required."""
        with pytest.raises(Exception):  # ValidationError or IntegrityError
            PKCS11Key.objects.create(token_label='test_token', key_label=None, key_type=PKCS11Key.KeyType.RSA)

    def test_key_type_required(self):
        """Test that key_type is required."""
        with pytest.raises(Exception):  # ValidationError or IntegrityError
            PKCS11Key.objects.create(token_label='test_token', key_label='test_key', key_type=None)

    def test_multiple_keys_same_token(self):
        """Test that multiple keys can exist on the same token."""
        key1 = PKCS11Key.objects.create(token_label='shared_token', key_label='key1', key_type=PKCS11Key.KeyType.RSA)
        key2 = PKCS11Key.objects.create(token_label='shared_token', key_label='key2', key_type=PKCS11Key.KeyType.EC)

        assert key1.token_label == key2.token_label
        assert key1.key_label != key2.key_label

    def test_query_by_token_label(self):
        """Test querying keys by token label."""
        PKCS11Key.objects.create(token_label='token_a', key_label='key1', key_type=PKCS11Key.KeyType.RSA)
        PKCS11Key.objects.create(token_label='token_a', key_label='key2', key_type=PKCS11Key.KeyType.EC)
        PKCS11Key.objects.create(token_label='token_b', key_label='key3', key_type=PKCS11Key.KeyType.AES)

        token_a_keys = PKCS11Key.objects.filter(token_label='token_a')
        assert token_a_keys.count() == 2

    def test_query_by_key_type(self):
        """Test querying keys by type."""
        PKCS11Key.objects.create(token_label='token1', key_label='rsa_key1', key_type=PKCS11Key.KeyType.RSA)
        PKCS11Key.objects.create(token_label='token2', key_label='rsa_key2', key_type=PKCS11Key.KeyType.RSA)
        PKCS11Key.objects.create(token_label='token3', key_label='ec_key1', key_type=PKCS11Key.KeyType.EC)

        rsa_keys = PKCS11Key.objects.filter(key_type=PKCS11Key.KeyType.RSA)
        assert rsa_keys.count() == 2

    def test_update_key_label(self):
        """Test that key_label can be updated."""
        key = PKCS11Key.objects.create(token_label='test_token', key_label='old_label', key_type=PKCS11Key.KeyType.RSA)

        key.key_label = 'new_label'
        key.save()

        refreshed = PKCS11Key.objects.get(id=key.id)
        assert refreshed.key_label == 'new_label'

    def test_update_token_label(self):
        """Test that token_label can be updated."""
        key = PKCS11Key.objects.create(token_label='old_token', key_label='test_key', key_type=PKCS11Key.KeyType.RSA)

        key.token_label = 'new_token'
        key.save()

        refreshed = PKCS11Key.objects.get(id=key.id)
        assert refreshed.token_label == 'new_token'
