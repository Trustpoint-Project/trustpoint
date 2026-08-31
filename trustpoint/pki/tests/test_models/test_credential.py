# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for PKI credential models."""

from __future__ import annotations

from typing import Any

import pytest
from django.core.exceptions import ValidationError

from crypto.models import CryptoManagedKeyModel, CryptoProviderProfileModel
from pki.models.credential import (
    CertificateChainOrderModel,
    CredentialAlreadyExistsError,
    CredentialModel,
    IDevIDReferenceModel,
)
from pki.models import credential as credential_module


class TestCredentialAlreadyExistsError:
    """Test the CredentialAlreadyExistsError exception."""

    def test_error_creation(self) -> None:
        """Test creating a CredentialAlreadyExistsError."""
        error = CredentialAlreadyExistsError()
        assert isinstance(error, ValidationError)
        assert 'Credential already exists' in str(error)

    def test_error_can_be_raised(self) -> None:
        """Test that the error can be raised and caught."""
        with pytest.raises(CredentialAlreadyExistsError):
            raise CredentialAlreadyExistsError

    def test_error_message(self) -> None:
        """Test that error has the correct message."""
        error = CredentialAlreadyExistsError()
        assert error.messages[0] == 'Credential already exists.'


class TestCredentialModelBackendManagedKeys:
    """Tests for the managed-key-only credential boundary."""

    def test_signing_credentials_reject_raw_private_key_storage(self) -> None:
        """Trustpoint signing credentials must be backed by the crypto backend."""
        credential = CredentialModel(
            credential_type=CredentialModel.CredentialTypeChoice.ISSUING_CA,
            private_key='-----BEGIN PRIVATE KEY-----\nlegacy\n-----END PRIVATE KEY-----',
        )

        with pytest.raises(ValidationError, match='configured crypto backend'):
            credential.clean()


class TestCredentialModelManagedKeyExportBoundary:
    """Regression tests for managed private-key non-exportability."""

    def test_get_private_key_serializer_wraps_managed_key_facade(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Managed key serializers are created from a managed facade, never raw key bytes."""
        provider_profile = CryptoProviderProfileModel(name='test-provider', backend_kind='software')
        managed_key = CryptoManagedKeyModel(
            alias='test-managed-key',
            provider_profile=provider_profile,
            algorithm='rsa',
            public_key_fingerprint_sha256='0' * 64,
        )
        credential = CredentialModel(
            credential_type=CredentialModel.CredentialTypeChoice.ISSUING_CA,
            managed_private_key=managed_key,
        )

        facade = object()
        captured: dict[str, Any] = {}

        class FakePrivateKeySerializer:
            def __init__(self, key: object) -> None:
                captured['key'] = key

        monkeypatch.setattr(credential_module, 'managed_private_key_for_ref', lambda _: facade)
        monkeypatch.setattr(credential_module, 'PrivateKeySerializer', FakePrivateKeySerializer)

        serializer = credential.get_private_key_serializer()

        assert isinstance(serializer, FakePrivateKeySerializer)
        assert captured['key'] is facade

    def test_get_private_key_serializer_wraps_errors_for_managed_keys(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Managed-key serializer failures should be raised as RuntimeError with context."""
        provider_profile = CryptoProviderProfileModel(name='test-provider', backend_kind='software')
        managed_key = CryptoManagedKeyModel(
            alias='test-managed-key',
            provider_profile=provider_profile,
            algorithm='rsa',
            public_key_fingerprint_sha256='0' * 64,
        )
        credential = CredentialModel(
            credential_type=CredentialModel.CredentialTypeChoice.ISSUING_CA,
            managed_private_key=managed_key,
        )

        monkeypatch.setattr(credential_module, 'managed_private_key_for_ref', lambda _: (_ for _ in ()).throw(ValueError('boom')))

        with pytest.raises(RuntimeError, match='Failed to get managed private key: boom'):
            credential.get_private_key_serializer()

    def test_get_credential_serializer_uses_private_key_facade(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Credential serializer construction must not require private-key export."""
        captured_args: dict[str, Any] = {}

        class FakeCredentialSerializer:
            def __init__(self, *, private_key: Any, certificate: Any, additional_certificates: Any) -> None:
                captured_args['private_key'] = private_key
                captured_args['certificate'] = certificate
                captured_args['additional_certificates'] = additional_certificates

        class FakeSerializer:
            def __init__(self, value: Any) -> None:
                self._value = value

            def as_crypto(self) -> Any:
                return self._value

        credential = CredentialModel(credential_type=CredentialModel.CredentialTypeChoice.ISSUING_CA)

        monkeypatch.setattr(credential_module, 'CredentialSerializer', FakeCredentialSerializer)
        monkeypatch.setattr(credential, 'get_private_key', lambda: 'managed-key-facade')
        monkeypatch.setattr(credential, 'get_private_key_serializer', lambda: (_ for _ in ()).throw(AssertionError()))
        monkeypatch.setattr(credential, 'get_certificate_serializer', lambda: FakeSerializer('cert'))
        monkeypatch.setattr(credential, 'get_certificate_chain_serializer', lambda: FakeSerializer(['chain']))

        credential.get_credential_serializer()

        assert captured_args['private_key'] == 'managed-key-facade'
        assert captured_args['certificate'] == 'cert'
        assert captured_args['additional_certificates'] == ['chain']


@pytest.mark.django_db
class TestCertificateChainOrderModel:
    """Test the CertificateChainOrderModel."""

    def test_certificate_chain_order_model_exists(self) -> None:
        """Test that CertificateChainOrderModel is importable."""
        assert CertificateChainOrderModel is not None

    def test_certificate_chain_order_has_order_field(self) -> None:
        """Test that model has an order field."""
        assert hasattr(CertificateChainOrderModel, 'order')


@pytest.mark.django_db
class TestIDevIDReferenceModel:
    """Test the IDevIDReferenceModel."""

    def test_idevid_reference_model_exists(self) -> None:
        """Test that IDevIDReferenceModel is importable."""
        assert IDevIDReferenceModel is not None

    def test_idevid_reference_model_name(self) -> None:
        """Test that model has correct name."""
        assert IDevIDReferenceModel.__name__ == 'IDevIDReferenceModel'

    def test_idevid_reference_has_meta(self) -> None:
        """Test that model has Meta class."""
        assert hasattr(IDevIDReferenceModel, '_meta')
