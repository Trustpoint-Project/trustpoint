"""Tests for PKI credential models."""

from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError

from pki.models.credential import (
    CertificateChainOrderModel,
    CredentialAlreadyExistsError,
    IDevIDReferenceModel,
)


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
            raise CredentialAlreadyExistsError()

    def test_error_message(self) -> None:
        """Test that error has the correct message."""
        error = CredentialAlreadyExistsError()
        assert error.messages[0] == 'Credential already exists.'


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
