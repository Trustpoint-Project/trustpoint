# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the auto-generated PKI."""

from unittest import mock

import pytest

from pki.auto_gen_pki import AutoGenPki
from pki.models import CaModel, CertificateModel, DomainModel
from pki.util.keys import AutoGenPkiKeyAlgorithm


@pytest.mark.parametrize(
    'key_alg',
    [AutoGenPkiKeyAlgorithm.RSA2048, AutoGenPkiKeyAlgorithm.SECP256R1],
)
def test_auto_gen_pki(key_alg: AutoGenPkiKeyAlgorithm) -> None:
    """Test that the auto-generated PKI can be correctly enabled, used and disabled."""
    mock_issuing_ca = mock.MagicMock()
    mock_issuing_ca.pk = 1
    mock_issuing_ca.credential.certificate.certificate_status = CertificateModel.CertificateStatus.REVOKED
    mock_issuing_ca.is_active = False
    mock_domain = mock.MagicMock()
    mock_domain.is_active = False

    mock_issued_credential = mock.MagicMock()
    mock_issued_credential.credential.certificate.certificate_status = CertificateModel.CertificateStatus.OK

    def mock_get_auto_gen_pki(key_alg: AutoGenPkiKeyAlgorithm | None = None) -> mock.MagicMock | None:
        del key_alg
        if not hasattr(mock_get_auto_gen_pki, 'enabled') or not mock_get_auto_gen_pki.enabled:
            return None
        return mock_issuing_ca

    def disable_auto_gen_pki() -> None:
        mock_get_auto_gen_pki.enabled = False
        mock_issued_credential.credential.certificate.certificate_status = CertificateModel.CertificateStatus.REVOKED
        mock_domain.is_active = False

    with (
        mock.patch('pki.auto_gen_pki.AutoGenPki._generate_private_key', return_value=mock.MagicMock()),
        mock.patch('pki.auto_gen_pki.AutoGenPki._save_managed_issuing_ca', return_value=mock_issuing_ca),
        mock.patch('pki.models.CaModel.create_new_issuing_ca', return_value=mock_issuing_ca),
        mock.patch('pki.models.domain.DomainModel.objects.get_or_create', return_value=(mock_domain, True)),
        mock.patch('pki.models.domain.DomainModel.objects.get', return_value=mock_domain),
        mock.patch('pki.models.CaModel.objects.get', return_value=mock_issuing_ca),
        mock.patch('pki.auto_gen_pki.AutoGenPki.get_auto_gen_pki', mock_get_auto_gen_pki),
        mock.patch(
            'pki.util.x509.CertificateGenerator.create_issuing_ca',
            return_value=(mock.MagicMock(), mock.MagicMock()),
        ),
        mock.patch('pki.auto_gen_pki.AutoGenPki.disable_auto_gen_pki', side_effect=disable_auto_gen_pki),
    ):
        # Check that the auto-generated PKI is disabled by default
        assert AutoGenPki.get_auto_gen_pki() is None

        # Enable the auto-generated PKI
        AutoGenPki.enable_auto_gen_pki(key_alg=key_alg)
        mock_get_auto_gen_pki.enabled = True

        # Check that the auto-generated PKI is enabled
        issuing_ca = AutoGenPki.get_auto_gen_pki()
        assert issuing_ca is not None

        # Use the auto-generated PKI domain to issue a domain credential to a new device
        try:
            domain = DomainModel.objects.get(unique_name='AutoGenPKI')
        except DomainModel.DoesNotExist:
            pytest.fail('Auto-generated PKI domain was not created')
        issued_credential = mock_issued_credential
        assert issued_credential.credential.certificate.certificate_status == CertificateModel.CertificateStatus.OK

        # Disable the auto-generated PKI
        AutoGenPki.disable_auto_gen_pki()

        # Check that the issued credential has been revoked
        assert issued_credential.credential.certificate.certificate_status == CertificateModel.CertificateStatus.REVOKED

        # Check that the issuing CA has been revoked and set as inactive
        issuing_ca = CaModel.objects.get(pk=issuing_ca.pk)  # reload from DB
        assert issuing_ca.credential.certificate.certificate_status == CertificateModel.CertificateStatus.REVOKED
        assert not issuing_ca.is_active

        # Check that the auto-generated PKI is disabled (this checks that the Issuing CA has been renamed)
        assert AutoGenPki.get_auto_gen_pki() is None

        # Check that the domain has been set as inactive
        domain = DomainModel.objects.get(unique_name='AutoGenPKI')
        assert not domain.is_active


@pytest.mark.parametrize(
    ('key_alg', 'expected_key_type'),
    [
        (AutoGenPkiKeyAlgorithm.RSA2048, 'RSA-2048'),
        (AutoGenPkiKeyAlgorithm.RSA4096, 'RSA-4096'),
        (AutoGenPkiKeyAlgorithm.SECP256R1, 'ECC-SECP256R1'),
        (AutoGenPkiKeyAlgorithm.MLDSA44, 'MLDSA-44'),
        (AutoGenPkiKeyAlgorithm.MLDSA65, 'MLDSA-65'),
        (AutoGenPkiKeyAlgorithm.MLDSA87, 'MLDSA-87'),
    ],
)
def test_legacy_algorithm_normalizes_to_shared_key_type(key_alg: AutoGenPkiKeyAlgorithm, expected_key_type: str) -> None:
    """Legacy AutoGen callers normalize to the shared key-generation service format."""
    assert AutoGenPki._normalize_key_type(key_alg) == expected_key_type


def test_key_spec_for_unknown_algorithm_rejects_invalid_value() -> None:
    """Unknown AutoGenPKI choices fail before backend interaction."""
    with pytest.raises(ValueError, match='Unsupported'):
        AutoGenPki._generate_private_key('invalid', 'test-key')
