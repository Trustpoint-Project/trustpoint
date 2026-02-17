"""Tests for the auto-generated PKI."""

import pytest
from unittest import mock



from management.models import KeyStorageConfig

from pki.auto_gen_pki import AutoGenPki

from pki.models import CertificateModel, DomainModel, CaModel


from pki.util.keys import AutoGenPkiKeyAlgorithm


@pytest.mark.parametrize('key_alg', [AutoGenPkiKeyAlgorithm.RSA2048, AutoGenPkiKeyAlgorithm.SECP256R1])
def test_auto_gen_pki(key_alg: AutoGenPkiKeyAlgorithm) -> None:
    """Test that the auto-generated PKI can be correctly enabled, used and disabled."""
    # Mock KeyStorageConfig.get_config() to return a config with SOFTHSM for protected CA creation
    mock_config = mock.MagicMock()
    mock_config.storage_type = KeyStorageConfig.StorageType.SOFTHSM
    mock_token = mock.MagicMock()
    mock_token.module_path = '/usr/local/lib/libpkcs11-proxy.so'
    mock_token.label = 'Trustpoint-SoftHSM'
    mock_token.slot = 0
    mock_issuing_ca = mock.MagicMock()
    mock_issuing_ca.pk = 1
    mock_issuing_ca.credential.certificate.certificate_status = CertificateModel.CertificateStatus.REVOKED
    mock_issuing_ca.is_active = False
    mock_domain = mock.MagicMock()
    mock_domain.is_active = False

    mock_issued_credential = mock.MagicMock()
    mock_issued_credential.credential.certificate.certificate_status = CertificateModel.CertificateStatus.OK

    def mock_get_auto_gen_pki(key_alg: AutoGenPkiKeyAlgorithm | None = None):
        if not hasattr(mock_get_auto_gen_pki, 'enabled') or not mock_get_auto_gen_pki.enabled:
            return None
        return mock_issuing_ca

    with (
        mock.patch.object(KeyStorageConfig, 'get_config', return_value=mock_config),
        mock.patch('pki.models.credential.PKCS11Token.objects.first', return_value=mock_token),
        mock.patch('pki.models.CaModel.create_new_issuing_ca', return_value=mock_issuing_ca),
        mock.patch('pki.models.domain.DomainModel.objects.get_or_create', return_value=(mock_domain, True)),
        mock.patch('pki.models.domain.DomainModel.objects.get', return_value=mock_domain),
        mock.patch('pki.models.CaModel.objects.get', return_value=mock_issuing_ca),
        mock.patch('pki.auto_gen_pki.AutoGenPki.get_auto_gen_pki', mock_get_auto_gen_pki),
        mock.patch('pki.util.x509.CertificateGenerator.save_issuing_ca', return_value=mock_issuing_ca),
        mock.patch(
            'pki.util.x509.CertificateGenerator.create_issuing_ca', return_value=(mock.MagicMock(), mock.MagicMock())
        ),
        mock.patch(
            'pki.auto_gen_pki.AutoGenPki.disable_auto_gen_pki',
            side_effect=lambda: (
                setattr(mock_get_auto_gen_pki, 'enabled', False),
                setattr(
                    mock_issued_credential.credential.certificate,
                    'certificate_status',
                    CertificateModel.CertificateStatus.REVOKED,
                ),
                setattr(mock_domain, 'is_active', False),
            ),
        ),
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
