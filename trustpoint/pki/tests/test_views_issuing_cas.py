"""Tests for PKI issuing CA views."""

from unittest.mock import Mock, call, patch

from pki.views.issuing_cas import IssuingCaRequestCertCmpView


def _mock_certificate(subject: bytes = b'subject', issuer: bytes = b'issuer') -> Mock:
    """Return a certificate-like mock with public subject and issuer bytes."""
    cert = Mock()
    cert.subject.public_bytes.return_value = subject
    cert.issuer.public_bytes.return_value = issuer
    return cert


def test_find_existing_ca_for_certificate_prefers_keyless_match() -> None:
    """The lookup should return the keyless CA match before checking credential CAs."""
    cert = _mock_certificate()
    keyless_ca = Mock()
    keyless_queryset = Mock()
    keyless_queryset.first.return_value = keyless_ca

    with patch('pki.views.issuing_cas.CaModel.objects.filter', return_value=keyless_queryset) as filter_mock:
        result = IssuingCaRequestCertCmpView()._find_existing_ca_for_certificate(cert)

    assert result is keyless_ca
    filter_mock.assert_called_once_with(
        certificate__subject_public_bytes=b'subject'.hex().upper(),
        certificate__issuer_public_bytes=b'issuer'.hex().upper(),
    )


def test_find_existing_ca_for_certificate_falls_back_to_credential_match() -> None:
    """The lookup should check credential-backed CAs when no keyless CA matches."""
    cert = _mock_certificate()
    credential_ca = Mock()
    keyless_queryset = Mock()
    keyless_queryset.first.return_value = None
    credential_queryset = Mock()
    credential_queryset.first.return_value = credential_ca

    with patch(
        'pki.views.issuing_cas.CaModel.objects.filter',
        side_effect=[keyless_queryset, credential_queryset],
    ) as filter_mock:
        result = IssuingCaRequestCertCmpView()._find_existing_ca_for_certificate(cert)

    assert result is credential_ca
    assert filter_mock.call_args_list == [
        call(
            certificate__subject_public_bytes=b'subject'.hex().upper(),
            certificate__issuer_public_bytes=b'issuer'.hex().upper(),
        ),
        call(
            credential__certificate__subject_public_bytes=b'subject'.hex().upper(),
            credential__certificate__issuer_public_bytes=b'issuer'.hex().upper(),
        ),
    ]
