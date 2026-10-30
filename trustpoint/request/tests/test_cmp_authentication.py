# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Unit tests for CMP authentication components."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.primitives import hashes
from trustpoint_core.oid import HashAlgorithm

from aoki.views import AokiServiceMixin
from pki.models import IssuedCredentialModel
from request.authentication.cmp import CmpCertConfAuthentication
from request.message_responder.cmp import CmpMessageResponder, CmpPkiConfResponder
from request.operation_processor.sign import GenericSigner
from request.request_context import CmpCertConfRequestContext


class TestCmpCertConfAuthentication:
    """Tests for certConf credential resolution in CMP authentication."""

    def test_authenticate_uses_declared_hash_alg_to_resolve_credential(self) -> None:
        """CertConf hashAlg must drive certificate-hash matching when provided."""
        cert_der = b'certificate-der-bytes'
        digest = hashes.Hash(hashes.SHA384())
        digest.update(cert_der)
        cert_hash = digest.finalize()

        context = CmpCertConfRequestContext(
            operation='certconf',
            cert_hash=cert_hash,
            cert_hash_algorithm_oid=HashAlgorithm.SHA384.dotted_string,
        )

        domain = Mock(unique_name='test-domain')
        device = Mock()
        credential = Mock()
        credential.get_certificate.return_value = Mock(public_bytes=Mock(return_value=cert_der))
        issued_cred = Mock(domain=domain, device=device, credential=credential)

        queryset = Mock()
        queryset.iterator.return_value = [issued_cred]
        with (
            patch.object(IssuedCredentialModel.objects, 'select_related', return_value=queryset),
            patch.object(AokiServiceMixin, 'get_domain_based_owner_credential', return_value=None),
        ):
            CmpCertConfAuthentication().authenticate(context)

        assert context.domain is domain
        assert context.device is device

    def test_authenticate_requires_hash_alg_for_no_implicit_hash_signature(self) -> None:
        """CertConf without hashAlg must be rejected for no-implicit-digest signature suites."""
        cert_hash = bytes.fromhex('aa' * 32)
        context = CmpCertConfRequestContext(operation='certconf', cert_hash=cert_hash)

        credential = Mock()
        credential.get_certificate.return_value = Mock()
        issued_cred = Mock(domain=Mock(unique_name='test-domain'), device=Mock(), credential=credential)

        queryset = Mock()
        queryset.select_related.return_value.first.return_value = issued_cred

        with (
            patch.object(IssuedCredentialModel.objects, 'filter', return_value=queryset),
            patch('request.cert_conf.SignatureSuite.from_certificate') as suite_mock,
        ):
            suite_mock.return_value = Mock(algorithm_identifier=Mock(hash_algorithm=None))
            with pytest.raises(ValueError, match='hashAlg is required'):
                CmpCertConfAuthentication().authenticate(context)


@pytest.mark.parametrize('has_owner', [True, False])
def test_certconf_uses_resolved_domain_owner_when_available(*, has_owner: bool) -> None:
    """Use the issued credential's domain for DevOwner signing; preserve the CA fallback."""
    domain = Mock(unique_name='tenant-domain')
    device = Mock()
    issued = Mock(domain=domain, device=device)
    owner = Mock() if has_owner else None
    context = CmpCertConfRequestContext(
        operation='certconf',
        cert_hash=b'confirmed-certificate-hash',
        domain_str='.aoki',
    )
    with (
        patch.object(CmpCertConfAuthentication, '_resolve_issued_credential_by_cert_hash', return_value=issued),
        patch.object(AokiServiceMixin, 'get_domain_based_owner_credential', return_value=owner) as resolve_owner,
    ):
        CmpCertConfAuthentication().authenticate(context)
    resolve_owner.assert_called_once_with(domain)
    assert context.domain is domain
    assert context.device is device
    assert context.owner_credential is owner
    assert context.is_aoki is has_owner


def test_certconf_without_domain_preserves_fallback() -> None:
    """A missing domain must not fabricate an AOKI owner credential."""
    context = CmpCertConfRequestContext(operation='certconf', cert_hash=b'confirmed-certificate-hash')
    with patch.object(
        CmpCertConfAuthentication,
        '_resolve_issued_credential_by_cert_hash',
        return_value=Mock(domain=None, device=None),
    ):
        CmpCertConfAuthentication().authenticate(context)
    assert context.owner_credential is None
    assert context.is_aoki is False


@pytest.mark.parametrize('has_owner', [True, False])
def test_resolved_owner_protects_pkiconf_header_and_signature(*, has_owner: bool) -> None:
    """Carry the selected trust anchor from authentication into the pkiConf signer."""
    issuer = Mock(name='independent-issuing-ca')
    owner = Mock(name='domain-devowner') if has_owner else None
    signer = owner or issuer
    device = Mock(onboarding_config=None)
    issued = Mock(domain=Mock(unique_name='tenant-domain'), device=device)
    context = CmpCertConfRequestContext(
        operation='certconf',
        cert_hash=b'confirmed-certificate-hash',
        issuer_credential=issuer,
    )
    with (
        patch.object(CmpCertConfAuthentication, '_resolve_issued_credential_by_cert_hash', return_value=issued),
        patch.object(AokiServiceMixin, 'get_domain_based_owner_credential', return_value=owner),
        patch.object(CmpPkiConfResponder, '_build_base_pkiconf_message', return_value={}) as build,
        patch.object(CmpMessageResponder, '_get_encoded_protected_part', return_value=b'protected-part'),
        patch.object(GenericSigner, 'sign', return_value=b'signature') as sign,
        patch(
            'request.message_responder.cmp.x509.SubjectKeyIdentifier.from_public_key', return_value=Mock(digest=b'ski')
        ),
        patch('request.message_responder.cmp.encoder.encode', return_value=b'pkiconf'),
    ):
        CmpCertConfAuthentication().authenticate(context)
        CmpPkiConfResponder.build_response(context)
    assert build.call_args.kwargs['issuer_cert'] is signer.get_certificate.return_value
    sign.assert_called_once_with(b'protected-part', signer)
    assert context.http_response_content == b'pkiconf'
