# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Unit tests for CMP authentication components."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.primitives import hashes
from trustpoint_core.oid import HashAlgorithm

from pki.models import IssuedCredentialModel
from request.authentication.cmp import CmpCertConfAuthentication
from request.request_context import CmpCertConfRequestContext


class TestCmpCertConfAuthentication:
    """Tests for certConf credential resolution in CMP authentication."""

    def test_authenticate_uses_declared_hash_alg_to_resolve_credential(self) -> None:
        """certConf hashAlg must drive certificate-hash matching when provided."""
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
        with patch.object(IssuedCredentialModel.objects, 'select_related', return_value=queryset):
            CmpCertConfAuthentication().authenticate(context)

        assert context.domain is domain
        assert context.device is device

    def test_authenticate_requires_hash_alg_for_no_implicit_hash_signature(self) -> None:
        """certConf without hashAlg must be rejected for no-implicit-digest signature suites."""
        cert_hash = bytes.fromhex('aa' * 32)
        context = CmpCertConfRequestContext(operation='certconf', cert_hash=cert_hash)

        credential = Mock()
        credential.get_certificate.return_value = Mock()
        issued_cred = Mock(domain=Mock(unique_name='test-domain'), device=Mock(), credential=credential)

        queryset = Mock()
        queryset.select_related.return_value.first.return_value = issued_cred

        with patch.object(IssuedCredentialModel.objects, 'filter', return_value=queryset):
            with patch('request.authentication.cmp.SignatureSuite.from_certificate') as suite_mock:
                suite_mock.return_value = Mock(algorithm_identifier=Mock(hash_algorithm=None))
                with pytest.raises(ValueError, match='hashAlg is required'):
                    CmpCertConfAuthentication().authenticate(context)
