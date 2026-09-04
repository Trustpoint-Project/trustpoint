# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Focused tests for request operation processors."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from request.operation_processor.issue_cert import LocalCaCertificateIssueProcessor
from request.operation_processor.issue_cred import CredentialIssueProcessor
from request.request_context import BaseRequestContext, CmpCertificateRequestContext, ManualCredentialRequestContext
from workflows2.models import Workflow2Run
from workflows2.services.dispatch import DispatchOutcome


def test_credential_issue_processor_does_not_gate_on_workflow2_outcome() -> None:
    """Credential issuance should not be silently blocked by a stale workflows2 outcome."""
    context = ManualCredentialRequestContext(
        cert_requested=x509.CertificateBuilder(),
        domain=Mock(),
    )
    run = Mock()
    run.status = Workflow2Run.STATUS_AWAITING
    context.workflow2_outcome = DispatchOutcome(status='blocked', run=run, instances=[Mock()])

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    generated_key = Mock()
    generated_key.as_crypto.return_value = private_key

    with patch(
        'request.operation_processor.issue_cred.KeyGenerator.generate_private_key',
        return_value=generated_key,
    ) as mock_generate, patch(
        'request.operation_processor.issue_cred.CertificateIssueProcessor.process_operation',
    ) as mock_issue:
        CredentialIssueProcessor().process_operation(context)

    mock_generate.assert_called_once_with(domain=context.domain)
    mock_issue.assert_called_once_with(context)
    assert context.private_key is generated_key


def test_local_ca_certificate_issue_processor_tolerates_request_without_meta() -> None:
    """CMP replay contexts may carry only a minimal request object without META."""

    class _StoredRequest:
        body = b'cmp-cr-request'

    context = CmpCertificateRequestContext(
        raw_message=_StoredRequest(),
        protocol='cmp',
        operation='certification',
    )

    with patch('request.operation_processor.issue_cert.settings') as mock_settings:
        mock_settings.TP_HTTP_PORT = '80'
        url = LocalCaCertificateIssueProcessor()._get_crl_distribution_point_url(context, ca_id=7)  # noqa: SLF001

    assert url.endswith('/crl/7')


def test_credential_issue_processor_validates_context_and_request() -> None:
    """Reject contexts without the required credential issuance inputs."""
    processor = CredentialIssueProcessor()
    with pytest.raises(TypeError, match='subclass of BaseCredentialRequestContext'):
        processor.process_operation(BaseRequestContext())
    with pytest.raises(ValueError, match='certificate request'):
        processor.process_operation(ManualCredentialRequestContext(domain=Mock()))
    with pytest.raises(ValueError, match='domain'):
        processor.process_operation(ManualCredentialRequestContext(cert_requested=x509.CertificateBuilder()))


def test_credential_issue_processor_preserves_existing_key_and_propagates_issue_errors() -> None:
    """Reuse an existing key and expose errors from certificate issuance."""
    context = ManualCredentialRequestContext(
        cert_requested=x509.CertificateBuilder(), domain=Mock(), private_key=Mock(),
    )
    with patch(
        'request.operation_processor.issue_cred.CertificateIssueProcessor.process_operation',
        side_effect=RuntimeError('issue failed'),
    ) as issue:
        with pytest.raises(RuntimeError, match='issue failed'):
            CredentialIssueProcessor().process_operation(context)
    issue.assert_called_once_with(context)
