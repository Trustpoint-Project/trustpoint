"""Focused tests for request operation processors."""

from __future__ import annotations

from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from request.operation_processor.issue_cred import CredentialIssueProcessor
from request.request_context import ManualCredentialRequestContext
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
