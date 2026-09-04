"""Focused tests for CMP signing operation processing."""

from unittest.mock import Mock, patch
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature

from request.operation_processor.sign import GenericSignatureVerifier, GenericSigner, LocalCaCmpSignatureProcessor
from request.request_context import BaseRequestContext


def test_cmp_signature_processor_requires_message_and_signature() -> None:
    """Require message input before processing and signature output afterward."""
    processor = LocalCaCmpSignatureProcessor()
    with pytest.raises(ValueError, match='Data to be signed'):
        processor.process_operation(BaseRequestContext())
    with pytest.raises(ValueError, match='Signature not generated'):
        processor.get_signature()


def test_cmp_signature_processor_uses_owner_credential() -> None:
    """Prefer the authenticated owner credential when signing CMP data."""
    owner = Mock()
    context = BaseRequestContext(owner_credential=owner, issuer_credential=Mock())
    with patch('request.operation_processor.sign.GenericSigner.sign', return_value=b'signature') as sign:
        processor = LocalCaCmpSignatureProcessor(b'cmp-header')
        processor.process_operation(context)

    sign.assert_called_once_with(b'cmp-header', owner)
    assert processor.get_signature() == b'signature'


def test_cmp_signature_processor_loads_issuer_credential_and_propagates_signing_error() -> None:
    """Load a local issuer credential and preserve signing failures."""
    context = BaseRequestContext(domain=Mock())
    issuer = context.domain.get_issuing_ca_or_value_error.return_value.get_credential.return_value
    with patch('request.operation_processor.sign.GenericSigner.sign', side_effect=RuntimeError('sign failed')):
        with pytest.raises(RuntimeError, match='sign failed'):
            LocalCaCmpSignatureProcessor(b'data').process_operation(context)

    assert context.issuer_credential is issuer


def test_cmp_signature_processor_rejects_missing_issuer_credential() -> None:
    """Reject signing when the configured CA has no credential."""
    context = BaseRequestContext(domain=Mock())
    context.domain.get_issuing_ca_or_value_error.return_value.get_credential.return_value = None

    with pytest.raises(ValueError, match='does not have a credential'):
        LocalCaCmpSignatureProcessor(b'data').process_operation(context)


def test_generic_signer_signs_and_verifies_rsa_data(credential_instance: dict[str, Any]) -> None:
    """Exercise the RSA signing and verification path with a real credential."""
    credential = credential_instance['credential']
    data = b'cmp-data'

    signature = GenericSigner.sign(data, credential)

    GenericSignatureVerifier.verify(data, signature, credential.get_certificate())
    with pytest.raises(InvalidSignature):
        GenericSignatureVerifier.verify(b'changed-data', signature, credential.get_certificate())


def test_generic_signer_rejects_non_mldsa_key_for_hashless_suite(credential_instance: dict[str, Any]) -> None:
    credential = credential_instance['credential']
    suite = Mock()
    suite.algorithm_identifier.hash_algorithm = None

    with patch('request.operation_processor.sign.SignatureSuite.from_certificate', return_value=suite), pytest.raises(
        TypeError, match='hash algorithm is None'
    ):
        GenericSigner.sign(b'data', credential)


def test_generic_signer_rejects_unsupported_private_key_type(credential_instance: dict[str, Any]) -> None:
    credential = credential_instance['credential']

    with patch.object(credential, 'get_private_key', return_value=object()), pytest.raises(
        TypeError, match='unsupported private key type'
    ):
        GenericSigner.sign(b'data', credential)


def test_generic_verifier_rejects_hashless_non_mldsa_certificate(credential_instance: dict[str, Any]) -> None:
    credential = credential_instance['credential']
    suite = Mock()
    suite.algorithm_identifier.hash_algorithm = None

    with patch('request.operation_processor.sign.SignatureSuite.from_certificate', return_value=suite), pytest.raises(
        TypeError, match='hash algorithm is None'
    ):
        GenericSignatureVerifier.verify(b'data', b'signature', credential.get_certificate())
