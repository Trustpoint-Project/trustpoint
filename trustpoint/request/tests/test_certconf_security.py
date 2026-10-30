# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for transaction-bound CMP certificate confirmation."""

# ruff: noqa: SLF001, S105, S106

from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from django.test import RequestFactory
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc4210
from trustpoint_core.oid import HashAlgorithm, HmacAlgorithm

from cmp.views import CmpRequestView
from management.models import SecurityConfig
from request.authentication.cmp import CmpSharedSecretAuthentication
from request.clients.cmp_client import CmpClient
from request.message_builder.cmp import CmpPkiHeaderBuilding
from request.message_responder.cmp import CmpErrorMessageResponder, CmpPkiConfResponder
from request.request_context import CmpCertConfRequestContext
from request.security_hardening import _certconf_hash_algorithm, authenticate_cmp_request


def _certificate(digest: hashes.HashAlgorithm | None) -> x509.Certificate:
    key = ed25519.Ed25519PrivateKey.generate() if digest is None else ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'CMP confirmation')])
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, digest)
    )


def _confirmation(
    certificate: x509.Certificate, digest: hashes.HashAlgorithm, algorithm_oid: str | None = None,
) -> tuple[CmpCertConfRequestContext, Mock]:
    message = rfc4210.PKIMessage()
    header = message['header']
    header['pvno'] = 3 if algorithm_oid else 2
    header['sender']['rfc822Name'] = 'device@example.test'
    header['recipient']['rfc822Name'] = 'ca@example.test'
    header['transactionID'] = b'transaction-id'
    header['senderNonce'] = b'client-nonce'
    header['recipNonce'] = b'server-nonce'
    message['header'] = CmpPkiHeaderBuilding._prepare_protection_algorithm_pbm(
        header, hmac_algorithm=HmacAlgorithm.HMAC_SHA256,
    )
    cert_hash = certificate.fingerprint(digest)
    message['body']['certConf'][0]['certHash'] = cert_hash
    message['body']['certConf'][0]['certReqId'] = 0
    context = CmpCertConfRequestContext(
        parsed_message=message,
        cert_hash=cert_hash,
        cert_hash_algorithm_oid=algorithm_oid,
        cert_req_id=0,
        cmp_shared_secret='test-secret',
        cmp_server_host='example.test',
        issuer_credential=Mock(get_certificate=Mock(return_value=certificate)),
    )
    CmpClient(context)._add_protection_shared_secret(message)
    context.cmp_shared_secret = None
    transaction = Mock(
        cert_req_id=0,
        device=Mock(onboarding_config=None, no_onboarding_config=Mock(cmp_shared_secret='test-secret')),
        domain=Mock(),
    )
    transaction.final_certificate.get_certificate_serializer.return_value.as_crypto.return_value = certificate
    return context, transaction


@pytest.mark.parametrize('digest_type', [hashes.SHA256, hashes.SHA384, hashes.SHA512])
def test_implicit_certconf_digest_authenticates_and_protects_pkiconf(digest_type: type[hashes.HashAlgorithm]) -> None:
    """OpenSSL-style certConf must use the issued signature digest, independently of PBM."""
    SecurityConfig.objects.create()
    certificate = _certificate(digest_type())
    context, transaction = _confirmation(certificate, digest_type())
    with patch('request.security_hardening.validate_cmp_transaction_freshness', return_value=transaction):
        authenticate_cmp_request(context)

    assert context.device is transaction.device
    assert context.cmp_shared_secret == 'test-secret'
    CmpPkiConfResponder.build_response(context)
    response, remainder = decoder.decode(context.http_response_content, asn1Spec=rfc4210.PKIMessage())
    assert not remainder
    assert response['body'].getName() == 'pkiconf'
    CmpSharedSecretAuthentication._verify_protection_shared_secret(response, 'test-secret')


def test_explicit_certconf_digest_overrides_signature_digest() -> None:
    """CMP 2021 hashAlg can explicitly select a different allowed digest."""
    SecurityConfig.objects.create()
    certificate = _certificate(hashes.SHA384())
    context, transaction = _confirmation(certificate, hashes.SHA512(), HashAlgorithm.SHA512.dotted_string)
    with patch('request.security_hardening.validate_cmp_transaction_freshness', return_value=transaction):
        authenticate_cmp_request(context)
    assert context.cmp_shared_secret == 'test-secret'


def test_certconf_requires_explicit_digest_for_eddsa() -> None:
    """A signature without an implicit digest requires hashAlg."""
    certificate = _certificate(None)
    with pytest.raises(ValueError, match='hashAlg is required'):
        _certconf_hash_algorithm(CmpCertConfRequestContext(), certificate)
    context = CmpCertConfRequestContext(cert_hash_algorithm_oid=HashAlgorithm.SHA512.dotted_string)
    assert isinstance(_certconf_hash_algorithm(context, certificate), hashes.SHA512)


def test_certconf_rejects_disallowed_digest() -> None:
    """An explicit weak digest must not bypass the confirmation allowlist."""
    context = CmpCertConfRequestContext(cert_hash_algorithm_oid=HashAlgorithm.SHA1.dotted_string)
    with pytest.raises(ValueError, match='not permitted'):
        _certconf_hash_algorithm(context, _certificate(hashes.SHA384()))


@pytest.mark.parametrize('invalid_hash', [True, False])
def test_invalid_certconf_never_returns_pkiconf(*, invalid_hash: bool) -> None:
    """A hash mismatch or invalid PBM must reach the error responder without acknowledging acceptance."""
    SecurityConfig.objects.create()
    certificate = _certificate(hashes.SHA384())
    context, transaction = _confirmation(certificate, hashes.SHA256() if invalid_hash else hashes.SHA384())
    if not invalid_hash:
        transaction.device.no_onboarding_config.cmp_shared_secret = 'different-secret'

    def error_response(ctx: CmpCertConfRequestContext) -> None:
        ctx.http_response_status = HTTPStatus.BAD_REQUEST
        ctx.http_response_content = b'confirmation rejected'

    with (
        patch('cmp.views.CmpHttpRequestValidator'),
        patch('cmp.views.CmpMessageParser') as parser,
        patch('cmp.views.validate_cmp_transaction_freshness'),
        patch('request.security_hardening.validate_cmp_transaction_freshness', return_value=transaction),
        patch('cmp.views.record_cmp_response_nonce'),
        patch('cmp.views.release_delivered_workflow2_request'),
        patch.object(CmpErrorMessageResponder, 'build_response', side_effect=error_response) as error,
        patch.object(CmpPkiConfResponder, 'build_response') as confirmation,
        patch('request.message_responder.cmp.retire_onboarding_secrets') as retire,
    ):
        parser.return_value.parse.return_value = context
        response = CmpRequestView().post(RequestFactory().post('/cmp/confirmation'))

    error.assert_called_once_with(context)
    confirmation.assert_not_called()
    retire.assert_not_called()
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert context.error_details is not None
    assert context.cmp_shared_secret is None
