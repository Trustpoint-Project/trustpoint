# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the SCEP server (RFC 8894)."""

from __future__ import annotations

import datetime
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from django.test import Client
from django.utils import timezone
from management.models.audit_log import AuditLog
from pki.models import IssuedCredentialModel
from pki.models.certificate import CertificateModel, RevokedCertificateModel

from scep.handler import ScepPkiOperationHandler
from scep.protocol import cms
from scep.protocol.oids import FailInfo, MessageType, PkiStatus
from scep.tests import support
from scep.tests.conftest import ScepEnv

CN = 'scep-device'


def _post(client: Client, env: ScepEnv, body: bytes) -> Any:
    return client.post(
        env.url + '?operation=PKIOperation', data=body, content_type='application/x-pki-message', secure=True
    )


def _enroll(  # noqa: PLR0913
    client: Client,
    env: ScepEnv,
    key: Any,
    *,
    secret: str | None = None,
    tx: str = 'tx-1',
    cn: str = CN,
    csr: Any = None,
    **kwargs: Any,
) -> tuple[Any, support.CertRep | None, bytes]:
    csr = csr or support.make_csr(key, cn, secret if secret is not None else env.secret)
    signer_cert = support.make_self_signed(key, cn)
    body, nonce = support.build_request(
        signer_key=key, signer_cert=signer_cert, server_cert=env.server_cert, csr=csr, transaction_id=tx, **kwargs
    )
    response = _post(client, env, body)
    rep = support.parse_cert_rep(response.content) if response.status_code == 200 else None
    return response, rep, nonce


def _issued(rep: support.CertRep, key: Any, env: ScepEnv) -> list[x509.Certificate]:
    if isinstance(key, support.rsa.RSAPrivateKey):
        return support.decrypt_cert_rep(rep, key=key)
    return support.decrypt_cert_rep(rep, password=env.secret)


def _renew(
    client: Client, env: ScepEnv, old_key: Any, old_cert: x509.Certificate, new_key: Any, tx: str, cn: str = CN
) -> tuple[Any, support.CertRep | None, bytes]:
    csr = support.make_csr(new_key, cn)
    body, nonce = support.build_request(
        signer_key=old_key,
        signer_cert=old_cert,
        server_cert=env.server_cert,
        csr=csr,
        message_type=MessageType.RENEWAL_REQ,
        transaction_id=tx,
    )
    response = _post(client, env, body)
    rep = support.parse_cert_rep(response.content) if response.status_code == 200 else None
    return response, rep, nonce


def _assert_failure(rep: support.CertRep | None, nonce: bytes, fail_info: FailInfo | None = None) -> None:
    assert rep is not None
    assert rep.status == PkiStatus.FAILURE
    assert rep.econtent is None
    assert rep.signature_valid
    assert rep.recipient_nonce == nonce
    if fail_info is not None:
        assert rep.fail_info == fail_info


# ---------------------------------------------------------------- discovery


def test_get_ca_caps(client: Client, rsa_env: ScepEnv) -> None:
    response = client.get(rsa_env.url, {'operation': 'GetCACaps'}, secure=True)
    assert response.status_code == 200
    assert response['Content-Type'].startswith('text/plain')
    assert response.content.decode().split() == ['AES', 'POSTPKIOperation', 'Renewal', 'SCEPStandard', 'SHA-256']


def test_get_ca_cert_returns_server_and_ca_chain(client: Client, rsa_env: ScepEnv) -> None:
    response = client.get(rsa_env.url, {'operation': 'GetCACert'}, secure=True)
    assert response.status_code == 200
    assert response['Content-Type'] == 'application/x-x509-ca-ra-cert'
    ci = support.ber_decoder.decode(response.content, asn1Spec=support.rfc5652.ContentInfo())[0]
    sd = support.ber_decoder.decode(ci['content'], asn1Spec=support.rfc5652.SignedData())[0]
    assert len(sd['signerInfos']) == 0
    assert not sd['encapContentInfo']['eContent'].isValue
    certs = [
        x509.load_der_x509_certificate(support.der_encoder.encode(c['certificate'])) for c in sd['certificates']
    ]
    server = next(c for c in certs if c.subject == rsa_env.server_cert.subject)
    usage = server.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.digital_signature
    assert usage.key_encipherment
    assert not server.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    ca = next(c for c in certs if c is not server)
    assert server.issuer == ca.subject


def test_discovery_requires_https(client: Client, rsa_env: ScepEnv) -> None:
    assert client.get(rsa_env.url, {'operation': 'GetCACaps'}).status_code == 403


def test_unsupported_and_unknown_operations(client: Client, rsa_env: ScepEnv) -> None:
    assert client.get(rsa_env.url, {'operation': 'GetNextCACert'}, secure=True).status_code == 501
    assert client.get(rsa_env.url, {'operation': 'Bogus'}, secure=True).status_code == 400
    response = client.get(rsa_env.url, {'operation': 'PKIOperation', 'message': 'AAAA'}, secure=True)
    assert response.status_code == 405


def test_scep_not_permitted_by_security_config_is_not_served(client: Client, rsa_env: ScepEnv) -> None:
    from management.models import SecurityConfig  # noqa: PLC0415

    cfg = SecurityConfig.objects.first() or SecurityConfig.objects.create()
    cfg.permitted_no_onboarding_pki_protocols = [1, 4]
    cfg.save()
    assert client.get(rsa_env.url, {'operation': 'GetCACaps'}, secure=True).status_code == 404
    cfg.permitted_no_onboarding_pki_protocols = [1, 4, 64]
    cfg.save()
    assert client.get(rsa_env.url, {'operation': 'GetCACaps'}, secure=True).status_code == 200


def test_oversized_request_rejected(client: Client, rsa_env: ScepEnv) -> None:
    assert _post(client, rsa_env, b'\x00' * (cms.MAX_REQUEST_BYTES + 1)).status_code == 413


# ---------------------------------------------------------------- RSA enrollment


def test_rsa_initial_enrollment(client: Client, rsa_env: ScepEnv) -> None:
    key = support.make_key('rsa')
    response, rep, nonce = _enroll(client, rsa_env, key)
    assert response['Content-Type'] == 'application/x-pki-message'
    assert rep is not None
    assert rep.status == PkiStatus.SUCCESS
    assert rep.signature_valid
    assert rep.transaction_id == 'tx-1'
    assert rep.recipient_nonce == nonce
    assert bytes(rep.attributes['2.16.840.1.113733.1.9.5']) != nonce
    certs = _issued(rep, key, rsa_env)
    assert certs[0].public_key().public_numbers() == key.public_key().public_numbers()
    assert IssuedCredentialModel.objects.filter(device=rsa_env.device).count() == 1
    assert rsa_env.config.scep_challenge_consumed_at is not None
    assert AuditLog.objects.filter(operation_type=AuditLog.OperationType.SCEP_ENROLLMENT).count() == 1
    assert rsa_env.secret not in str(list(AuditLog.objects.values_list('details', flat=True)))


def test_rsa_renewal_with_new_key(client: Client, rsa_env: ScepEnv) -> None:
    key = support.make_key('rsa')
    _, rep, _ = _enroll(client, rsa_env, key)
    assert rep is not None
    cert = _issued(rep, key, rsa_env)[0]

    new_key = support.make_key('rsa')
    _, rep2, nonce = _renew(client, rsa_env, key, cert, new_key, 'tx-renew')
    assert rep2 is not None
    assert rep2.status == PkiStatus.SUCCESS, rep2.fail_text
    assert rep2.recipient_nonce == nonce
    renewed = support.decrypt_cert_rep(rep2, key=key)[0]
    assert renewed.public_key().public_numbers() == new_key.public_key().public_numbers()
    assert renewed.serial_number != cert.serial_number
    assert AuditLog.objects.filter(operation_type=AuditLog.OperationType.SCEP_RENEWAL).count() == 1


# ---------------------------------------------------------------- ECC


def test_ecc_enrollment_and_renewal_use_password_recipient(client: Client, ec_env: ScepEnv) -> None:
    key = support.make_key('p256')
    _, rep, nonce = _enroll(client, ec_env, key)
    assert rep is not None
    assert rep.status == PkiStatus.SUCCESS
    assert rep.recipient_nonce == nonce
    content_info = support.ber_decoder.decode(rep.econtent, asn1Spec=support.rfc5652.ContentInfo())[0]
    env = support.ber_decoder.decode(content_info['content'], asn1Spec=support.rfc5652.EnvelopedData())[0]
    assert env['recipientInfos'][0].getName() == 'pwri'
    cert = support.decrypt_cert_rep(rep, password=ec_env.secret)[0]

    new_key = support.make_key('p256')
    _, rep2, _ = _renew(client, ec_env, key, cert, new_key, 'tx-renew')
    assert rep2 is not None
    assert rep2.status == PkiStatus.SUCCESS
    renewed = support.decrypt_cert_rep(rep2, password=ec_env.secret)[0]
    assert renewed.public_key().public_numbers() == new_key.public_key().public_numbers()


def test_retained_secret_cannot_authorize_second_enrollment(client: Client, ec_env: ScepEnv) -> None:
    key = support.make_key('p256')
    _, rep, _ = _enroll(client, ec_env, key)
    assert rep is not None
    assert rep.status == PkiStatus.SUCCESS
    key2 = support.make_key('p256')
    _, rep2, nonce = _enroll(client, ec_env, key2, tx='tx-2')
    _assert_failure(rep2, nonce, FailInfo.BAD_REQUEST)
    assert IssuedCredentialModel.objects.filter(device=ec_env.device).count() == 1


def test_secret_alone_does_not_grant_renewal(client: Client, ec_env: ScepEnv) -> None:
    key = support.make_key('p256')
    _, rep, _ = _enroll(client, ec_env, key)
    assert rep is not None
    stranger_key = support.make_key('p256')
    stranger_cert = support.make_self_signed(stranger_key, CN)
    _, rep2, nonce = _renew(client, ec_env, stranger_key, stranger_cert, support.make_key('p256'), 'tx-x')
    _assert_failure(rep2, nonce, FailInfo.BAD_CERT_ID)


# ---------------------------------------------------------------- secrets


@pytest.mark.parametrize('mode', ['wrong', 'expired', 'missing'])
def test_invalid_secret_is_rejected_and_not_consumed(client: Client, rsa_env: ScepEnv, mode: str) -> None:
    secret: str | None = rsa_env.secret
    if mode == 'wrong':
        secret = 'not-the-secret'  # noqa: S105
    elif mode == 'expired':
        type(rsa_env.config).objects.filter(pk=rsa_env.config.pk).update(
            scep_challenge_expires_at=timezone.now() - datetime.timedelta(seconds=1)
        )
    key = support.make_key('rsa')
    csr = support.make_csr(key, CN, secret) if mode != 'missing' else support.make_csr(key, CN)
    _, rep, nonce = _enroll(client, rsa_env, key, csr=csr)
    _assert_failure(rep, nonce, FailInfo.BAD_REQUEST)
    assert not IssuedCredentialModel.objects.filter(device=rsa_env.device).exists()
    assert rsa_env.config.scep_challenge_consumed_at is None


def test_reset_invalidates_previous_secret(client: Client, rsa_env: ScepEnv) -> None:
    old_secret = rsa_env.secret
    rsa_env.new_authorization()
    key = support.make_key('rsa')
    _, rep, nonce = _enroll(client, rsa_env, key, csr=support.make_csr(key, CN, old_secret))
    _assert_failure(rep, nonce, FailInfo.BAD_REQUEST)
    assert rsa_env.config.scep_challenge_digest != type(rsa_env.config).scep_digest_for(old_secret)


def test_secret_of_other_device_is_bound_to_its_device_profile(client: Client, rsa_env: ScepEnv) -> None:
    assert rsa_env.config.scep_certificate_profile == rsa_env.profile
    assert rsa_env.secret not in str(rsa_env.config)
    assert rsa_env.config.scep_challenge_digest != rsa_env.secret


def test_scep_disabled_for_device_is_rejected(client: Client, rsa_env: ScepEnv) -> None:
    config = rsa_env.device.no_onboarding_config
    config.set_pki_protocols([])
    config.save()
    key = support.make_key('rsa')
    _, rep, nonce = _enroll(client, rsa_env, key)
    _assert_failure(rep, nonce, FailInfo.BAD_REQUEST)


# ---------------------------------------------------------------- malformed and unsupported input


def test_garbage_is_http_400(client: Client, rsa_env: ScepEnv) -> None:
    assert _post(client, rsa_env, b'not asn1').status_code == 400


def test_missing_transaction_attributes_is_http_400(client: Client, rsa_env: ScepEnv) -> None:
    key = support.make_key('rsa')
    for omitted in ('transactionID', 'messageType', 'senderNonce'):
        csr = support.make_csr(key, CN, rsa_env.secret)
        body, _ = support.build_request(
            signer_key=key,
            signer_cert=support.make_self_signed(key, CN),
            server_cert=rsa_env.server_cert,
            csr=csr,
            omit_attributes=(omitted,),
        )
        assert _post(client, rsa_env, body).status_code == 400


def test_invalid_signature_is_bad_message_check(client: Client, rsa_env: ScepEnv) -> None:
    key = support.make_key('rsa')
    _, rep, nonce = _enroll(client, rsa_env, key, corrupt_signature=True)
    _assert_failure(rep, nonce, FailInfo.BAD_MESSAGE_CHECK)
    assert not IssuedCredentialModel.objects.filter(device=rsa_env.device).exists()


def test_corrupt_envelope_and_csr(client: Client, rsa_env: ScepEnv) -> None:
    key = support.make_key('rsa')
    envelope = cms.encrypt_pkcs_pki_envelope(b'definitely not a csr', cms.KeyTransRecipient(rsa_env.server_cert))
    _, rep, nonce = _enroll(client, rsa_env, key, envelope=envelope)
    _assert_failure(rep, nonce, FailInfo.BAD_REQUEST)


def test_small_rsa_key_and_unsupported_curve(client: Client, rsa_env: ScepEnv) -> None:
    for kind in ('rsa1024', 'p521'):
        key = support.make_key(kind)
        _, rep, nonce = _enroll(client, rsa_env, key)
        _assert_failure(rep, nonce, FailInfo.BAD_ALG)


def test_signer_must_match_csr(client: Client, rsa_env: ScepEnv) -> None:
    key = support.make_key('rsa')
    other = support.make_key('rsa')
    csr = support.make_csr(other, CN, rsa_env.secret)
    _, rep, nonce = _enroll(client, rsa_env, key, csr=csr)
    _assert_failure(rep, nonce, FailInfo.BAD_REQUEST)
    assert rsa_env.config.scep_challenge_consumed_at is None


def test_unsupported_message_type(client: Client, rsa_env: ScepEnv) -> None:
    key = support.make_key('rsa')
    _, rep, nonce = _enroll(client, rsa_env, key, message_type=MessageType.GET_CRL)
    _assert_failure(rep, nonce, FailInfo.BAD_REQUEST)


# ---------------------------------------------------------------- renewal authorization


def _enrolled(client: Client, env: ScepEnv) -> tuple[Any, x509.Certificate]:
    key = support.make_key('rsa')
    _, rep, _ = _enroll(client, env, key)
    assert rep is not None
    return key, _issued(rep, key, env)[0]


def test_renewal_with_revoked_certificate_rejected(client: Client, rsa_env: ScepEnv) -> None:
    key, cert = _enrolled(client, rsa_env)
    model = CertificateModel.objects.get(sha256_fingerprint=cert.fingerprint(hashes.SHA256()).hex().upper())
    RevokedCertificateModel.objects.create(
        certificate=model,
        revocation_reason=RevokedCertificateModel.ReasonCode.UNSPECIFIED,
        ca=rsa_env.domain.issuing_ca,
    )
    _, rep, nonce = _renew(client, rsa_env, key, cert, support.make_key('rsa'), 'tx-r')
    _assert_failure(rep, nonce, FailInfo.BAD_REQUEST)


def test_renewal_with_unrelated_certificate_rejected(client: Client, rsa_env: ScepEnv) -> None:
    stranger = support.make_key('rsa')
    _, rep, nonce = _renew(client, rsa_env, stranger, support.make_self_signed(stranger, CN), stranger, 'tx-s')
    _assert_failure(rep, nonce, FailInfo.BAD_CERT_ID)


def test_renewal_cannot_change_identity(client: Client, rsa_env: ScepEnv) -> None:
    key, cert = _enrolled(client, rsa_env)
    _, rep, nonce = _renew(client, rsa_env, key, cert, support.make_key('rsa'), 'tx-i', cn='someone-else')
    _assert_failure(rep, nonce, FailInfo.BAD_REQUEST)


def test_renewal_with_invalid_csr_signature_independent_of_outer_signature(
    client: Client, rsa_env: ScepEnv
) -> None:
    key, cert = _enrolled(client, rsa_env)
    csr_der = bytearray(support.make_csr(support.make_key('rsa'), CN).public_bytes(serialization.Encoding.DER))
    csr_der[-5] ^= 0xFF
    body, nonce = support.build_request(
        signer_key=key,
        signer_cert=cert,
        server_cert=rsa_env.server_cert,
        csr=bytes(csr_der),
        message_type=MessageType.RENEWAL_REQ,
        transaction_id='tx-bad-csr',
    )
    rep = support.parse_cert_rep(_post(client, rsa_env, body).content)
    _assert_failure(rep, nonce)


def test_recovery_after_expiry_needs_fresh_authorization(client: Client, rsa_env: ScepEnv) -> None:
    key, cert = _enrolled(client, rsa_env)
    CertificateModel.objects.filter(sha256_fingerprint=cert.fingerprint(hashes.SHA256()).hex().upper()).update(
        not_valid_after=timezone.now() - datetime.timedelta(days=1)
    )
    _, rep, nonce = _renew(client, rsa_env, key, cert, support.make_key('rsa'), 'tx-e')
    _assert_failure(rep, nonce, FailInfo.BAD_REQUEST)
    rsa_env.new_authorization()
    new_key = support.make_key('rsa')
    _, rep2, _ = _enroll(client, rsa_env, new_key, tx='tx-fresh')
    assert rep2 is not None
    assert rep2.status == PkiStatus.SUCCESS


# ---------------------------------------------------------------- retries


def test_verified_retry_returns_same_certificate_without_issuing_again(client: Client, rsa_env: ScepEnv) -> None:
    key = support.make_key('rsa')
    csr = support.make_csr(key, CN, rsa_env.secret)
    cert_first = support.make_self_signed(key, CN)
    results = []
    for _ in range(2):
        body, nonce = support.build_request(
            signer_key=key, signer_cert=cert_first, server_cert=rsa_env.server_cert, csr=csr, transaction_id='tx-retry'
        )
        rep = support.parse_cert_rep(_post(client, rsa_env, body).content)
        assert rep.status == PkiStatus.SUCCESS
        assert rep.recipient_nonce == nonce
        results.append((nonce, support.decrypt_cert_rep(rep, key=key)[0]))
    assert results[0][0] != results[1][0]
    assert results[0][1].serial_number == results[1][1].serial_number
    assert IssuedCredentialModel.objects.filter(device=rsa_env.device).count() == 1
    assert len(rsa_env.config.scep_transactions) == 1
    assert AuditLog.objects.filter(operation_type=AuditLog.OperationType.SCEP_RETRY).count() == 1


def test_conflicting_transaction_reuse_rejected(client: Client, rsa_env: ScepEnv) -> None:
    key = support.make_key('rsa')
    _, rep, _ = _enroll(client, rsa_env, key, tx='tx-dup')
    assert rep is not None
    assert rep.status == PkiStatus.SUCCESS
    other = support.make_key('rsa')
    csr = support.make_csr(other, CN, rsa_env.secret)
    _, rep2, nonce = _enroll(client, rsa_env, other, tx='tx-dup', csr=csr)
    _assert_failure(rep2, nonce, FailInfo.BAD_REQUEST)
    assert IssuedCredentialModel.objects.filter(device=rsa_env.device).count() == 1


def test_concurrent_duplicate_is_served_as_retry(client: Client, rsa_env: ScepEnv) -> None:
    """The second of two racing identical requests loses the unique constraint and is answered as a retry."""
    key = support.make_key('rsa')
    csr = support.make_csr(key, CN, rsa_env.secret)
    signer = support.make_self_signed(key, CN)
    body, _ = support.build_request(
        signer_key=key, signer_cert=signer, server_cert=rsa_env.server_cert, csr=csr, transaction_id='tx-race'
    )
    assert support.parse_cert_rep(_post(client, rsa_env, body).content).status == PkiStatus.SUCCESS

    original = ScepPkiOperationHandler._lookup_transaction  # noqa: SLF001
    calls = {'n': 0}

    def racy(config: Any, transaction_id: str) -> Any:
        calls['n'] += 1
        return None if calls['n'] == 1 else original(config, transaction_id)

    with (
        patch.object(ScepPkiOperationHandler, '_lookup_transaction', staticmethod(racy)),
        patch('onboarding.models.ScepEnrollmentModelMixin.can_authorize_scep_enrollment', return_value=True),
    ):
        body2, _ = support.build_request(
            signer_key=key, signer_cert=signer, server_cert=rsa_env.server_cert, csr=csr, transaction_id='tx-race'
        )
        rep = support.parse_cert_rep(_post(client, rsa_env, body2).content)
    assert rep.status == PkiStatus.SUCCESS
    assert IssuedCredentialModel.objects.filter(device=rsa_env.device).count() == 1


def test_failed_issuance_does_not_consume_secret(client: Client, rsa_env: ScepEnv) -> None:
    key = support.make_key('rsa')
    with patch('scep.handler.OperationProcessor.process_operation', side_effect=RuntimeError('boom')):
        _, rep, nonce = _enroll(client, rsa_env, key)
    _assert_failure(rep, nonce)
    assert rsa_env.config.scep_challenge_consumed_at is None
    assert not rsa_env.config.scep_transactions
    _, rep2, _ = _enroll(client, rsa_env, key, tx='tx-2')
    assert rep2 is not None
    assert rep2.status == PkiStatus.SUCCESS


def test_rejection_is_audited_without_secret(client: Client, rsa_env: ScepEnv) -> None:
    key = support.make_key('rsa')
    _enroll(client, rsa_env, key, secret='wrong-secret-value')  # noqa: S106
    entry = AuditLog.objects.get(operation_type=AuditLog.OperationType.SCEP_REJECTED)
    assert 'wrong-secret-value' not in str(entry.details)
    assert 'wrong-secret-value' not in entry.target_display


# ---------------------------------------------------------------- independent verification with OpenSSL


@pytest.mark.parametrize('kind', ['rsa', 'p256'])
def test_responses_verify_and_decrypt_with_openssl(client: Client, rsa_env: ScepEnv, ec_env: ScepEnv, kind: str) -> None:
    env = rsa_env if kind == 'rsa' else ec_env
    key = support.make_key(kind)
    response, rep, _ = _enroll(client, env, key)
    assert rep is not None
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / 'rep.der').write_bytes(response.content)
        verify = subprocess.run(  # noqa: S603
            ['openssl', 'cms', '-verify', '-inform', 'DER', '-in', str(d / 'rep.der'), '-noverify', '-out', str(d / 'inner.der'), '-binary'],  # noqa: S607
            capture_output=True,
            check=False,
        )
        assert verify.returncode == 0, verify.stderr
        if kind == 'rsa':
            (d / 'k.pem').write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                )
            )
            args = ['-inkey', str(d / 'k.pem')]
        else:
            args = ['-pwri_password', env.secret]
        decrypt = subprocess.run(  # noqa: S603
            ['openssl', 'cms', '-decrypt', '-inform', 'DER', '-in', str(d / 'inner.der'), '-out', str(d / 'certs.der'), *args],  # noqa: S607
            capture_output=True,
            check=False,
        )
        assert decrypt.returncode == 0, decrypt.stderr
