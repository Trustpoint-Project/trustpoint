# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for synchronous certificate issuance through a remote CMP CA (Trustpoint as RA)."""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pki.models import CaModel
from request.clients.cmp_client import CmpClientError
from request.message_builder.cmp import CmpMessageBuilder
from request.operation_processor.issue_cert import RemoteCaCertificateIssueProcessor
from request.request_context import CmpCertificateRequestContext

PATCH_BASE = 'request.operation_processor.issue_cert'


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])


def _make_ca(cn: str = 'Upstream Root') -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _issue(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    public_key: object,
    *,
    is_ca: bool = False,
    subject: str = 'validated-device',
    dns_names: tuple[str, ...] | None = ('validated.example.test',),
) -> x509.Certificate:
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(ca_cert.subject)
        .public_key(public_key)  # type: ignore[arg-type]
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=10))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if dns_names is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names]), critical=False,
        )
    return builder.sign(ca_key, hashes.SHA256())


def _truststore(*certs: x509.Certificate) -> Mock:
    entries = [Mock(certificate=Mock(get_certificate_serializer=Mock(return_value=Mock(as_crypto=Mock(return_value=c)))))
               for c in certs]
    store = Mock()
    store.truststoreordermodel_set.order_by.return_value = entries
    return store


class _Env:
    def __init__(self) -> None:
        self.ca_key, self.ca_cert = _make_ca()
        self.device_key = ec.generate_private_key(ec.SECP256R1())
        self.device_pub = self.device_key.public_key()
        self.ca = Mock(unique_name='ra', remote_host='cmp.example.test', remote_port=8443, remote_path='/cmp/x',
                       cmp_sender_kid=42,
                       ca_type=CaModel.CaTypeChoice.REMOTE_CMP_RA, chain_truststore=None)
        self.ca.no_onboarding_config = Mock(cmp_shared_secret='s3cret', trust_store=_truststore(self.ca_cert))  # noqa: S106
        builder = (
            x509.CertificateBuilder()
            .subject_name(_name('validated-device'))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('validated.example.test')]), critical=False)
        )
        self.context = CmpCertificateRequestContext(
            device=Mock(common_name='dev'),
            domain=Mock(issuing_ca=self.ca, unique_name='dom'),
            cert_requested=x509.CertificateBuilder().public_key(self.device_pub),
            cert_requested_profile_validated=builder,
            cmp_body_type='ir',
        )

    def run(self, client_result: object = None, side_effect: Exception | None = None) -> Mock:
        if client_result is None:
            client_result = (_issue(self.ca_key, self.ca_cert, self.device_pub), [])
        with patch(f'{PATCH_BASE}.CmpClient') as client_class, patch(f'{PATCH_BASE}.CredentialSaver') as saver, patch(
            f'{PATCH_BASE}.AuditLog.create_entry'
        ), patch.object(
            RemoteCaCertificateIssueProcessor, '_get_keyless_issuer_credential', return_value=Mock(name='issuer'),
        ), patch.object(
            RemoteCaCertificateIssueProcessor, '_get_credential_type_for_template', return_value=(None, 'Profile')
        ):
            client_class.return_value.send_and_extract_certificate.side_effect = side_effect
            client_class.return_value.send_and_extract_certificate.return_value = client_result
            try:
                RemoteCaCertificateIssueProcessor(ca_type='cmp').process_operation(self.context)
            finally:
                self.client_class = client_class
                self.saver = saver
        return client_class


def _sent(env: _Env) -> tuple[CmpCertificateRequestContext, object, dict]:
    args, kwargs = env.client_class.return_value.send_and_extract_certificate.call_args
    return env.client_class.call_args[0][0], args[0], kwargs


def test_upstream_path_gets_profile_for_trustpoint_style_paths() -> None:
    path = RemoteCaCertificateIssueProcessor._upstream_cmp_path  # noqa: SLF001
    assert path('/.well-known/cmp/p/dom/certification', 'tls_server') == '/.well-known/cmp/p/dom/tls_server/certification'
    assert path('/cmp/x', 'tls_server') == '/cmp/x'
    assert path('/.well-known/cmp/p/dom/certification', None) == '/.well-known/cmp/p/dom/certification'


def test_builder_ra_verified_pop_without_private_key() -> None:
    context = CmpCertificateRequestContext(request_data={
        'subject': _name('x'), 'public_key': ec.generate_private_key(ec.SECP256R1()).public_key(),
        'recipient_name': 'CN=ca', 'proof_of_possession': 'ra_verified',
    })
    CmpMessageBuilder().build(context)
    body = context.parsed_message['body']
    assert body.getName() == 'cr'
    popo = body['cr'][0]['popo']
    assert popo.getName() == 'raVerified'


def test_builder_signature_pop_unchanged() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    context = CmpCertificateRequestContext(request_data={
        'subject': _name('x'), 'public_key': key.public_key(), 'private_key': key, 'recipient_name': 'CN=ca',
    })
    CmpMessageBuilder().build(context)
    assert context.parsed_message['body']['cr'][0]['popo'].getName() == 'signature'


@pytest.mark.parametrize('body_type', ['ir', 'cr'])
def test_upstream_request_is_always_cr_with_shared_secret(body_type: str) -> None:
    env = _Env()
    env.context.cmp_body_type = body_type
    env.run()
    upstream, message, kwargs = _sent(env)
    assert message['body'].getName() == 'cr'
    assert message['body']['cr'][0]['popo'].getName() == 'raVerified'
    assert kwargs == {'add_shared_secret_protection': True}
    assert (upstream.cmp_server_host, upstream.cmp_server_port, upstream.cmp_server_path) == (
        'cmp.example.test', 8443, '/cmp/x')
    assert upstream.cmp_shared_secret == 's3cret'  # noqa: S105


def test_upstream_uses_new_transaction_and_validated_request() -> None:
    env = _Env()
    env.context.cmp_transaction_id = 'original'
    env.run()
    upstream, message, _ = _sent(env)
    assert upstream.request_data['public_key'] is env.device_pub
    assert upstream.request_data['subject'].rfc4514_string() == 'CN=validated-device'
    assert [e.oid for e in upstream.request_data['extensions']] == [x509.OID_SUBJECT_ALTERNATIVE_NAME]
    template = message['body']['cr'][0]['certReq']['certTemplate']
    spki = env.device_pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    key_bits = template['publicKey']['subjectPublicKey']
    assert int(key_bits).to_bytes(len(spki), 'big') == spki
    assert bytes(message['header']['transactionID'])
    assert bytes(message['header']['senderKID']) == b'42'


def test_success_saves_credential_and_populates_context() -> None:
    env = _Env()
    env.run()
    env.saver.return_value.save_remote_keyless_credential.assert_called_once()
    assert env.context.issued_certificate is not None
    assert env.context.issued_certificate_chain == [env.ca_cert]
    assert env.context.issuer_credential is not None


def test_success_accepts_intermediate_from_extra_certs() -> None:
    env = _Env()
    inter_key, inter_cert = _make_ca('Inter')
    # Re-sign the intermediate with the root so it chains.
    now = datetime.now(UTC)
    inter_cert = (
        x509.CertificateBuilder().subject_name(inter_cert.subject).issuer_name(env.ca_cert.subject)
        .public_key(inter_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(env.ca_key, hashes.SHA256())
    )
    env.run((_issue(inter_key, inter_cert, env.device_pub), [inter_cert]))
    assert env.context.issued_certificate is not None


def test_mismatching_public_key_is_rejected() -> None:
    env = _Env()
    other = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(ValueError, match='public key does not match'):
        env.run((_issue(env.ca_key, env.ca_cert, other), []))
    env.saver.return_value.save_remote_keyless_credential.assert_not_called()


def test_changed_subject_is_rejected() -> None:
    env = _Env()
    with pytest.raises(TypeError, match='changed the certificate subject'):
        env.run((_issue(env.ca_key, env.ca_cert, env.device_pub, subject='other-device'), []))
    env.saver.return_value.save_remote_keyless_credential.assert_not_called()


@pytest.mark.parametrize(
    ('dns_names', 'message'),
    [(None, 'removed required extension'), (('other.example.test',), 'changed security-critical extension')],
)
def test_changed_or_missing_san_is_rejected(dns_names: tuple[str, ...] | None, message: str) -> None:
    env = _Env()
    with pytest.raises(ValueError, match=message):
        env.run((_issue(env.ca_key, env.ca_cert, env.device_pub, dns_names=dns_names), []))
    env.saver.return_value.save_remote_keyless_credential.assert_not_called()


def test_ca_certificate_is_rejected() -> None:
    env = _Env()
    with pytest.raises(ValueError, match='CA certificate'):
        env.run((_issue(env.ca_key, env.ca_cert, env.device_pub, is_ca=True), []))


def test_untrusted_chain_is_rejected() -> None:
    env = _Env()
    rogue_key, rogue_cert = _make_ca('Rogue')
    with pytest.raises(ValueError, match='does not chain'):
        env.run((_issue(rogue_key, rogue_cert, env.device_pub), []))
    assert env.context.issued_certificate is None


def test_upstream_failure_is_reported_clearly() -> None:
    env = _Env()
    with pytest.raises(ValueError, match='Upstream CMP enrollment failed'):
        env.run(side_effect=CmpClientError('connection refused'))
    env.saver.return_value.save_remote_keyless_credential.assert_not_called()


def test_waiting_response_is_rejected() -> None:
    env = _Env()
    with pytest.raises(ValueError, match='only synchronous issuance'):
        env.run(side_effect=CmpClientError('Certificate issuance failed with status 3: waiting'))


@pytest.mark.parametrize('attribute', ['remote_host', 'remote_port', 'remote_path'])
def test_incomplete_configuration_is_rejected(attribute: str) -> None:
    env = _Env()
    setattr(env.ca, attribute, None)
    with pytest.raises(ValueError, match='is not configured'):
        env.run()
