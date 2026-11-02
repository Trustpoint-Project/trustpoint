# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Signed CMP CA discovery through the HTTP request pipeline."""

import os
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.test import RequestFactory
from django.urls import resolve
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_modules import rfc4210

from cmp.models import CmpTransactionModel
from management.models import SecurityConfig
from pki.models import IssuedCredentialModel
from request.message_builder.cmp import CmpPkiHeaderBuilding
from request.message_responder.cmp import CmpGeneralResponder
from request.operation_processor.cmp_general import CA_CERTS_OID
from request.request_context import CmpGeneralRequestContext
from request.tests.test_cmp_key_update import _assert_signature, _sign


@pytest.fixture
def material(domain_credential_cmp_onboarding, rsa_private_key):
    SecurityConfig.objects.get_or_create()
    issued = domain_credential_cmp_onboarding['domain_credential']
    return issued, issued.credential.get_certificate(), rsa_private_key


def _request(certificate, key, *, oid=CA_CERTS_OID):
    message = rfc4210.PKIMessage()
    header = message['header']
    header['pvno'] = 2
    header['recipient'] = CmpPkiHeaderBuilding._build_general_name_from_dn(certificate.issuer.rfc4514_string())
    header['transactionID'] = os.urandom(16)
    message['body']['genm'][0]['infoType'] = oid
    return _sign(message, certificate, key)


def _post(message, path):
    request = RequestFactory().post(path, encoder.encode(message), content_type='application/pkixcmp')
    match = resolve(path)
    response = match.func(request, *match.args, **match.kwargs)
    assert response.status_code == 200, response.content
    assert response['Content-Type'] == 'application/pkixcmp'
    result, remainder = decoder.decode(response.content, asn1Spec=rfc4210.PKIMessage())
    assert not remainder
    return result


def _certificates(message):
    assert message['body'].getName() == 'gen'
    entries = message['body']['gen']
    assert len(entries) == 1
    assert str(entries[0]['infoType']) == CA_CERTS_OID
    value, remainder = decoder.decode(
        entries[0]['infoValue'].asOctets(),
        asn1Spec=univ.SequenceOf(componentType=rfc4210.CMPCertificate()),
    )
    assert not remainder
    return [x509.load_der_x509_certificate(encoder.encode(cert)) for cert in value]


@pytest.mark.parametrize(
    'layout',
    [
        '/.well-known/cmp/p/{domain}/getcacerts',
        '/.well-known/cmp/p/{domain}/getcacerts/',
        '/.well-known/cmp/p/{domain}',
        '/.well-known/cmp/getcacerts',
        '/.well-known/cmp/',
        '/.well-known/cmp/p/{domain}~domain_credential/getcacerts',
    ],
)
def test_ca_certificates_returns_signed_genp(material, layout):
    issued, certificate, key = material
    message = _request(certificate, key)
    path = layout.format(domain=issued.domain.unique_name)
    credentials_before = IssuedCredentialModel.objects.count()
    with patch('request.operation_processor.cmp_certificate_request.CertificateIssueProcessor') as issuer:
        response = _post(message, path)
    issuer.assert_not_called()
    ca = issued.domain.issuing_ca.credential.get_certificate()
    assert _certificates(response) == [ca]
    _assert_signature(response, ca)
    assert response['header']['transactionID'] == message['header']['transactionID']
    assert response['header']['recipNonce'].asOctets() == message['header']['senderNonce'].asOctets()
    assert len(response['header']['senderNonce'].asOctets()) == 16
    assert not response['header']['generalInfo'].hasValue()
    assert x509.load_der_x509_certificate(encoder.encode(response['extraCerts'][0])) == ca
    assert IssuedCredentialModel.objects.count() == credentials_before
    assert not CmpTransactionModel.objects.exists()


@pytest.mark.parametrize('invalid', ['unknown_oid', 'value', 'multiple', 'signature', 'unprotected'])
def test_ca_certificates_rejects_invalid_requests(material, invalid):
    issued, certificate, key = material
    message = _request(certificate, key, oid='1.2.3.4' if invalid == 'unknown_oid' else CA_CERTS_OID)
    if invalid == 'value':
        message['body']['genm'][0]['infoValue'] = encoder.encode(univ.Null(''))
    elif invalid == 'multiple':
        message['body']['genm'][1]['infoType'] = CA_CERTS_OID
    message = _sign(message, certificate, key)
    if invalid == 'signature':
        message['protection'] = message['protection'].clone(value=univ.BitString.fromOctetString(b'invalid'))
    elif invalid == 'unprotected':
        message.setComponentByName('protection', univ.noValue)
    response = _post(message, f'/.well-known/cmp/p/{issued.domain.unique_name}/getcacerts')
    assert response['body'].getName() == 'error'
    assert int(response['body']['error']['pKIStatusInfo']['status']) == 2
    _assert_signature(response, issued.domain.issuing_ca.credential.get_certificate())
    assert not CmpTransactionModel.objects.exists()


def test_ca_certificates_rejects_cross_domain_access(material):
    from pki.models.domain import DomainModel

    issued, certificate, key = material
    other = DomainModel.objects.create(unique_name='other-discovery-domain', issuing_ca=issued.domain.issuing_ca)
    response = _post(_request(certificate, key), f'/.well-known/cmp/p/{other.unique_name}/getcacerts')
    assert response['body'].getName() == 'error'


def test_ca_certificates_rejects_pbm(material):
    from request.clients.cmp_client import CmpClient
    from request.tests.test_cmp_response_security import _message

    issued, certificate, key = material
    message = _message()
    message['header']['senderNonce'] = os.urandom(16)
    message['body']['genm'][0]['infoType'] = CA_CERTS_OID
    context = CmpGeneralRequestContext(cmp_server_host='unused', cmp_shared_secret='test-secret')
    CmpClient(context)._add_protection_shared_secret(message)
    response = _post(message, f'/.well-known/cmp/p/{issued.domain.unique_name}/getcacerts')
    assert response['body'].getName() == 'error'
    _assert_signature(response, issued.domain.issuing_ca.credential.get_certificate())


def test_ca_certificates_omits_empty_info_value(material):
    issued, certificate, key = material
    context = CmpGeneralRequestContext(
        protocol='cmp',
        operation='getcacerts',
        parsed_message=_request(certificate, key),
        issuer_credential=issued.domain.issuing_ca.credential,
    )
    CmpGeneralResponder.build_response(context)
    response, _ = decoder.decode(context.http_response_content, asn1Spec=rfc4210.PKIMessage())
    assert str(response['body']['gen'][0]['infoType']) == CA_CERTS_OID
    assert not response['body']['gen'][0]['infoValue'].hasValue()
    _assert_signature(response, issued.domain.issuing_ca.credential.get_certificate())


def test_ca_certificates_includes_prepared_chain_and_deduplicates(material):
    from pki.models.ca_rollover import CaRolloverState
    from pki.util.x509 import CertificateGenerator

    issued, certificate, key = material
    successor, _ = CertificateGenerator.create_root_ca('Prepared successor')
    credential = Mock()
    credential.get_certificate.return_value = successor
    credential.get_certificate_chain.return_value = [issued.domain.issuing_ca.credential.get_certificate()]
    rollover = Mock(state=CaRolloverState.PREPARATION)
    rollover.new_issuing_ca.get_credential.return_value = credential
    with patch('request.operation_processor.cmp_general.CaRolloverService.get_active_rollover', return_value=rollover):
        response = _post(_request(certificate, key), f'/.well-known/cmp/p/{issued.domain.unique_name}/getcacerts')
    ca = issued.domain.issuing_ca.credential.get_certificate()
    assert _certificates(response) == [ca, successor]
    _assert_signature(response, ca)


def test_ca_certificates_cannot_overwrite_enrollment_transaction(material):
    issued, certificate, key = material
    message = _request(certificate, key)
    tx = CmpTransactionModel.objects.create(
        transaction_id=message['header']['transactionID'].asOctets().hex(),
        operation='certification',
        request_body_type='cr',
        request_der=b'original request',
        last_server_nonce=b'original-server-nonce',
        status=CmpTransactionModel.Status.WAITING,
    )
    response = _post(message, f'/.well-known/cmp/p/{issued.domain.unique_name}/getcacerts')
    assert response['body'].getName() == 'error'
    tx.refresh_from_db()
    assert bytes(tx.last_server_nonce) == b'original-server-nonce'
    assert tx.status == CmpTransactionModel.Status.WAITING


def test_ca_certificates_openssl_interoperability(material, tmp_path):
    import shutil
    import subprocess

    openssl = shutil.which('openssl')
    if openssl is None:
        pytest.skip('OpenSSL CMP is unavailable')
    help_output = subprocess.run([openssl, 'cmp', '-help'], capture_output=True, text=True)
    if '-reqout_only' not in help_output.stderr:
        pytest.skip('OpenSSL CMP lacks request-only generation')
    issued, certificate, key = material
    cert_path = tmp_path / 'device.pem'
    key_path = tmp_path / 'key.pem'
    ca_path = tmp_path / 'ca.pem'
    request_path = tmp_path / 'genm.der'
    response_path = tmp_path / 'genp.der'
    output_path = tmp_path / 'retrieved.pem'
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ca = issued.domain.issuing_ca.credential.get_certificate()
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    command = [
        openssl,
        'cmp',
        '-cmd',
        'genm',
        '-infotype',
        'caCerts',
        '-cert',
        str(cert_path),
        '-key',
        str(key_path),
        '-trusted',
        str(ca_path),
        '-cacertsout',
        str(output_path),
    ]
    generated = subprocess.run(command + ['-reqout_only', str(request_path)], capture_output=True, text=True)
    assert generated.returncode == 0, generated.stderr + generated.stdout
    message, remainder = decoder.decode(request_path.read_bytes(), asn1Spec=rfc4210.PKIMessage())
    assert not remainder
    response = _post(message, f'/.well-known/cmp/p/{issued.domain.unique_name}/getcacerts')
    assert _certificates(response) == [ca]
    response_path.write_bytes(encoder.encode(response))
    accepted = subprocess.run(
        command + ['-reqin', str(request_path), '-rspin', str(response_path)],
        capture_output=True,
        text=True,
    )
    assert accepted.returncode == 0, accepted.stderr + accepted.stdout
    assert x509.load_pem_x509_certificate(output_path.read_bytes()) == ca


def test_ca_certificates_accepts_application_certificate(material):
    from pki.tests.credential_helpers import issue_test_credential

    issued, certificate, key = material
    application = issue_test_credential(
        issued.device,
        'tls_server',
        common_name='CA discovery client',
        public_key=key.public_key(),
    )
    message = _request(application.credential.get_certificate(), key)
    response = _post(message, f'/.well-known/cmp/p/{issued.domain.unique_name}/getcacerts')
    assert _certificates(response) == [issued.domain.issuing_ca.credential.get_certificate()]


def test_ca_certificates_rejects_revoked_signer(material):
    issued, certificate, key = material
    issued.revoke()
    response = _post(_request(certificate, key), f'/.well-known/cmp/p/{issued.domain.unique_name}/getcacerts')
    assert response['body'].getName() == 'error'
    _assert_signature(response, issued.domain.issuing_ca.credential.get_certificate())


@pytest.mark.parametrize('oid', [CA_CERTS_OID, '1.2.3.4'])
def test_ca_certificates_does_not_echo_request_only_headers(material, oid):
    from pyasn1.type import char

    issued, certificate, key = material
    message = _request(certificate, key, oid=oid)
    profile = univ.SequenceOf(componentType=char.UTF8String())
    profile.append('domain_credential')
    header_info = message['header']['generalInfo'][0]
    header_info['infoType'] = '1.3.6.1.5.5.7.4.21'
    header_info['infoValue'] = encoder.encode(profile)
    response = _post(_sign(message, certificate, key), f'/.well-known/cmp/p/{issued.domain.unique_name}/getcacerts')
    assert response['body'].getName() == ('gen' if oid == CA_CERTS_OID else 'error')
    assert not response['header']['generalInfo'].hasValue()
    _assert_signature(response, issued.domain.issuing_ca.credential.get_certificate())
