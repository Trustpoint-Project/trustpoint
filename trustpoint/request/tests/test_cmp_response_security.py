# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Authenticate real DER responses at the CMP client's transport boundary."""

import hashlib
import hmac
from unittest.mock import Mock, patch

import pytest
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_modules import rfc4210

from request.clients.cmp_client import MAX_CMP_RESPONSE_BYTES, CmpClient, CmpClientError
from request.message_responder.cmp import CmpCertificationResponder, CmpMessageResponder
from request.request_context import CmpBaseRequestContext
from request.tests.test_est_client import certificate_and_csr

SECRET = 'test-only-upstream-shared-secret'
PBM_OID = '1.2.840.113533.7.66.13'
SHA256_OID = '2.16.840.1.101.3.4.2.1'
HMAC_SHA256_OID = '1.2.840.113549.2.9'


def _parameters(message):
    return decoder.decode(message['header']['protectionAlg']['parameters'], asn1Spec=rfc4210.PBMParameter())[0]


def _protect(message, secret=SECRET, owf='sha256', mac='sha256'):
    """Generate the peer's MAC independently from the client's cryptography code."""
    pbm = _parameters(message)
    key = secret.encode() + pbm['salt'].asOctets()
    for _ in range(int(pbm['iterationCount'])):
        key = hashlib.new(owf, key).digest()
    protected = rfc4210.ProtectedPart()
    protected['header'] = message['header']
    protected['infoValue'] = message['body']
    signature = hmac.digest(key, encoder.encode(protected), mac)
    message['protection'] = message['protection'].clone(value=univ.BitString.fromOctetString(signature))


def _message():
    message = rfc4210.PKIMessage()
    header = message['header']
    header['pvno'] = 2
    header['sender']['rfc822Name'] = 'sender@example.test'
    header['recipient']['rfc822Name'] = 'recipient@example.test'
    header['transactionID'] = b'transaction-0001'
    pbm = rfc4210.PBMParameter()
    pbm['salt'] = b'upstream-salt-01'
    pbm['iterationCount'] = 2
    pbm['owf']['algorithm'] = SHA256_OID
    pbm['mac']['algorithm'] = HMAC_SHA256_OID
    header['protectionAlg']['algorithm'] = PBM_OID
    header['protectionAlg']['parameters'] = encoder.encode(pbm)
    return message


def _exchange(request_type='cr', response_type='cp'):
    request = _message()
    request['header']['senderNonce'] = b'client-nonce-0001'
    if request_type in {'ir', 'cr', 'kur'}:
        entry = request['body'][request_type][0]['certReq']
        entry['certReqId'] = 7
        entry['certTemplate']['version'] = 2
    elif request_type == 'pollReq':
        request['body']['pollReq'][0]['certReqId'] = 7
        request['header']['recipNonce'] = b'previous-server1'
    elif request_type == 'certConf':
        request['body']['certConf'][0]['certReqId'] = 7
        request['body']['certConf'][0]['certHash'] = b'certificate-hash'
        request['header']['recipNonce'] = b'previous-server1'
    _protect(request)
    response = _message()
    response['header']['senderNonce'] = b'server-nonce-0001'
    response['header']['recipNonce'] = request['header']['senderNonce'].asOctets()
    if response_type in {'ip', 'cp', 'kup'}:
        entry = response['body'][response_type]['response'][0]
        entry['certReqId'] = 7
        entry['status']['status'] = 0
    elif response_type == 'pkiconf':
        response['body']['pkiconf'] = response['body']['pkiconf'].clone('')
    elif response_type == 'pollRep':
        entry = response['body']['pollRep'][0]
        entry['certReqId'] = 7
        entry['checkAfter'] = 5
    elif response_type == 'error':
        response['body']['error']['pKIStatusInfo']['status'] = 2
        response['body']['error']['pKIStatusInfo']['statusString'][0] = 'peer rejection'
    _protect(response)
    return request, response


@pytest.fixture
def client():
    return CmpClient(CmpBaseRequestContext(cmp_server_host='upstream.example.test', cmp_shared_secret=SECRET))


@pytest.mark.parametrize(
    ('request_type', 'response_type'),
    [
        ('ir', 'ip'),
        ('cr', 'cp'),
        ('kur', 'kup'),
        ('certConf', 'pkiconf'),
        ('pollReq', 'pollRep'),
        ('pollReq', 'cp'),
    ],
)
def test_accepts_protected_bound_response_without_tls_verification(client, request_type, response_type):
    request, response = _exchange(request_type, response_type)
    raw = encoder.encode(response)
    with patch('request.clients.cmp_client.requests.post', return_value=Mock(status_code=200, content=raw)) as post:
        parsed, returned_raw = client.send_pki_message(request)
    assert returned_raw == raw
    assert parsed['body'].getName() == response_type
    assert post.call_args.kwargs['verify'] is False


def test_accepts_and_extracts_certificate_from_trustpoint_responder(client):
    request, _ = _exchange()
    request['body']['cr'][0]['certReq']['certReqId'] = 0
    _protect(request)
    _, certificate, _ = certificate_and_csr()
    credential = Mock(
        get_certificate=Mock(return_value=certificate),
        get_certificate_chain=Mock(return_value=[]),
    )
    sender_kid = request['header']['senderKID'].clone(value=b'upstream-key-id')
    response = CmpCertificationResponder._build_base_cp_message(request, certificate, credential, sender_kid)
    CmpMessageResponder._add_protection_shared_secret(
        response,
        CmpBaseRequestContext(parsed_message=request, cmp_shared_secret=SECRET),
    )
    with patch(
        'request.clients.cmp_client.requests.post',
        return_value=Mock(
            status_code=200,
            content=encoder.encode(response),
        ),
    ):
        issued, chain = client.send_and_extract_certificate(request)
    assert issued == certificate
    assert chain == [certificate]


def test_response_is_bound_to_wire_request_even_if_caller_mutates_original(client):
    request, response = _exchange()
    request_bytes = encoder.encode(request)
    response_bytes = encoder.encode(response)

    def transport(_url, **kwargs):
        assert kwargs['data'] == request_bytes
        request['header']['senderNonce'] = b'changed-client-1'
        return Mock(status_code=200, content=response_bytes)

    with patch('request.clients.cmp_client.requests.post', side_effect=transport):
        parsed, _ = client.send_pki_message(request)
    assert parsed['header']['recipNonce'].asOctets() != request['header']['senderNonce'].asOctets()


@pytest.mark.parametrize(
    ('owf_oid', 'owf', 'mac_oid', 'mac'),
    [
        ('2.16.840.1.101.3.4.2.2', 'sha384', '1.2.840.113549.2.10', 'sha384'),
        ('2.16.840.1.101.3.4.2.3', 'sha512', '1.2.840.113549.2.11', 'sha512'),
        ('2.16.840.1.101.3.4.2.8', 'sha3_256', HMAC_SHA256_OID, 'sha256'),
    ],
)
def test_accepts_independent_strong_response_pbm_parameters(client, owf_oid, owf, mac_oid, mac):
    request, response = _exchange()
    pbm = _parameters(response)
    pbm['owf']['algorithm'] = owf_oid
    pbm['mac']['algorithm'] = mac_oid
    pbm['owf']['parameters'] = b'\x05\x00'
    pbm['mac']['parameters'] = b'\x05\x00'
    pbm['salt'] = b'new-upstream-salt'
    response['header']['protectionAlg']['parameters'] = encoder.encode(pbm)
    _protect(response, owf=owf, mac=mac)
    assert client._parse_response(encoder.encode(response), request)['body'].getName() == 'cp'


@pytest.mark.parametrize('version', [1, 4])
def test_rejects_unsupported_response_versions(client, version):
    request, response = _exchange()
    response['header']['pvno'] = version
    _protect(response)
    with pytest.raises(CmpClientError, match='Unsupported CMP response version'):
        client._parse_response(encoder.encode(response), request)


@pytest.mark.parametrize('field', ['protectionAlg', 'protection'])
def test_rejects_missing_protection(client, field):
    request, response = _exchange()
    owner = response['header'] if field == 'protectionAlg' else response
    owner.setComponentByName(field)
    with pytest.raises(CmpClientError, match='missing message protection'):
        client._parse_response(encoder.encode(response), request)


@pytest.mark.parametrize('field', ['transactionID', 'recipNonce', 'senderNonce'])
@pytest.mark.parametrize('missing', [False, True])
def test_rejects_missing_or_incorrect_binding_fields(client, field, missing):
    request, response = _exchange()
    header = response['header']
    if missing:
        header.setComponentByName(field)
    else:
        header[field] = b'incorrect-value'
    _protect(response)
    with pytest.raises(CmpClientError, match=field):
        client._parse_response(encoder.encode(response), request)


@pytest.mark.parametrize('request_field', ['senderNonce', 'recipNonce'])
def test_rejects_reflected_or_reused_server_nonce(client, request_field):
    request, response = _exchange('pollReq', 'pollRep')
    response['header']['senderNonce'] = request['header'][request_field].asOctets()
    _protect(response)
    with pytest.raises(CmpClientError, match='not fresh'):
        client._parse_response(encoder.encode(response), request)


def test_replay_cannot_satisfy_a_new_request_nonce(client):
    request, response = _exchange()
    request['header']['senderNonce'] = b'next-client-0001'
    _protect(request)
    with pytest.raises(CmpClientError, match='recipNonce'):
        client._parse_response(encoder.encode(response), request)


def test_rejects_invalid_mac_and_does_not_extract_certificates(client):
    request, response = _exchange()
    response['body']['cp']['response'][0]['status']['status'] = 2
    with (
        patch(
            'request.clients.cmp_client.requests.post',
            return_value=Mock(
                status_code=200,
                content=encoder.encode(response),
            ),
        ),
        patch.object(client, '_extract_issued_certificate') as extract,
    ):
        with pytest.raises(CmpClientError, match='protection verification failed'):
            client.send_and_extract_certificate(request)
    extract.assert_not_called()


def test_rejects_response_mac_using_a_different_secret(client):
    request, response = _exchange()
    _protect(response, secret='attacker-secret')
    with pytest.raises(CmpClientError, match='protection verification failed'):
        client._parse_response(encoder.encode(response), request)


def test_rejects_non_octet_aligned_protection(client):
    request, response = _exchange()
    response['protection'] = response['protection'].clone(value=univ.BitString('10101'))
    with pytest.raises(CmpClientError, match='complete octets'):
        client._parse_response(encoder.encode(response), request)


def test_shared_secret_must_be_available(client):
    request, response = _exchange()
    client.context.cmp_shared_secret = None
    with pytest.raises(CmpClientError, match='shared secret is required'):
        client._parse_response(encoder.encode(response), request)


@pytest.mark.parametrize('side', ['request', 'response'])
def test_rejects_unsupported_or_changed_protection_modes(client, side):
    request, response = _exchange()
    message = request if side == 'request' else response
    message['header']['protectionAlg']['algorithm'] = '1.2.840.10045.4.3.2'
    with pytest.raises(CmpClientError, match='Only PBM-protected'):
        client._parse_response(encoder.encode(response), request)


@pytest.mark.parametrize(('request_type', 'response_type'), [('ir', 'cp'), ('cr', 'ip'), ('cr', 'pkiconf')])
def test_rejects_authenticated_wrong_response_type(client, request_type, response_type):
    request, response = _exchange(request_type, response_type)
    with pytest.raises(CmpClientError, match='Unexpected CMP response body'):
        client._parse_response(encoder.encode(response), request)


@pytest.mark.parametrize(('request_type', 'response_type'), [('cr', 'cp'), ('pollReq', 'cp'), ('pollReq', 'pollRep')])
def test_rejects_authenticated_wrong_certificate_request_id(client, request_type, response_type):
    request, response = _exchange(request_type, response_type)
    entry = (
        response['body'][response_type][0]
        if response_type == 'pollRep'
        else response['body'][response_type]['response'][0]
    )
    entry['certReqId'] = 8
    _protect(response)
    with pytest.raises(CmpClientError, match='certReqId'):
        client._parse_response(encoder.encode(response), request)


def test_rejects_authenticated_multiple_certificate_responses(client):
    request, response = _exchange()
    response['body']['cp']['response'][1]['certReqId'] = 8
    response['body']['cp']['response'][1]['status']['status'] = 0
    _protect(response)
    with pytest.raises(CmpClientError, match='Exactly one'):
        client._parse_response(encoder.encode(response), request)


@pytest.mark.parametrize(
    ('field', 'value'),
    [
        ('iterationCount', 0),
        ('iterationCount', -1),
        ('iterationCount', 100_001),
        ('iterationCount', 2**63),
        ('salt', b'short'),
        ('salt', b'x' * 65),
    ],
)
def test_bounds_untrusted_pbm_work_before_key_derivation(client, field, value):
    request, response = _exchange()
    pbm = _parameters(response)
    pbm[field] = value
    response['header']['protectionAlg']['parameters'] = encoder.encode(pbm)
    with patch('request.clients.cmp_client.hashes.Hash') as digest:
        with pytest.raises(CmpClientError, match='outside permitted bounds'):
            client._parse_response(encoder.encode(response), request)
    digest.assert_not_called()


@pytest.mark.parametrize(
    ('field', 'oid'),
    [
        ('owf', '1.3.14.3.2.26'),
        ('mac', '1.2.840.113549.2.7'),
        ('owf', '1.2.3.4.999'),
        ('mac', '1.2.3.4.999'),
    ],
)
def test_rejects_weak_or_unknown_pbm_algorithms(client, field, oid):
    request, response = _exchange()
    pbm = _parameters(response)
    pbm[field]['algorithm'] = oid
    response['header']['protectionAlg']['parameters'] = encoder.encode(pbm)
    with pytest.raises(CmpClientError):
        client._parse_response(encoder.encode(response), request)


@pytest.mark.parametrize('field', ['owf', 'mac'])
def test_rejects_invalid_algorithm_parameters(client, field):
    request, response = _exchange()
    pbm = _parameters(response)
    pbm[field]['parameters'] = b'\x02\x01\x01'
    response['header']['protectionAlg']['parameters'] = encoder.encode(pbm)
    with pytest.raises(CmpClientError, match='algorithm parameters'):
        client._parse_response(encoder.encode(response), request)


def test_rejects_trailing_pbm_parameter_data(client):
    request, response = _exchange()
    parameters = response['header']['protectionAlg']['parameters'].asOctets()
    response['header']['protectionAlg']['parameters'] = parameters + b'\x05\x00'
    with pytest.raises(CmpClientError):
        client._parse_response(encoder.encode(response), request)


def test_error_status_is_only_consumed_after_authentication(client):
    request, response = _exchange('cr', 'error')
    with pytest.raises(CmpClientError, match='CMP server returned error status 2: peer rejection'):
        client._parse_response(encoder.encode(response), request)
    response['body']['error']['pKIStatusInfo']['statusString'][0] = 'injected attacker text'
    with pytest.raises(CmpClientError, match='protection verification failed') as error:
        client._parse_response(encoder.encode(response), request)
    assert 'injected attacker text' not in str(error.value)


def test_unprotected_error_does_not_expose_untrusted_status_text(client):
    request, response = _exchange('cr', 'error')
    response.setComponentByName('protection')
    with pytest.raises(CmpClientError, match='missing message protection') as error:
        client._parse_response(encoder.encode(response), request)
    assert 'peer rejection' not in str(error.value)


@pytest.mark.parametrize('raw', [b'', b'\x30', b'not DER'])
def test_malformed_messages_raise_client_errors(client, raw):
    request, _ = _exchange()
    with pytest.raises(CmpClientError):
        client._parse_response(raw, request)


def test_rejects_trailing_message_data(client):
    request, response = _exchange()
    with pytest.raises(CmpClientError, match='trailing data in CMP response'):
        client._parse_response(encoder.encode(response) + b'\x05\x00', request)


def test_rejects_oversized_response_before_asn1_decoding(client):
    request, _ = _exchange()
    with patch('request.clients.cmp_client.decoder.decode') as decode:
        with pytest.raises(CmpClientError, match='maximum permitted size'):
            client._parse_response(b'x' * (MAX_CMP_RESPONSE_BYTES + 1), request)
    decode.assert_not_called()
