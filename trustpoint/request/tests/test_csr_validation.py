# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Exercise shared PKCS#10 validation through its enrollment adapters."""

import base64
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding

from pki.forms.csr import CsrIssuanceForm
from pki.services.csr import (
    MAX_CSR_SIZE,
    MAX_CSR_TRANSPORT_SIZE,
    CsrErrorCode,
    CsrValidationError,
    decode_base64_csr,
    parse_csr,
)
from request.gds_push.gds_push_service import GdsPushError, GdsPushService
from request.message_parser.est import EstCsrSignatureVerification, EstPkiMessageParsing
from request.message_parser.rest import RestCsrSignatureVerification, RestPkiMessageParsing
from request.request_context import EstCertificateRequestContext, RestCertificateRequestContext
from scep.handler import ScepPkiOperationHandler
from scep.protocol.errors import ScepProtocolError
from scep.protocol.oids import FailInfo


@pytest.fixture(scope='module', params=['rsa', 'pss', 'ec', 'mldsa44', 'mldsa65', 'mldsa87'])
def signed_csr(request):
    """Use real signatures, including PSS with non-default MGF and salt parameters."""
    kind = request.param
    kwargs = {}
    digest = hashes.SHA256()
    if kind.startswith('mldsa'):
        key = {
            'mldsa44': mldsa.MLDSA44PrivateKey,
            'mldsa65': mldsa.MLDSA65PrivateKey,
            'mldsa87': mldsa.MLDSA87PrivateKey,
        }[kind].generate()
        digest = None
    elif kind == 'ec':
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if kind == 'pss':
            kwargs['rsa_padding'] = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=20)
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'device.example')]))
        .sign(key, digest, **kwargs)
    )


def _http_context(transport, der):
    """Represent the same request using each supported HTTP transport."""
    pem = x509.load_der_x509_csr(der).public_bytes(Encoding.PEM)
    wrapped = base64.encodebytes(der)
    headers = {}
    if transport.startswith('rest'):
        value = pem if transport == 'rest-pem' else wrapped
        body = json.dumps({'csr': value.decode('ascii')}).encode()
        context = RestCertificateRequestContext()
        parser, verifier = RestPkiMessageParsing(), RestCsrSignatureVerification()
    else:
        body = {'est-pem': pem, 'est-der': der, 'est-base64': wrapped, 'est-transfer': wrapped}[transport]
        if transport == 'est-transfer':
            headers['Content-Transfer-Encoding'] = 'base64'
        context = EstCertificateRequestContext()
        parser, verifier = EstPkiMessageParsing(), EstCsrSignatureVerification()
    context.raw_message = SimpleNamespace(body=body, headers=headers)
    return context, parser, verifier


@pytest.mark.parametrize(
    'transport', ['pem', 'der', 'est-pem', 'est-der', 'est-base64', 'est-transfer', 'rest-pem', 'rest-base64']
)
@pytest.mark.parametrize('tampered', [False, True])
def test_signature_validation_across_transports(signed_csr, transport, tampered):
    """UI, EST and REST agree on RSA, parameterized PSS, EC and all ML-DSA variants."""
    der = bytearray(signed_csr.public_bytes(Encoding.DER))
    if tampered:
        der[-1] ^= 1
    der = bytes(der)
    if transport in ('pem', 'der'):
        data = der if transport == 'der' else x509.load_der_x509_csr(der).public_bytes(Encoding.PEM)
        if tampered:
            with pytest.raises(CsrValidationError) as failure:
                parse_csr(data)
            assert failure.value.code == CsrErrorCode.INVALID_SIGNATURE
        else:
            assert parse_csr(data).subject == signed_csr.subject
        return
    context, parser, verifier = _http_context(transport, der)
    parser.parse(context)
    if transport.startswith('est'):
        assert context.est_encoding == ('pem' if transport == 'est-pem' else 'pkcs7')
    if tampered:
        with pytest.raises(ValueError, match='Failed to verify the CSR signature'):
            verifier.parse(context)
    else:
        verifier.parse(context)
        assert context.cert_requested.subject == signed_csr.subject


def test_scep_retains_algorithm_restrictions_and_error_codes(signed_csr):
    """SCEP keeps its SHA-2 restriction and distinguishes malformed requests from bad proof."""
    der = signed_csr.public_bytes(Encoding.DER)
    if signed_csr.signature_hash_algorithm is None:
        with pytest.raises(ScepProtocolError) as failure:
            ScepPkiOperationHandler._load_csr(der)
        assert failure.value.fail_info == FailInfo.BAD_ALG
    else:
        assert ScepPkiOperationHandler._load_csr(der).subject == signed_csr.subject
    corrupt = der[:-1] + bytes([der[-1] ^ 1])
    with pytest.raises(ScepProtocolError) as failure:
        ScepPkiOperationHandler._load_csr(corrupt)
    assert failure.value.fail_info == FailInfo.BAD_MESSAGE_CHECK
    with pytest.raises(ScepProtocolError) as failure:
        ScepPkiOperationHandler._load_csr(b'not a CSR')
    assert failure.value.fail_info == FailInfo.BAD_REQUEST


@pytest.mark.parametrize('extra', ['bundle', 'pem-trailing', 'der-trailing'])
def test_rejects_extra_csr_data(signed_csr, extra):
    """A successful parse cannot silently discard another request or trailing content."""
    pem = signed_csr.public_bytes(Encoding.PEM)
    data = {
        'bundle': pem + pem,
        'pem-trailing': pem + b'unexpected',
        'der-trailing': signed_csr.public_bytes(Encoding.DER) + b'unexpected',
    }[extra]
    with pytest.raises(CsrValidationError):
        parse_csr(data)


def test_accepts_legacy_pem_label_and_whitespace(signed_csr):
    """OpenSSL's NEW label and CRLF/wrapped encodings remain interoperable."""
    pem = signed_csr.public_bytes(Encoding.PEM).replace(b'CERTIFICATE REQUEST', b'NEW CERTIFICATE REQUEST')
    assert parse_csr(b' \r\n' + pem.replace(b'\n', b'\r\n') + b'\t').subject == signed_csr.subject


@pytest.mark.parametrize('data', [b'@@YWJj', b'YWJj!!!!', b'YQ==junk', b'YQ==='])
def test_base64_rejects_junk(data):
    """Transport decoding must not silently drop non-Base64 bytes."""
    with pytest.raises(CsrValidationError):
        decode_base64_csr(data)


@pytest.mark.parametrize('data', [b'x' * (MAX_CSR_TRANSPORT_SIZE + 1), base64.b64encode(b'x' * (MAX_CSR_SIZE + 1))])
def test_encoded_and_decoded_limits(data):
    """Both encoded request overhead and decoded payloads have bounded size."""
    with pytest.raises(CsrValidationError) as failure:
        decode_base64_csr(data)
    assert failure.value.code == CsrErrorCode.TOO_LARGE


@pytest.mark.parametrize('payload', [[], None, 'csr', {'csr': ['value']}, {'csr': 123}, {'csr': {'value': 'csr'}}])
def test_rest_invalid_json_shapes_are_client_errors(payload):
    """JSON values and CSR fields with unexpected types produce a controlled HTTP 400."""
    context = RestCertificateRequestContext(raw_message=SimpleNamespace(body=json.dumps(payload).encode()))
    with pytest.raises(ValueError):
        RestPkiMessageParsing().parse(context)
    assert context.http_response_status == 400


@pytest.mark.parametrize('protocol', ['est', 'rest'])
def test_http_transport_limit(protocol):
    """Oversized bodies fail before any cryptographic parsing."""
    body = b'x' * (MAX_CSR_TRANSPORT_SIZE + 1)
    if protocol == 'est':
        context = EstCertificateRequestContext(raw_message=SimpleNamespace(body=body, headers={}))
        parser = EstPkiMessageParsing()
    else:
        context = RestCertificateRequestContext(raw_message=SimpleNamespace(body=body))
        parser = RestPkiMessageParsing()
    with pytest.raises(ValueError):
        parser.parse(context)
    assert context.http_response_status == 400


@pytest.mark.asyncio
async def test_gds_rejects_bad_proof_before_issuance(signed_csr):
    """GDS push must prove key possession before profile validation or issuance."""
    der = signed_csr.public_bytes(Encoding.DER)
    corrupt = der[:-1] + bytes([der[-1] ^ 1])
    service = GdsPushService(Mock(), insecure=True)
    with (
        patch('request.gds_push.gds_push_service.ProfileValidator.validate') as validate,
        patch('request.gds_push.gds_push_service.CertificateIssueProcessor') as issue,
    ):
        with pytest.raises(GdsPushError, match='signature is invalid'):
            await service._sign_csr(corrupt)
    validate.assert_not_called()
    issue.assert_not_called()


def test_oversized_upload_is_rejected():
    """An uploaded CSR cannot bypass the shared parser's input limit."""
    from django.core.files.uploadedfile import SimpleUploadedFile

    form = CsrIssuanceForm(files={'csr_file': SimpleUploadedFile('large.csr', b'x' * (MAX_CSR_SIZE + 1))})
    assert not form.is_valid()
    assert 'too large' in str(form.errors)
