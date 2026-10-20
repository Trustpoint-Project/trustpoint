# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for CMP enrollment security checks."""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_modules import rfc4210
from trustpoint_core.oid import AlgorithmIdentifier

from request.authentication.cmp import CmpSignatureBasedInitializationAuthentication
from request.request_context import CmpBaseRequestContext, CmpCertificateRequestContext
from request.security_hardening import _verify_declared_signature_algorithm, validate_cmp_proof_of_possession


@pytest.fixture(
    params=[
        (mldsa.MLDSA44PrivateKey, AlgorithmIdentifier.ML_DSA_44),
        (mldsa.MLDSA65PrivateKey, AlgorithmIdentifier.ML_DSA_65),
        (mldsa.MLDSA87PrivateKey, AlgorithmIdentifier.ML_DSA_87),
    ]
)
def mldsa_key_and_algorithm(request):
    key_type, algorithm = request.param
    return key_type.generate(), algorithm


def _pop_context(key, algorithm):
    message = rfc4210.PKIMessage()
    entry = message['body']['cr'][0]
    entry['certReq']['certReqId'] = 0
    entry['certReq']['certTemplate']['version'] = 2
    proof = entry['pop']['signature']
    proof['algorithmIdentifier']['algorithm'] = algorithm.dotted_string
    proof['signature'] = univ.BitString.fromOctetString(key.sign(encoder.encode(entry['certReq'])))
    return CmpCertificateRequestContext(
        parsed_message=message,
        cmp_body_type='cr',
        cert_requested=x509.CertificateBuilder().public_key(key.public_key()),
    )


def test_mldsa_pop_verifies_the_signed_certificate_request(mldsa_key_and_algorithm):
    key, algorithm = mldsa_key_and_algorithm
    context = _pop_context(key, algorithm)
    validate_cmp_proof_of_possession(context)

    context.parsed_message['body']['cr'][0]['certReq']['certReqId'] = 1
    with pytest.raises(InvalidSignature):
        validate_cmp_proof_of_possession(context)


def test_mldsa_pop_rejects_a_different_declared_variant(mldsa_key_and_algorithm):
    key, algorithm = mldsa_key_and_algorithm
    context = _pop_context(key, algorithm)
    wrong_algorithm = (
        AlgorithmIdentifier.ML_DSA_44 if algorithm != AlgorithmIdentifier.ML_DSA_44 else AlgorithmIdentifier.ML_DSA_65
    )
    context.parsed_message['body']['cr'][0]['pop']['signature']['algorithmIdentifier']['algorithm'] = (
        wrong_algorithm.dotted_string
    )
    with pytest.raises(ValueError, match='incompatible'):
        validate_cmp_proof_of_possession(context)


def test_mldsa_protection_supports_onboarded_device_requests(mldsa_key_and_algorithm):
    key, algorithm = mldsa_key_and_algorithm
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'CMP signer')])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, None)
    )
    message = rfc4210.PKIMessage()
    header = message['header']
    header['pvno'] = 2
    header['sender']['rfc822Name'] = 'device@example.test'
    header['recipient']['rfc822Name'] = 'ca@example.test'
    header['protectionAlg']['algorithm'] = algorithm.dotted_string
    message['body']['pkiconf'] = message['body']['pkiconf'].clone('')
    protected = rfc4210.ProtectedPart()
    protected['header'] = header
    protected['infoValue'] = message['body']
    message['protection'] = message['protection'].clone(
        value=univ.BitString.fromOctetString(key.sign(encoder.encode(protected)))
    )
    context = CmpBaseRequestContext(parsed_message=message)
    _verify_declared_signature_algorithm(context, certificate)
    CmpSignatureBasedInitializationAuthentication()._verify_protection_signature(message, certificate)

    header['sender']['rfc822Name'] = 'attacker@example.test'
    with pytest.raises(InvalidSignature):
        CmpSignatureBasedInitializationAuthentication()._verify_protection_signature(message, certificate)


def test_ra_verified_requires_an_authenticated_device_linked_to_a_cmp_ra():
    from devices.models import DeviceModel
    from pki.models import CaModel, DomainModel

    message = rfc4210.PKIMessage()
    message['body']['cr'][0]['pop']['raVerified'] = ''
    context = CmpCertificateRequestContext(parsed_message=message, cmp_body_type='cr')
    with pytest.raises(ValueError, match='not permitted'):
        validate_cmp_proof_of_possession(context)
    context.device = DeviceModel(common_name='ordinary-device')
    with pytest.raises(ValueError, match='not permitted'):
        validate_cmp_proof_of_possession(context)
    context.device = DeviceModel(
        common_name='trusted-ra',
        domain=DomainModel(
            unique_name='ra-domain',
            issuing_ca=CaModel(unique_name='cmp-ra', ca_type=CaModel.CaTypeChoice.REMOTE_CMP_RA),
        ),
    )
    validate_cmp_proof_of_possession(context)


def test_upstream_validity_uses_authorized_duration_and_normalizes_datetimes():
    from request.security_hardening import _validate_upstream_validity

    key = mldsa.MLDSA65PrivateKey.generate()
    now = datetime.now(UTC).replace(microsecond=0)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'upstream')])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .serial_number(1)
        .public_key(key.public_key())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10))
    )
    certificate = builder.sign(key, None)
    _validate_upstream_validity(builder, certificate)
    longer_lived = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .serial_number(2)
        .public_key(key.public_key())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=11))
        .sign(key, None)
    )
    with pytest.raises(ValueError, match='exceeded'):
        _validate_upstream_validity(builder, longer_lived)


def test_pkcs_hmac_protection_preserves_leading_zero_bits_in_the_response():
    from request.authentication.cmp import CmpSharedSecretAuthentication
    from request.clients.cmp_client import CmpClient
    from request.message_builder.cmp import CmpPkiHeaderBuilding
    from request.message_responder.cmp import CmpMessageResponder
    from request.security_hardening import validate_cmp_pbm_parameters

    message = rfc4210.PKIMessage()
    header = message['header']
    header['pvno'] = 2
    header['sender']['rfc822Name'] = 'device@example.test'
    header['recipient']['rfc822Name'] = 'ca@example.test'
    message['header'] = CmpPkiHeaderBuilding._prepare_protection_algorithm_pbm(header)
    parameters, _ = decoder.decode(message['header']['protectionAlg']['parameters'], asn1Spec=rfc4210.PBMParameter())
    parameters['mac']['algorithm'] = '1.2.840.113549.2.9'
    parameters['salt'] = b'0123456789abcdef'
    message['header']['protectionAlg']['parameters'] = encoder.encode(parameters)
    message['body']['pkiconf'] = message['body']['pkiconf'].clone('')
    context = CmpBaseRequestContext(
        parsed_message=message, cmp_shared_secret='test-secret', cmp_server_host='example.test'
    )
    client = CmpClient(context)
    for counter in range(32):
        message['header']['transactionID'] = counter.to_bytes(1, 'big')
        client._add_protection_shared_secret(message)
        if message['protection'].asOctets()[0] < 128:
            break
    else:
        pytest.fail('Could not construct a MAC with a leading zero bit')
    validate_cmp_pbm_parameters(context)
    CmpSharedSecretAuthentication._verify_protection_shared_secret(message, 'test-secret')
    CmpMessageResponder._add_protection_shared_secret(message, context)
    CmpSharedSecretAuthentication._verify_protection_shared_secret(message, 'test-secret')
