# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for EST's TLS-session-bound proof of possession."""

import base64
import ssl
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import AttributeOID
from django.test import RequestFactory
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import char, univ
from pyasn1_modules import rfc2986

from est.channel_binding import verify_est_channel_binding
from request.request_context import EstCertificateRequestContext

SESSION_BINDING = b'0123456789ab'
ENCODED_BINDING = base64.b64encode(SESSION_BINDING)


@pytest.fixture(autouse=True)
def optional_binding_policy(settings):
    settings.DEVELOPMENT_ENV = True
    settings.TRUSTPOINT_EST_REQUIRE_CHANNEL_BINDING = False
    settings.TRUSTPOINT_EST_TRUST_PROXY_CHANNEL_BINDING = False
    settings.TRUSTPOINT_TRUSTED_PROXY_IPS = ('127.0.0.1', '::1')


def make_csr(key, challenge=ENCODED_BINDING, mutate=None):
    """Create a signed CSR, including correctly signed malformed-attribute cases."""
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'bound.example')])
    )
    if challenge is not None:
        builder = builder.add_attribute(AttributeOID.CHALLENGE_PASSWORD, challenge)
    csr = builder.sign(key, hashes.SHA256())
    if mutate is None:
        return csr
    decoded, remainder = decoder.decode(csr.public_bytes(Encoding.DER), asn1Spec=rfc2986.CertificationRequest())
    assert not remainder
    mutate(decoded['certificationRequestInfo']['attributes'])
    signature = key.sign(encoder.encode(decoded['certificationRequestInfo']), ec.ECDSA(hashes.SHA256()))
    decoded['signature'] = univ.BitString.fromOctetString(signature)
    csr = x509.load_der_x509_csr(encoder.encode(decoded))
    assert csr.is_signature_valid
    return csr


@pytest.fixture
def binding_context(ec_private_key):
    request = RequestFactory().post(
        '/.well-known/est/domain/tls_server/simpleenroll', data=b'csr', content_type='application/pkcs10'
    )
    transport = Mock(spec=ssl.SSLSocket)
    transport.version.return_value = 'TLSv1.2'
    transport.get_channel_binding.return_value = SESSION_BINDING
    request.META['werkzeug.socket'] = transport
    return EstCertificateRequestContext(
        protocol='est', operation='simpleenroll', raw_message=request, cert_requested=make_csr(ec_private_key)
    )


def assert_binding_rejected(context):
    with pytest.raises(ValueError):
        verify_est_channel_binding(context)
    assert context.http_response_status == 400
    assert context.http_response_content


@pytest.mark.parametrize('operation', ['simpleenroll', 'simplereenroll'])
@pytest.mark.parametrize('required', [False, True])
def test_binding_matches_actual_tls_session(binding_context, operation, settings, required):
    settings.TRUSTPOINT_EST_REQUIRE_CHANNEL_BINDING = required
    binding_context.operation = operation
    verify_est_channel_binding(binding_context)
    binding_context.raw_message.META['werkzeug.socket'].get_channel_binding.assert_called_once_with('tls-unique')
    assert binding_context.http_response_status is None
    assert binding_context.est_channel_binding_verified


@pytest.mark.parametrize('string_type', [char.UTF8String, char.PrintableString, char.BMPString, char.UniversalString])
def test_valid_directory_string_encodings(binding_context, ec_private_key, string_type):
    def mutate(attributes):
        attributes[0]['values'][0] = encoder.encode(string_type(ENCODED_BINDING.decode('ascii')))

    binding_context.cert_requested = make_csr(ec_private_key, mutate=mutate)
    verify_est_channel_binding(binding_context)


@pytest.mark.parametrize('value_type', [univ.OctetString, char.IA5String])
def test_challenge_must_be_directory_string(binding_context, ec_private_key, value_type):
    def mutate(attributes):
        attributes[0]['values'][0] = encoder.encode(value_type(ENCODED_BINDING))

    binding_context.cert_requested = make_csr(ec_private_key, mutate=mutate)
    assert_binding_rejected(binding_context)


@pytest.mark.parametrize('mutation', ['duplicate', 'empty-values', 'multiple-values'])
def test_ambiguous_challenge_attributes_are_rejected(binding_context, ec_private_key, mutation):
    def mutate(attributes):
        if mutation == 'duplicate':
            attributes.append(attributes[0].clone(cloneValueFlag=True))
        elif mutation == 'empty-values':
            attributes[0]['values'].clear()
        else:
            attributes[0]['values'][1] = encoder.encode(char.UTF8String(ENCODED_BINDING.decode('ascii')))

    binding_context.cert_requested = make_csr(ec_private_key, mutate=mutate)
    assert_binding_rejected(binding_context)


@pytest.mark.parametrize('challenge', [b'', b'not-base64!', ENCODED_BINDING + b'\n', b'A' * 256, 'é'.encode()])
def test_invalid_challenge_values_are_rejected(binding_context, ec_private_key, challenge):
    binding_context.cert_requested = make_csr(ec_private_key, challenge)
    assert_binding_rejected(binding_context)


def test_noncanonical_base64_is_rejected(binding_context, ec_private_key):
    transport = binding_context.raw_message.META['werkzeug.socket']
    transport.get_channel_binding.return_value = b'abcd'
    # ZA== is canonical for the final byte; ZB== decodes identically with nonzero pad bits.
    binding_context.cert_requested = make_csr(ec_private_key, b'YWJjZB==')
    assert base64.b64decode(b'YWJjZB==') == b'abcd'
    assert_binding_rejected(binding_context)


def test_binding_from_a_different_session_is_rejected(binding_context):
    binding_context.est_channel_binding_verified = True
    binding_context.raw_message.META['werkzeug.socket'].get_channel_binding.return_value = b'another-tls!'
    assert_binding_rejected(binding_context)
    assert not binding_context.est_channel_binding_verified


def test_unrelated_multivalued_attribute_does_not_hide_valid_binding(binding_context, ec_private_key):
    def mutate(attributes):
        unrelated = rfc2986.Attribute()
        unrelated['type'] = univ.ObjectIdentifier('1.2.840.113549.1.9.20')
        unrelated['values'][0] = encoder.encode(char.UTF8String('first'))
        unrelated['values'][1] = encoder.encode(char.UTF8String('second'))
        attributes.append(unrelated)

    binding_context.cert_requested = make_csr(ec_private_key, mutate=mutate)
    verify_est_channel_binding(binding_context)


@pytest.mark.parametrize('actual_binding', [None, b''])
def test_unavailable_session_binding_is_rejected(binding_context, actual_binding):
    binding_context.raw_message.META['werkzeug.socket'].get_channel_binding.return_value = actual_binding
    assert_binding_rejected(binding_context)


def test_socket_failure_cannot_downgrade_to_proxy_headers(binding_context, settings):
    settings.TRUSTPOINT_EST_TRUST_PROXY_CHANNEL_BINDING = True
    set_proxy_metadata(binding_context)
    binding_context.raw_message.META['werkzeug.socket'].get_channel_binding.side_effect = OSError('closed')
    assert_binding_rejected(binding_context)


def test_direct_socket_is_authoritative_over_proxy_headers(binding_context, settings):
    settings.TRUSTPOINT_EST_TRUST_PROXY_CHANNEL_BINDING = True
    set_proxy_metadata(binding_context, HTTP_X_EST_TLS_UNIQUE=base64.b64encode(b'forged').decode())
    verify_est_channel_binding(binding_context)


def test_optional_binding_absence_does_not_require_tls_metadata(binding_context, ec_private_key):
    binding_context.cert_requested = make_csr(ec_private_key, None)
    binding_context.raw_message = None
    verify_est_channel_binding(binding_context)


def test_required_binding_rejects_absent_attribute(binding_context, ec_private_key, settings):
    settings.TRUSTPOINT_EST_REQUIRE_CHANNEL_BINDING = True
    binding_context.cert_requested = make_csr(ec_private_key, None)
    assert_binding_rejected(binding_context)


def test_tls13_does_not_reuse_tls_unique(binding_context):
    binding_context.raw_message.META['werkzeug.socket'].version.return_value = 'TLSv1.3'
    assert_binding_rejected(binding_context)
    binding_context.raw_message.META['werkzeug.socket'].get_channel_binding.assert_not_called()


def test_native_tls_socket_is_development_only(binding_context, settings):
    """Production uses the proxy path that can enforce EMS and no renegotiation."""
    settings.DEVELOPMENT_ENV = False
    assert_binding_rejected(binding_context)


def set_proxy_metadata(context, **overrides):
    context.raw_message.META.update(
        {
            'REMOTE_ADDR': '127.0.0.1',
            'HTTP_X_EST_TLS_UNIQUE': ENCODED_BINDING.decode(),
            'HTTP_X_EST_TLS_UNIQUE_SUPPORTED': '1',
            'HTTP_X_EST_TLS_PROTOCOL': 'TLSv1.2',
            **overrides,
        }
    )


def proxy_context(context):
    context.raw_message.META.pop('werkzeug.socket')
    set_proxy_metadata(context)
    return context


def test_explicitly_trusted_proxy_can_supply_tls_metadata(binding_context, settings):
    settings.TRUSTPOINT_EST_TRUST_PROXY_CHANNEL_BINDING = True
    verify_est_channel_binding(proxy_context(binding_context))


def test_proxy_binding_requires_explicit_opt_in(binding_context):
    assert_binding_rejected(proxy_context(binding_context))


@pytest.mark.parametrize('peer', ['203.0.113.4', '', 'not-an-ip'])
def test_untrusted_proxy_cannot_choose_binding(binding_context, settings, peer):
    settings.TRUSTPOINT_EST_TRUST_PROXY_CHANNEL_BINDING = True
    context = proxy_context(binding_context)
    context.raw_message.META['REMOTE_ADDR'] = peer
    assert_binding_rejected(context)


@pytest.mark.parametrize(
    'header', ['HTTP_X_EST_TLS_UNIQUE', 'HTTP_X_EST_TLS_UNIQUE_SUPPORTED', 'HTTP_X_EST_TLS_PROTOCOL']
)
def test_incomplete_proxy_metadata_is_rejected(binding_context, settings, header):
    settings.TRUSTPOINT_EST_TRUST_PROXY_CHANNEL_BINDING = True
    context = proxy_context(binding_context)
    context.raw_message.META.pop(header)
    assert_binding_rejected(context)


@pytest.mark.parametrize('protocol', ['TLSv1.3', 'TLSv1.1', ''])
def test_proxy_binding_requires_tls12(binding_context, settings, protocol):
    settings.TRUSTPOINT_EST_TRUST_PROXY_CHANNEL_BINDING = True
    context = proxy_context(binding_context)
    context.raw_message.META['HTTP_X_EST_TLS_PROTOCOL'] = protocol
    assert_binding_rejected(context)


def test_proxy_must_report_supported_binding(binding_context, settings):
    settings.TRUSTPOINT_EST_TRUST_PROXY_CHANNEL_BINDING = True
    context = proxy_context(binding_context)
    context.raw_message.META['HTTP_X_EST_TLS_UNIQUE_SUPPORTED'] = '0'
    assert_binding_rejected(context)


def test_unparsed_csr_is_type_error():
    with pytest.raises(TypeError):
        verify_est_channel_binding(EstCertificateRequestContext(cert_requested='not-a-csr'))
