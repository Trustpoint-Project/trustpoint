# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for signature verification shared by EST and REST."""

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives.serialization import Encoding

from request.message_parser.est import EstCsrSignatureVerification
from request.message_parser.rest import RestCsrSignatureVerification
from request.request_context import EstCertificateRequestContext, RestCertificateRequestContext


@pytest.mark.parametrize(
    'verifier_type,context_type',
    [
        (EstCsrSignatureVerification, EstCertificateRequestContext),
        (RestCsrSignatureVerification, RestCertificateRequestContext),
    ],
)
@pytest.mark.parametrize(
    'key_type',
    [
        mldsa.MLDSA44PrivateKey,
        mldsa.MLDSA65PrivateKey,
        mldsa.MLDSA87PrivateKey,
    ],
)
@pytest.mark.parametrize('tampered', [False, True])
def test_mldsa_csr_signature_validation(verifier_type, context_type, key_type, tampered):
    """Both protocols accept hashless ML-DSA CSRs and reject corrupt signatures."""
    key = key_type.generate()
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'device.example')]))
        .sign(key, None)
    )
    context = context_type(cert_requested=csr)

    if tampered:
        der = bytearray(csr.public_bytes(Encoding.DER))
        der[-1] ^= 1
        context.cert_requested = x509.load_der_x509_csr(bytes(der))
        with pytest.raises(ValueError, match='Failed to verify the CSR signature'):
            verifier_type().parse(context)
    else:
        verifier_type().parse(context)


@pytest.mark.parametrize(
    'verifier_type,context_type,error_type',
    [
        (EstCsrSignatureVerification, EstCertificateRequestContext, ValueError),
        (RestCsrSignatureVerification, RestCertificateRequestContext, TypeError),
    ],
)
def test_protocol_specific_invalid_csr_errors(verifier_type, context_type, error_type):
    """Invalid CSR objects retain each protocol's existing exception type."""
    context = context_type(cert_requested='invalid')
    with pytest.raises(error_type):
        verifier_type().parse(context)
