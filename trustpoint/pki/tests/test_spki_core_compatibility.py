# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Core algorithm classification preserves Trustpoint's stored SPKI conventions."""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, rsa
from trustpoint_core.oid import NamedCurve, PublicKeyAlgorithmOid

from pki.models.certificate import CertificateModel


def certificate_for_key(key):
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'SPKI compatibility')])
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256() if isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)) else None)
    )


@pytest.mark.parametrize(
    ('factory', 'algorithm', 'size', 'curve'),
    [
        (
            lambda: rsa.generate_private_key(public_exponent=65537, key_size=1024),
            PublicKeyAlgorithmOid.RSA,
            1024,
            NamedCurve.NONE,
        ),
        (
            lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
            PublicKeyAlgorithmOid.RSA,
            2048,
            NamedCurve.NONE,
        ),
        (lambda: ec.generate_private_key(ec.SECP256R1()), PublicKeyAlgorithmOid.ECC, 256, NamedCurve.SECP256R1),
        (lambda: ec.generate_private_key(ec.SECP384R1()), PublicKeyAlgorithmOid.ECC, 384, NamedCurve.SECP384R1),
        (lambda: ec.generate_private_key(ec.SECP521R1()), PublicKeyAlgorithmOid.ECC, 521, NamedCurve.SECP521R1),
        (mldsa.MLDSA44PrivateKey.generate, PublicKeyAlgorithmOid.ML_DSA_44, 0, NamedCurve.NONE),
        (mldsa.MLDSA65PrivateKey.generate, PublicKeyAlgorithmOid.ML_DSA_65, 0, NamedCurve.NONE),
        (mldsa.MLDSA87PrivateKey.generate, PublicKeyAlgorithmOid.ML_DSA_87, 0, NamedCurve.NONE),
    ],
    ids=['rsa1024', 'rsa2048', 'p256', 'p384', 'p521', 'mldsa44', 'mldsa65', 'mldsa87'],
)
def test_spki_metadata_keeps_legacy_rsa_sizes_and_mldsa_zero(factory, algorithm, size, curve):
    """Stored metadata must not inherit Core PublicKeyInfo's size restrictions or units."""
    assert CertificateModel._get_spki_info(certificate_for_key(factory())) == (algorithm, size, curve)


def test_unsupported_spki_key_keeps_existing_error_message():
    """Core still rejects unsupported subject keys through Trustpoint's existing error boundary."""
    with pytest.raises(TypeError, match='Subject Public Key Info contains an unsupported key type'):
        CertificateModel._get_spki_info(certificate_for_key(ed25519.Ed25519PrivateKey.generate()))
