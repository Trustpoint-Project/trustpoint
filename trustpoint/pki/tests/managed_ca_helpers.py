"""Helpers for PKI tests that need backend-managed CA keys."""

import uuid
from typing import cast

from cryptography import x509

from crypto.application.private_keys import ManagedRSAPrivateKey, generate_managed_signing_private_key
from crypto.domain.specs import RsaKeySpec
from pki.util.x509 import CertificateGenerator


def create_managed_ca_private_key(alias_prefix: str) -> ManagedRSAPrivateKey:
    """Generate a backend-managed RSA CA private key for tests."""
    return cast(
        'ManagedRSAPrivateKey',
        generate_managed_signing_private_key(
            alias=f'{alias_prefix}-{uuid.uuid4().hex}',
            key_spec=RsaKeySpec(key_size=2048),
        ),
    )


def create_managed_root_ca(cn: str) -> tuple[x509.Certificate, ManagedRSAPrivateKey]:
    """Create a self-signed root CA certificate with a backend-managed private key."""
    private_key = create_managed_ca_private_key(cn.lower().replace(' ', '-'))
    certificate, generated_private_key = CertificateGenerator.create_root_ca(cn=cn, private_key=private_key)
    return certificate, cast('ManagedRSAPrivateKey', generated_private_key)


def create_managed_issuing_ca(
    *,
    issuer_private_key: ManagedRSAPrivateKey,
    issuer_cn: str,
    subject_cn: str,
) -> tuple[x509.Certificate, ManagedRSAPrivateKey]:
    """Create an issuing CA certificate with a backend-managed private key."""
    private_key = create_managed_ca_private_key(subject_cn.lower().replace(' ', '-'))
    certificate, generated_private_key = CertificateGenerator.create_issuing_ca(
        issuer_private_key=issuer_private_key,
        issuer_cn=issuer_cn,
        subject_cn=subject_cn,
        private_key=private_key,
    )
    return certificate, cast('ManagedRSAPrivateKey', generated_private_key)
