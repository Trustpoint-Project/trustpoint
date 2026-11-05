# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared CMP certificate-confirmation digest resolution and credential lookup."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from trustpoint_core.oid import HashAlgorithm, SignatureSuite

from pki.models import IssuedCredentialModel

CERTCONF_ALLOWED_DIGESTS: dict[HashAlgorithm, type[hashes.HashAlgorithm]] = {
    HashAlgorithm.SHA224: hashes.SHA224,
    HashAlgorithm.SHA256: hashes.SHA256,
    HashAlgorithm.SHA384: hashes.SHA384,
    HashAlgorithm.SHA512: hashes.SHA512,
    HashAlgorithm.SHA3_224: hashes.SHA3_224,
    HashAlgorithm.SHA3_256: hashes.SHA3_256,
    HashAlgorithm.SHA3_384: hashes.SHA3_384,
    HashAlgorithm.SHA3_512: hashes.SHA3_512,
}


def resolve_certconf_hash_algorithm(algorithm_oid: str | None) -> hashes.HashAlgorithm:
    """Resolve an allowed digest, preserving the legacy SHA-256 default."""
    if not algorithm_oid:
        return hashes.SHA256()
    try:
        algorithm = HashAlgorithm.from_dotted_string(algorithm_oid)
    except ValueError as exc:
        msg = f'certConf hashAlg OID {algorithm_oid!r} is unsupported.'
        raise ValueError(msg) from exc
    factory = CERTCONF_ALLOWED_DIGESTS.get(algorithm)
    if factory is None:
        msg = f'certConf hashAlg OID {algorithm_oid!r} is not permitted.'
        raise TypeError(msg)
    return factory()


def resolve_issued_credential_by_cert_hash(
    cert_hash: bytes,
    hash_algorithm: hashes.HashAlgorithm,
    *,
    require_implicit_hash: bool,
) -> IssuedCredentialModel | None:
    """Use the stored SHA-256 fingerprint or calculate another allowed certificate digest."""
    cert_hash_hex = cert_hash.hex().upper()

    if isinstance(hash_algorithm, hashes.SHA256):
        issued_cred = (
            IssuedCredentialModel.objects.filter(credential__certificate__sha256_fingerprint=cert_hash_hex)
            .select_related('domain', 'device', 'credential__certificate')
            .first()
        )
        if issued_cred is None:
            return None
        if require_implicit_hash:
            signature_hash = SignatureSuite.from_certificate(
                issued_cred.credential.get_certificate()
            ).algorithm_identifier.hash_algorithm
            if signature_hash is None:
                msg = 'certConf hashAlg is required for certificates whose signature algorithm has no implicit hash.'
                raise ValueError(msg)
        return issued_cred

    issued_credentials = IssuedCredentialModel.objects.select_related('domain', 'device', 'credential__certificate')
    for issued_cred in issued_credentials.iterator():
        certificate = issued_cred.credential.get_certificate()
        certificate_der = certificate.public_bytes(Encoding.DER)
        digest_ctx = hashes.Hash(hash_algorithm)
        digest_ctx.update(certificate_der)
        if digest_ctx.finalize() == cert_hash:
            return issued_cred
    return None
