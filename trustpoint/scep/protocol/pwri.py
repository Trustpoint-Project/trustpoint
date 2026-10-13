# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""CMS PasswordRecipientInfo (RFC 5652 section 6.2.4) with the RFC 3211 key wrap."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_modules import rfc5280, rfc5652, rfc8018

from scep.protocol.oids import (
    AES128_KEY_BYTES,
    AES_BLOCK_BYTES,
    OID_AES128_CBC,
    OID_HMAC_SHA256,
    OID_PBKDF2,
    OID_PWRI_KEK,
)

PBKDF2_ITERATIONS = 10_000
PBKDF2_SALT_BYTES = 16
PWRI_VERSION = 0


class PasswordRecipientError(ValueError):
    """The PasswordRecipientInfo cannot be processed (wrong password, unsupported parameters, corrupt data)."""


def _cbc(key: bytes, iv: bytes, data: bytes, *, encrypt: bool) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    ctx = cipher.encryptor() if encrypt else cipher.decryptor()
    return ctx.update(data) + ctx.finalize()


def _ecb_decrypt_block(key: bytes, block: bytes) -> bytes:
    ctx = Cipher(algorithms.AES(key), modes.ECB()).decryptor()  # noqa: S305 - single block of the RFC 3211 unwrap
    return ctx.update(block) + ctx.finalize()


def derive_kek(password: str, salt: bytes, iterations: int) -> bytes:
    """Derive the AES-128 key-encryption key from the shared secret."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=AES128_KEY_BYTES, salt=salt, iterations=iterations)
    return kdf.derive(password.encode('utf-8'))


def wrap_cek(cek: bytes, kek: bytes, iv: bytes) -> bytes:
    """Wrap a content-encryption key as specified in RFC 3211 section 2.3.1."""
    inner = bytes([len(cek)]) + bytes(b ^ 0xFF for b in cek[:3]) + cek
    padded_length = max(2 * AES_BLOCK_BYTES, -(-len(inner) // AES_BLOCK_BYTES) * AES_BLOCK_BYTES)
    inner += os.urandom(padded_length - len(inner))
    first_pass = _cbc(kek, iv, inner, encrypt=True)
    return _cbc(kek, first_pass[-AES_BLOCK_BYTES:], first_pass, encrypt=True)


def unwrap_cek(wrapped: bytes, kek: bytes, iv: bytes) -> bytes:
    """Unwrap a content-encryption key as specified in RFC 3211 section 2.3.2."""
    if len(wrapped) % AES_BLOCK_BYTES or len(wrapped) < 2 * AES_BLOCK_BYTES:
        msg = 'Invalid wrapped key length.'
        raise PasswordRecipientError(msg)
    last_block_first_pass = bytes(
        a ^ b for a, b in zip(_ecb_decrypt_block(kek, wrapped[-AES_BLOCK_BYTES:]),
                              wrapped[-2 * AES_BLOCK_BYTES : -AES_BLOCK_BYTES], strict=True)
    )
    first_pass = _cbc(kek, last_block_first_pass, wrapped, encrypt=False)
    inner = _cbc(kek, iv, first_pass, encrypt=False)
    length = inner[0]
    cek = inner[4 : 4 + length]
    check = inner[1:4]
    if length < 3 or len(cek) != length or check != bytes(b ^ 0xFF for b in cek[:3]):  # noqa: PLR2004
        msg = 'Key check value mismatch.'
        raise PasswordRecipientError(msg)
    return cek


def build_password_recipient_info(password: str, cek: bytes) -> rfc5652.RecipientInfo:
    """Create a PasswordRecipientInfo wrapping ``cek`` with a KEK derived from ``password``."""
    salt = os.urandom(PBKDF2_SALT_BYTES)
    iv = os.urandom(AES_BLOCK_BYTES)
    kek = derive_kek(password, salt, PBKDF2_ITERATIONS)

    pbkdf2_params = rfc8018.PBKDF2_params()
    pbkdf2_params['salt']['specified'] = salt
    pbkdf2_params['iterationCount'] = PBKDF2_ITERATIONS
    pbkdf2_params['keyLength'] = AES128_KEY_BYTES
    pbkdf2_params['prf']['algorithm'] = OID_HMAC_SHA256
    pbkdf2_params['prf']['parameters'] = univ.Any(encoder.encode(univ.Null('')))

    kdf_alg = rfc5280.AlgorithmIdentifier()
    kdf_alg['algorithm'] = OID_PBKDF2
    kdf_alg['parameters'] = univ.Any(encoder.encode(pbkdf2_params))

    kek_cipher = rfc5280.AlgorithmIdentifier()
    kek_cipher['algorithm'] = OID_AES128_CBC
    kek_cipher['parameters'] = univ.Any(encoder.encode(univ.OctetString(iv)))

    recipient = rfc5652.RecipientInfo()
    pwri = recipient['pwri']
    pwri['version'] = PWRI_VERSION
    pwri['keyDerivationAlgorithm']['algorithm'] = kdf_alg['algorithm']
    pwri['keyDerivationAlgorithm']['parameters'] = kdf_alg['parameters']
    pwri['keyEncryptionAlgorithm']['algorithm'] = OID_PWRI_KEK
    pwri['keyEncryptionAlgorithm']['parameters'] = univ.Any(encoder.encode(kek_cipher))
    pwri['encryptedKey'] = wrap_cek(cek, kek, iv)
    return recipient


def unwrap_password_recipient_info(pwri: rfc5652.PasswordRecipientInfo, password: str) -> bytes:
    """Recover the content-encryption key from a PasswordRecipientInfo using ``password``."""
    try:
        if pwri['keyEncryptionAlgorithm']['algorithm'] != OID_PWRI_KEK:
            msg = 'Unsupported key encryption algorithm.'
            raise PasswordRecipientError(msg)
        if not pwri['keyDerivationAlgorithm'].isValue or pwri['keyDerivationAlgorithm']['algorithm'] != OID_PBKDF2:
            msg = 'Unsupported key derivation algorithm.'
            raise PasswordRecipientError(msg)

        kek_cipher, _ = decoder.decode(bytes(pwri['keyEncryptionAlgorithm']['parameters']),
                                       asn1Spec=rfc5280.AlgorithmIdentifier())
        if kek_cipher['algorithm'] != OID_AES128_CBC:
            msg = 'Unsupported key wrap cipher.'
            raise PasswordRecipientError(msg)
        iv_obj, _ = decoder.decode(bytes(kek_cipher['parameters']), asn1Spec=univ.OctetString())
        params, _ = decoder.decode(bytes(pwri['keyDerivationAlgorithm']['parameters']), asn1Spec=rfc8018.PBKDF2_params())
        if params['prf'].isValue and params['prf']['algorithm'] != OID_HMAC_SHA256:
            msg = 'Unsupported PBKDF2 PRF.'
            raise PasswordRecipientError(msg)
        kek = derive_kek(password, bytes(params['salt']['specified']), int(params['iterationCount']))
        return unwrap_cek(bytes(pwri['encryptedKey']), kek, bytes(iv_obj))
    except PasswordRecipientError:
        raise
    except Exception as exc:
        msg = 'Malformed PasswordRecipientInfo.'
        raise PasswordRecipientError(msg) from exc
