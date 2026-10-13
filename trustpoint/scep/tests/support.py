# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Test-only helpers that build SCEP client messages and read CertRep responses."""

from __future__ import annotations

import datetime
import hashlib
import os
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import AttributeOID, NameOID
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import char, univ
from pyasn1_modules import rfc5280, rfc5652

from scep.protocol import cms
from scep.protocol.oids import (
    OID_AES128_CBC,
    OID_ATTR_CONTENT_TYPE,
    OID_ATTR_MESSAGE_DIGEST,
    OID_DATA,
    OID_ECDSA_WITH_SHA256,
    OID_FAIL_INFO,
    OID_MESSAGE_TYPE,
    OID_PKI_STATUS,
    OID_RECIPIENT_NONCE,
    OID_RSA_ENCRYPTION,
    OID_SENDER_NONCE,
    OID_SHA256,
    OID_TRANSACTION_ID,
    MessageType,
)
from scep.protocol.pwri import unwrap_password_recipient_info

from cryptography.hazmat.primitives import padding as sympad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def make_key(kind: str) -> Any:
    """Create a client key: 'rsa', 'rsa1024', 'p256', 'p384' or 'p521'."""
    if kind == 'rsa':
        return rsa.generate_private_key(65537, 2048)
    if kind == 'rsa1024':
        return rsa.generate_private_key(65537, 1024)
    return ec.generate_private_key({'p256': ec.SECP256R1(), 'p384': ec.SECP384R1(), 'p521': ec.SECP521R1()}[kind])


def make_csr(key: Any, cn: str, challenge: str | None = None, sans: list[str] | None = None) -> x509.CertificateSigningRequest:
    """Create a PKCS #10 request."""
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    )
    if challenge is not None:
        builder = builder.add_attribute(AttributeOID.CHALLENGE_PASSWORD, challenge.encode())
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    return builder.sign(key, hashes.SHA256())


def make_self_signed(key: Any, cn: str) -> x509.Certificate:
    """Create the self-signed signer certificate used for PKCSReq."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.KeyUsage(True, False, isinstance(key, rsa.RSAPrivateKey), False, False, False, False, False, False),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )


def _attr(oid: univ.ObjectIdentifier, value: Any) -> rfc5652.Attribute:
    attr = rfc5652.Attribute()
    attr['attrType'] = oid
    attr['attrValues'].append(univ.Any(der_encoder.encode(value)))
    return attr


def build_request(  # noqa: PLR0913
    *,
    signer_key: Any,
    signer_cert: x509.Certificate,
    server_cert: x509.Certificate,
    csr: x509.CertificateSigningRequest | bytes,
    message_type: MessageType = MessageType.PKCS_REQ,
    transaction_id: str = 'tx-1',
    nonce: bytes | None = None,
    corrupt_signature: bool = False,
    omit_attributes: tuple[str, ...] = (),
    envelope: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Build a pkiMessage; returns (message DER, sender nonce)."""
    nonce = nonce or os.urandom(16)
    csr_der = csr if isinstance(csr, bytes) else csr.public_bytes(serialization.Encoding.DER)
    econtent = envelope or cms.encrypt_pkcs_pki_envelope(csr_der, cms.KeyTransRecipient(server_cert))

    attrs = {
        'contentType': _attr(OID_ATTR_CONTENT_TYPE, OID_DATA),
        'messageDigest': _attr(OID_ATTR_MESSAGE_DIGEST, univ.OctetString(hashlib.sha256(econtent).digest())),
        'transactionID': _attr(OID_TRANSACTION_ID, char.PrintableString(transaction_id)),
        'messageType': _attr(OID_MESSAGE_TYPE, char.PrintableString(str(int(message_type)))),
        'senderNonce': _attr(OID_SENDER_NONCE, univ.OctetString(nonce)),
    }
    signed = rfc5652.SignedAttributes()
    for name, attr in attrs.items():
        if name not in omit_attributes:
            signed.append(attr)
    to_sign = der_encoder.encode(signed)
    if isinstance(signer_key, rsa.RSAPrivateKey):
        signature = signer_key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())
        sig_oid = OID_RSA_ENCRYPTION
    else:
        signature = signer_key.sign(to_sign, ec.ECDSA(hashes.SHA256()))
        sig_oid = OID_ECDSA_WITH_SHA256
    if corrupt_signature:
        signature = bytes([signature[0] ^ 0xFF]) + signature[1:]

    sd = rfc5652.SignedData()
    sd['version'] = 1
    sd['digestAlgorithms'].append(rfc5280.AlgorithmIdentifier().setComponentByName('algorithm', OID_SHA256))
    sd['encapContentInfo']['eContentType'] = OID_DATA
    sd['encapContentInfo']['eContent'] = econtent
    decoded, _ = der_decoder.decode(signer_cert.public_bytes(serialization.Encoding.DER), asn1Spec=rfc5280.Certificate())
    sd['certificates'][0]['certificate'] = decoded
    signer = sd['signerInfos'][0]
    signer['version'] = 1
    issuer, _ = der_decoder.decode(signer_cert.issuer.public_bytes(), asn1Spec=rfc5280.Name())
    signer['sid']['issuerAndSerialNumber']['issuer'] = issuer
    signer['sid']['issuerAndSerialNumber']['serialNumber'] = signer_cert.serial_number
    signer['digestAlgorithm']['algorithm'] = OID_SHA256
    for index, attr in enumerate(signed):
        signer['signedAttrs'][index] = attr
    signer['signatureAlgorithm']['algorithm'] = sig_oid
    signer['signature'] = signature
    content_info = rfc5652.ContentInfo()
    content_info['contentType'] = rfc5652.id_signedData
    content_info['content'] = univ.Any(der_encoder.encode(sd))
    return der_encoder.encode(content_info), nonce


@dataclass
class CertRep:
    """A decoded CertRep."""

    attributes: dict[str, Any]
    econtent: bytes | None
    certificates: list[x509.Certificate]
    signature_valid: bool

    @property
    def status(self) -> int:
        """pkiStatus as integer."""
        return int(str(self.attributes[str(OID_PKI_STATUS)]))

    @property
    def fail_text(self) -> str:
        """failInfoText if present."""
        return str(self.attributes.get('1.3.6.1.5.5.7.24.1', ''))

    @property
    def fail_info(self) -> int:
        """failInfo as integer."""
        return int(str(self.attributes[str(OID_FAIL_INFO)]))

    @property
    def recipient_nonce(self) -> bytes:
        """The echoed nonce."""
        return bytes(self.attributes[str(OID_RECIPIENT_NONCE)])

    @property
    def transaction_id(self) -> str:
        """The transactionID."""
        return str(self.attributes[str(OID_TRANSACTION_ID)])


def parse_cert_rep(data: bytes) -> CertRep:
    """Decode a CertRep and verify its signature against the embedded server certificate."""
    content_info, _ = ber_decoder.decode(data, asn1Spec=rfc5652.ContentInfo())
    sd, _ = ber_decoder.decode(content_info['content'], asn1Spec=rfc5652.SignedData())
    certs = [
        x509.load_der_x509_certificate(der_encoder.encode(c['certificate'])) for c in sd['certificates']
    ]
    signer = sd['signerInfos'][0]
    attributes: dict[str, Any] = {}
    signed = rfc5652.SignedAttributes()
    for attr in signer['signedAttrs']:
        signed.append(attr)
        raw = bytes(attr['attrValues'][0])
        value, _ = ber_decoder.decode(raw)
        attributes[str(attr['attrType'])] = value
    econtent = bytes(sd['encapContentInfo']['eContent']) if sd['encapContentInfo']['eContent'].isValue else None
    try:
        certs[0].public_key().verify(bytes(signer['signature']), der_encoder.encode(signed), padding.PKCS1v15(), hashes.SHA256())
        ok = bytes(attributes[str(OID_ATTR_MESSAGE_DIGEST)]) == hashlib.sha256(econtent or b'').digest()
    except Exception:  # noqa: BLE001
        ok = False
    return CertRep(attributes, econtent, certs, ok)


def decrypt_cert_rep(rep: CertRep, *, key: Any = None, password: str | None = None) -> list[x509.Certificate]:
    """Decrypt a SUCCESS CertRep with an RSA key (KTRI) or a password (PWRI) and return the certificates."""
    assert rep.econtent is not None  # noqa: S101
    content_info, _ = ber_decoder.decode(rep.econtent, asn1Spec=rfc5652.ContentInfo())
    env, _ = ber_decoder.decode(content_info['content'], asn1Spec=rfc5652.EnvelopedData())
    ri = env['recipientInfos'][0]
    if ri.getName() == 'ktri':
        cek = key.decrypt(bytes(ri['ktri']['encryptedKey']), padding.PKCS1v15())
    else:
        assert password is not None  # noqa: S101
        cek = unwrap_password_recipient_info(ri['pwri'], password)
    eci = env['encryptedContentInfo']
    assert eci['contentEncryptionAlgorithm']['algorithm'] == OID_AES128_CBC  # noqa: S101
    iv, _ = der_decoder.decode(bytes(eci['contentEncryptionAlgorithm']['parameters']), asn1Spec=univ.OctetString())
    dec = Cipher(algorithms.AES(cek), modes.CBC(bytes(iv))).decryptor()
    padded = dec.update(bytes(eci['encryptedContent'])) + dec.finalize()
    unpad = sympad.PKCS7(128).unpadder()
    inner = unpad.update(padded) + unpad.finalize()
    ci, _ = ber_decoder.decode(inner, asn1Spec=rfc5652.ContentInfo())
    sd, _ = ber_decoder.decode(ci['content'], asn1Spec=rfc5652.SignedData())
    certs = [x509.load_der_x509_certificate(der_encoder.encode(c['certificate'])) for c in sd['certificates']]
    # DER SET OF ordering is not meaningful: return the leaf (not an issuer of any other certificate) first.
    return sorted(certs, key=lambda c: any(o.issuer == c.subject and o is not c for o in certs))
