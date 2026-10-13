# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""CMS handling for SCEP pkiMessages (RFC 8894 sections 3.1 - 3.4) using pyasn1 and cryptography."""

from __future__ import annotations

import datetime
import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import char, univ, useful
from pyasn1_modules import rfc5280, rfc5652

from scep.protocol.errors import ScepMalformedMessageError, ScepProtocolError
from scep.protocol.oids import (
    AES128_KEY_BYTES,
    AES_BLOCK_BYTES,
    MAX_CERTIFICATES,
    MAX_RECIPIENT_INFOS,
    MAX_REQUEST_BYTES,
    MAX_SIGNED_ATTRIBUTES,
    MAX_TRANSACTION_ID_LENGTH,
    NONCE_LENGTH,
    OID_AES128_CBC,
    OID_ATTR_CONTENT_TYPE,
    OID_ATTR_MESSAGE_DIGEST,
    OID_ATTR_SIGNING_TIME,
    OID_DATA,
    OID_ECDSA_WITH_SHA256,
    OID_ENVELOPED_DATA,
    OID_FAIL_INFO,
    OID_FAIL_INFO_TEXT,
    OID_MESSAGE_TYPE,
    OID_PKI_STATUS,
    OID_RECIPIENT_NONCE,
    OID_RSA_ENCRYPTION,
    OID_SENDER_NONCE,
    OID_SHA256,
    OID_SHA256_WITH_RSA,
    OID_SIGNED_DATA,
    OID_TRANSACTION_ID,
    FailInfo,
    MessageType,
    PkiStatus,
)
from scep.protocol.pwri import build_password_recipient_info

if TYPE_CHECKING:
    from collections.abc import Sequence

MIN_RSA_KEY_BITS = 2048
ALLOWED_EC_CURVES = (ec.SECP256R1, ec.SECP384R1)
_PRINTABLE_RE = re.compile(r"^[A-Za-z0-9 '()+,\-./:=?]+$")
_DECRYPT_FAILURE_TEXT = 'Unable to decrypt the pkcsPKIEnvelope.'


@dataclass(frozen=True)
class KeyTransRecipient:
    """Encrypt to the RSA key of a certificate using CMS KeyTransRecipientInfo."""

    certificate: x509.Certificate


@dataclass(frozen=True)
class PasswordRecipient:
    """Encrypt with a shared secret using CMS PasswordRecipientInfo."""

    password: str


@dataclass(frozen=True)
class ParsedPkiMessage:
    """A parsed, but not yet signature-verified, SCEP pkiMessage."""

    transaction_id: str
    message_type: int
    sender_nonce: bytes
    signer_certificate: x509.Certificate | None
    certificates: tuple[x509.Certificate, ...]
    enveloped_data: bytes | None
    digest_algorithm_oid: str
    signature_algorithm_oid: str
    signature: bytes
    signed_attributes_der: bytes
    message_digest: bytes
    content_type_oid: str | None


def check_public_key_policy(public_key: object) -> None:
    """Enforce the supported key types: RSA >= 2048 bit and ECDSA P-256 / P-384."""
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < MIN_RSA_KEY_BITS:
            raise ScepProtocolError(FailInfo.BAD_ALG, 'RSA keys must be at least 2048 bits.')
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if not isinstance(public_key.curve, ALLOWED_EC_CURVES):
            raise ScepProtocolError(FailInfo.BAD_ALG, 'Only the NIST P-256 and P-384 curves are supported.')
        return
    raise ScepProtocolError(FailInfo.BAD_ALG, 'Unsupported public key type.')


def _decode(data: bytes | Any, spec: Any) -> Any:
    try:
        obj, rest = ber_decoder.decode(data, asn1Spec=spec)
    except (PyAsn1Error, ValueError, IndexError) as exc:
        msg = 'Malformed ASN.1 structure.'
        raise ScepMalformedMessageError(msg) from exc
    if rest:
        msg = 'Trailing data after ASN.1 structure.'
        raise ScepMalformedMessageError(msg)
    return obj


def _single_attribute(attributes: dict[str, list[Any]], oid: univ.ObjectIdentifier) -> Any | None:
    values = attributes.get(str(oid))
    if values is None:
        return None
    if len(values) != 1:
        msg = f'Attribute {oid} must carry exactly one value.'
        raise ScepMalformedMessageError(msg)
    return values[0]


def _decode_value(any_value: Any, spec: Any) -> Any:
    return _decode(bytes(any_value), spec)


def _printable(attributes: dict[str, list[Any]], oid: univ.ObjectIdentifier) -> str | None:
    raw = _single_attribute(attributes, oid)
    if raw is None:
        return None
    value = _decode_value(raw, char.PrintableString())
    text = str(value)
    if not text or len(text) > MAX_TRANSACTION_ID_LENGTH or not _PRINTABLE_RE.match(text):
        msg = f'Attribute {oid} is not a valid PrintableString.'
        raise ScepMalformedMessageError(msg)
    return text


def _load_certificates(sd: rfc5652.SignedData) -> tuple[x509.Certificate, ...]:
    certificates: list[x509.Certificate] = []
    if not sd['certificates'].isValue:
        return ()
    if len(sd['certificates']) > MAX_CERTIFICATES:
        msg = 'Too many certificates in the message.'
        raise ScepMalformedMessageError(msg)
    for choice in sd['certificates']:
        if choice.getName() != 'certificate':
            continue
        try:
            certificates.append(x509.load_der_x509_certificate(der_encoder.encode(choice['certificate'])))
        except (PyAsn1Error, ValueError) as exc:
            msg = 'Malformed certificate in the message.'
            raise ScepMalformedMessageError(msg) from exc
    return tuple(certificates)


def _issuer_der(cert: x509.Certificate) -> bytes:
    return cert.issuer.public_bytes()


def _matches_sid(cert: x509.Certificate, sid: Any) -> bool:
    if sid.getName() == 'issuerAndSerialNumber':
        iasn = sid['issuerAndSerialNumber']
        return (
            int(iasn['serialNumber']) == cert.serial_number
            and der_encoder.encode(iasn['issuer']) == _issuer_der(cert)
        )
    try:
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    except x509.ExtensionNotFound:
        return False
    return bytes(sid['subjectKeyIdentifier']) == ski


def parse_pki_message(data: bytes) -> ParsedPkiMessage:  # noqa: C901
    """Parse the structure of a pkiMessage. The signature is not verified here, see :func:`verify_signature`."""
    if len(data) > MAX_REQUEST_BYTES:
        msg = 'Request too large.'
        raise ScepMalformedMessageError(msg)
    content_info = _decode(data, rfc5652.ContentInfo())
    if content_info['contentType'] != OID_SIGNED_DATA:
        msg = 'The pkiMessage must be a CMS SignedData.'
        raise ScepMalformedMessageError(msg)
    sd = _decode(content_info['content'], rfc5652.SignedData())

    if len(sd['signerInfos']) != 1:
        msg = 'Exactly one SignerInfo is required.'
        raise ScepMalformedMessageError(msg)
    signer = sd['signerInfos'][0]
    if not signer['signedAttrs'].isValue:
        msg = 'The SignerInfo must contain signed attributes.'
        raise ScepMalformedMessageError(msg)
    if len(signer['signedAttrs']) > MAX_SIGNED_ATTRIBUTES:
        msg = 'Too many signed attributes.'
        raise ScepMalformedMessageError(msg)

    attributes: dict[str, list[Any]] = {}
    signed_attrs = rfc5652.SignedAttributes()
    for attr in signer['signedAttrs']:
        attributes.setdefault(str(attr['attrType']), []).extend(list(attr['attrValues']))
        signed_attrs.append(attr)

    transaction_id = _printable(attributes, OID_TRANSACTION_ID)
    message_type_text = _printable(attributes, OID_MESSAGE_TYPE)
    nonce_raw = _single_attribute(attributes, OID_SENDER_NONCE)
    if transaction_id is None or message_type_text is None or nonce_raw is None:
        msg = 'transactionID, messageType and senderNonce are required.'
        raise ScepMalformedMessageError(msg)
    if not message_type_text.isdigit():
        msg = 'messageType must be a decimal number.'
        raise ScepMalformedMessageError(msg)
    sender_nonce = bytes(_decode_value(nonce_raw, univ.OctetString()))
    if len(sender_nonce) != NONCE_LENGTH:
        msg = 'senderNonce must be 16 bytes.'
        raise ScepMalformedMessageError(msg)

    digest_raw = _single_attribute(attributes, OID_ATTR_MESSAGE_DIGEST)
    message_digest = bytes(_decode_value(digest_raw, univ.OctetString())) if digest_raw is not None else b''
    content_type_raw = _single_attribute(attributes, OID_ATTR_CONTENT_TYPE)
    content_type_oid = str(
        _decode_value(
            content_type_raw,
            univ.ObjectIdentifier()
            )
            ) if content_type_raw is not None else None

    econtent = sd['encapContentInfo']['eContent']
    if sd['encapContentInfo']['eContentType'] != OID_DATA:
        msg = 'The eContentType must be id-data.'
        raise ScepMalformedMessageError(msg)

    certificates = _load_certificates(sd)
    signer_certificate = next((c for c in certificates if _matches_sid(c, signer['sid'])), None)

    return ParsedPkiMessage(
        transaction_id=transaction_id,
        message_type=int(message_type_text),
        sender_nonce=sender_nonce,
        signer_certificate=signer_certificate,
        certificates=certificates,
        enveloped_data=bytes(econtent) if econtent.isValue else None,
        digest_algorithm_oid=str(signer['digestAlgorithm']['algorithm']),
        signature_algorithm_oid=str(signer['signatureAlgorithm']['algorithm']),
        signature=bytes(signer['signature']),
        signed_attributes_der=der_encoder.encode(signed_attrs),
        message_digest=message_digest,
        content_type_oid=content_type_oid,
    )


def verify_signature(message: ParsedPkiMessage) -> x509.Certificate:
    """Verify the CMS signature, the messageDigest and the contentType attribute; returns the signer certificate."""
    if message.digest_algorithm_oid != str(OID_SHA256):
        raise ScepProtocolError(FailInfo.BAD_ALG, 'Only SHA-256 is supported.')
    cert = message.signer_certificate
    if cert is None:
        raise ScepProtocolError(FailInfo.BAD_MESSAGE_CHECK, 'The signer certificate is not included in the message.')
    public_key = cert.public_key()
    check_public_key_policy(public_key)

    if message.content_type_oid != str(OID_DATA):
        raise ScepProtocolError(FailInfo.BAD_MESSAGE_CHECK, 'The contentType attribute must be id-data.')
    expected_digest = hashlib.sha256(message.enveloped_data or b'').digest()
    if not hmac.compare_digest(expected_digest, message.message_digest):
        raise ScepProtocolError(FailInfo.BAD_MESSAGE_CHECK, 'The messageDigest attribute does not match the content.')

    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            if message.signature_algorithm_oid not in {str(OID_RSA_ENCRYPTION), str(OID_SHA256_WITH_RSA)}:
                raise ScepProtocolError(FailInfo.BAD_ALG, 'Unsupported RSA signature algorithm.')
            public_key.verify(message.signature, message.signed_attributes_der, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if message.signature_algorithm_oid != str(OID_ECDSA_WITH_SHA256):
                raise ScepProtocolError(FailInfo.BAD_ALG, 'Unsupported ECDSA signature algorithm.')
            public_key.verify(message.signature, message.signed_attributes_der, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise ScepProtocolError(FailInfo.BAD_MESSAGE_CHECK, 'The CMS signature is invalid.') from None
    return cert


def decrypt_pkcs_pki_envelope(  # noqa: C901, PLR0912
    enveloped: bytes, server_key: rsa.RSAPrivateKey, server_cert: x509.Certificate
) -> bytes:
    """Decrypt the pkcsPKIEnvelope with the SCEP server RSA key (KeyTransRecipientInfo only)."""
    try:
        content_info = _decode(enveloped, rfc5652.ContentInfo())
        if content_info['contentType'] != OID_ENVELOPED_DATA:
            raise ScepProtocolError(FailInfo.BAD_REQUEST, 'The pkcsPKIEnvelope must be CMS EnvelopedData.')
        env = _decode(content_info['content'], rfc5652.EnvelopedData())
    except ScepMalformedMessageError as exc:
        raise ScepProtocolError(FailInfo.BAD_REQUEST, 'Malformed pkcsPKIEnvelope.') from exc

    if len(env['recipientInfos']) > MAX_RECIPIENT_INFOS:
        raise ScepProtocolError(FailInfo.BAD_REQUEST, 'Too many recipients.')
    ktris = [ri['ktri'] for ri in env['recipientInfos'] if ri.getName() == 'ktri']
    if not ktris:
        raise ScepProtocolError(FailInfo.BAD_ALG, 'A KeyTransRecipientInfo for the SCEP server is required.')
    own = [k for k in ktris if _matches_rid(server_cert, k['rid'])]
    if not own:
        raise ScepProtocolError(FailInfo.BAD_CERT_ID, 'No recipient matches the SCEP server certificate.')
    ktri = own[0]
    if ktri['keyEncryptionAlgorithm']['algorithm'] != OID_RSA_ENCRYPTION:
        raise ScepProtocolError(FailInfo.BAD_ALG, 'Only RSA (PKCS #1 v1.5) key transport is supported.')

    eci = env['encryptedContentInfo']
    if eci['contentType'] != OID_DATA or not eci['encryptedContent'].isValue:
        raise ScepProtocolError(FailInfo.BAD_REQUEST, 'The encrypted content must be id-data.')
    if eci['contentEncryptionAlgorithm']['algorithm'] != OID_AES128_CBC:
        raise ScepProtocolError(FailInfo.BAD_ALG, 'Only AES-128-CBC content encryption is supported.')
    try:
        iv = bytes(_decode_value(eci['contentEncryptionAlgorithm']['parameters'], univ.OctetString()))
    except ScepMalformedMessageError:
        raise ScepProtocolError(FailInfo.BAD_ALG, 'Invalid AES-128-CBC parameters.') from None
    ciphertext = bytes(eci['encryptedContent'])
    if len(iv) != AES_BLOCK_BYTES or not ciphertext or len(ciphertext) % AES_BLOCK_BYTES:
        raise ScepProtocolError(FailInfo.BAD_MESSAGE_CHECK, _DECRYPT_FAILURE_TEXT)

    # Never reveal whether the PKCS #1 v1.5 unwrap failed: continue with a random key instead.
    try:
        cek = server_key.decrypt(bytes(ktri['encryptedKey']), padding.PKCS1v15())
    except ValueError:
        cek = b''
    if len(cek) != AES128_KEY_BYTES:
        cek = os.urandom(AES128_KEY_BYTES)
    try:
        decryptor = Cipher(algorithms.AES(cek), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(AES_BLOCK_BYTES * 8).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        raise ScepProtocolError(FailInfo.BAD_MESSAGE_CHECK, _DECRYPT_FAILURE_TEXT) from None


def _matches_rid(cert: x509.Certificate, rid: Any) -> bool:
    if rid.getName() == 'issuerAndSerialNumber':
        return _matches_sid(cert, rid)
    try:
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    except x509.ExtensionNotFound:
        return False
    return bytes(rid['subjectKeyIdentifier']) == ski


def _issuer_and_serial(target: Any, cert: x509.Certificate) -> None:
    issuer, _ = der_decoder.decode(_issuer_der(cert), asn1Spec=rfc5280.Name())
    target['issuer'] = issuer
    target['serialNumber'] = cert.serial_number


def _any(value: Any) -> univ.Any:
    return univ.Any(der_encoder.encode(value))


def _alg(oid: univ.ObjectIdentifier, parameters: Any | None = None) -> rfc5280.AlgorithmIdentifier:
    alg = rfc5280.AlgorithmIdentifier()
    alg['algorithm'] = oid
    if parameters is not None:
        alg['parameters'] = _any(parameters)
    return alg


def encrypt_pkcs_pki_envelope(data: bytes, recipient: KeyTransRecipient | PasswordRecipient) -> bytes:
    """Encrypt ``data`` with AES-128-CBC and wrap the key for the recipient; returns a DER ContentInfo."""
    cek = os.urandom(AES128_KEY_BYTES)
    iv = os.urandom(AES_BLOCK_BYTES)
    padder = sym_padding.PKCS7(AES_BLOCK_BYTES * 8).padder()
    encryptor = Cipher(algorithms.AES(cek), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padder.update(data) + padder.finalize()) + encryptor.finalize()

    env = rfc5652.EnvelopedData()
    if isinstance(recipient, KeyTransRecipient):
        public_key = recipient.certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            msg = 'Key transport requires an RSA recipient key.'
            raise TypeError(msg)
        env['version'] = 0
        recipient_info = rfc5652.RecipientInfo()
        ktri = recipient_info['ktri']
        ktri['version'] = 0
        _issuer_and_serial(ktri['rid']['issuerAndSerialNumber'], recipient.certificate)
        ktri['keyEncryptionAlgorithm']['algorithm'] = OID_RSA_ENCRYPTION
        ktri['keyEncryptionAlgorithm']['parameters'] = _any(univ.Null(''))
        ktri['encryptedKey'] = public_key.encrypt(cek, padding.PKCS1v15())
    else:
        env['version'] = 3
        recipient_info = build_password_recipient_info(recipient.password, cek)
    env['recipientInfos'].append(recipient_info)

    eci = env['encryptedContentInfo']
    eci['contentType'] = OID_DATA
    eci['contentEncryptionAlgorithm']['algorithm'] = OID_AES128_CBC
    eci['contentEncryptionAlgorithm']['parameters'] = _any(univ.OctetString(iv))
    eci['encryptedContent'] = ciphertext
    return _wrap_content_info(OID_ENVELOPED_DATA, env)


def _wrap_content_info(content_type: univ.ObjectIdentifier, content: Any) -> bytes:
    content_info = rfc5652.ContentInfo()
    content_info['contentType'] = content_type
    content_info['content'] = _any(content)
    return der_encoder.encode(content_info)


def build_degenerate_certificates_only(certificates: Sequence[x509.Certificate]) -> bytes:
    """Build a certificates-only CMS SignedData (RFC 8894 section 3.4); the first certificate is the leaf."""
    sd = rfc5652.SignedData()
    sd['version'] = 1
    sd['digestAlgorithms'].clear()
    sd['encapContentInfo']['eContentType'] = OID_DATA
    for index, cert in enumerate(certificates):
        decoded, _ = der_decoder.decode(cert.public_bytes(serialization.Encoding.DER), asn1Spec=rfc5280.Certificate())
        sd['certificates'][index]['certificate'] = decoded
    sd['signerInfos'].clear()
    return _wrap_content_info(OID_SIGNED_DATA, sd)


def _attribute(oid: univ.ObjectIdentifier, value: Any) -> rfc5652.Attribute:
    attr = rfc5652.Attribute()
    attr['attrType'] = oid
    attr['attrValues'].append(_any(value))
    return attr


def build_cert_rep(  # noqa: PLR0913
    *,
    server_key: rsa.RSAPrivateKey,
    server_cert: x509.Certificate,
    transaction_id: str,
    recipient_nonce: bytes,
    status: PkiStatus,
    message_data: bytes | None = None,
    recipient: KeyTransRecipient | PasswordRecipient | None = None,
    fail_info: FailInfo | None = None,
    fail_text: str | None = None,
) -> bytes:
    """Build a signed CertRep. For SUCCESS the messageData is encrypted to ``recipient``; otherwise it is omitted."""
    econtent: bytes | None = None
    if status == PkiStatus.SUCCESS:
        if message_data is None or recipient is None:
            msg = 'A successful CertRep requires messageData and a recipient.'
            raise ValueError(msg)
        econtent = encrypt_pkcs_pki_envelope(message_data, recipient)

    attrs = [
        _attribute(OID_ATTR_CONTENT_TYPE, OID_DATA),
        _attribute(OID_ATTR_SIGNING_TIME, useful.UTCTime.fromDateTime(datetime.datetime.now(datetime.UTC))),
        _attribute(OID_ATTR_MESSAGE_DIGEST, univ.OctetString(hashlib.sha256(econtent or b'').digest())),
        _attribute(OID_TRANSACTION_ID, char.PrintableString(transaction_id)),
        _attribute(OID_MESSAGE_TYPE, char.PrintableString(str(int(MessageType.CERT_REP)))),
        _attribute(OID_PKI_STATUS, char.PrintableString(str(int(status)))),
    ]
    if status == PkiStatus.FAILURE:
        attrs.append(_attribute(OID_FAIL_INFO, char.PrintableString(str(int(fail_info
                                                                            if fail_info is not None
                                                                            else FailInfo.BAD_REQUEST)))))
        if fail_text:
            attrs.append(_attribute(OID_FAIL_INFO_TEXT, char.UTF8String(fail_text)))
    attrs.append(_attribute(OID_RECIPIENT_NONCE, univ.OctetString(recipient_nonce)))
    attrs.append(_attribute(OID_SENDER_NONCE, univ.OctetString(os.urandom(NONCE_LENGTH))))

    signed_attrs = rfc5652.SignedAttributes()
    for attr in attrs:
        signed_attrs.append(attr)
    signature = server_key.sign(der_encoder.encode(signed_attrs), padding.PKCS1v15(), hashes.SHA256())

    sd = rfc5652.SignedData()
    sd['version'] = 1
    sd['digestAlgorithms'].append(_alg(OID_SHA256))
    sd['encapContentInfo']['eContentType'] = OID_DATA
    if econtent is not None:
        sd['encapContentInfo']['eContent'] = econtent
    decoded_cert, _ = der_decoder.decode(server_cert.public_bytes(serialization.Encoding.DER),
                                         asn1Spec=rfc5280.Certificate())
    sd['certificates'][0]['certificate'] = decoded_cert

    signer = sd['signerInfos'][0]
    signer['version'] = 1
    _issuer_and_serial(signer['sid']['issuerAndSerialNumber'], server_cert)
    signer['digestAlgorithm']['algorithm'] = OID_SHA256
    for index, attr in enumerate(signed_attrs):
        signer['signedAttrs'][index] = attr
    signer['signatureAlgorithm']['algorithm'] = OID_RSA_ENCRYPTION
    signer['signatureAlgorithm']['parameters'] = _any(univ.Null(''))
    signer['signature'] = signature
    return _wrap_content_info(OID_SIGNED_DATA, sd)
