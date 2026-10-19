# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Object identifiers, message codes and limits used by the SCEP (RFC 8894) implementation."""

from __future__ import annotations

from enum import IntEnum

from pyasn1.type import univ  # type: ignore[import-untyped]

# RFC 8894 section 3.2.1: id-VeriSign 2.16.840.1.113733, id-pki .1, id-attributes .9
_ATTRIBUTES_ARC = '2.16.840.1.113733.1.9'

OID_TRANSACTION_ID = univ.ObjectIdentifier(f'{_ATTRIBUTES_ARC}.7')
OID_MESSAGE_TYPE = univ.ObjectIdentifier(f'{_ATTRIBUTES_ARC}.2')
OID_PKI_STATUS = univ.ObjectIdentifier(f'{_ATTRIBUTES_ARC}.3')
OID_FAIL_INFO = univ.ObjectIdentifier(f'{_ATTRIBUTES_ARC}.4')
OID_SENDER_NONCE = univ.ObjectIdentifier(f'{_ATTRIBUTES_ARC}.5')
OID_RECIPIENT_NONCE = univ.ObjectIdentifier(f'{_ATTRIBUTES_ARC}.6')
# id-scep-failInfoText ::= { id-pkix 24 1 }
OID_FAIL_INFO_TEXT = univ.ObjectIdentifier('1.3.6.1.5.5.7.24.1')

# CMS (RFC 5652) and PKCS #9
OID_DATA = univ.ObjectIdentifier('1.2.840.113549.1.7.1')
OID_SIGNED_DATA = univ.ObjectIdentifier('1.2.840.113549.1.7.2')
OID_ENVELOPED_DATA = univ.ObjectIdentifier('1.2.840.113549.1.7.3')
OID_ATTR_CONTENT_TYPE = univ.ObjectIdentifier('1.2.840.113549.1.9.3')
OID_ATTR_MESSAGE_DIGEST = univ.ObjectIdentifier('1.2.840.113549.1.9.4')
OID_ATTR_SIGNING_TIME = univ.ObjectIdentifier('1.2.840.113549.1.9.5')

# Algorithms
OID_SHA256 = univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1')
OID_RSA_ENCRYPTION = univ.ObjectIdentifier('1.2.840.113549.1.1.1')
OID_SHA256_WITH_RSA = univ.ObjectIdentifier('1.2.840.113549.1.1.11')
OID_ECDSA_WITH_SHA256 = univ.ObjectIdentifier('1.2.840.10045.4.3.2')
OID_AES128_CBC = univ.ObjectIdentifier('2.16.840.1.101.3.4.1.2')

# RFC 3211 / RFC 5652 section 6.2.4 password-based key management
OID_PWRI_KEK = univ.ObjectIdentifier('1.2.840.113549.1.9.16.3.9')
OID_PBKDF2 = univ.ObjectIdentifier('1.2.840.113549.1.5.12')
OID_HMAC_SHA256 = univ.ObjectIdentifier('1.2.840.113549.2.9')

# Request limits that bound parsing work (RFC 8894 does not define them).
MAX_REQUEST_BYTES = 128 * 1024
MAX_CERTIFICATES = 8
MAX_SIGNED_ATTRIBUTES = 16
MAX_RECIPIENT_INFOS = 8
MAX_TRANSACTION_ID_LENGTH = 128
NONCE_LENGTH = 16
AES_BLOCK_BYTES = 16
AES128_KEY_BYTES = 16

# GetCACaps keywords for exactly the functionality implemented (RFC 8894 section 3.5.2).
CA_CAPABILITIES = ('AES', 'POSTPKIOperation', 'Renewal', 'SCEPStandard', 'SHA-256')

CONTENT_TYPE_CA_CERT = 'application/x-x509-ca-cert'
CONTENT_TYPE_CA_RA_CERT = 'application/x-x509-ca-ra-cert'
CONTENT_TYPE_PKI_MESSAGE = 'application/x-pki-message'


class MessageType(IntEnum):
    """SCEP messageType values (RFC 8894 section 3.2.1.2)."""

    CERT_REP = 3
    RENEWAL_REQ = 17
    PKCS_REQ = 19
    CERT_POLL = 20
    GET_CERT = 21
    GET_CRL = 22


class PkiStatus(IntEnum):
    """SCEP pkiStatus values (RFC 8894 section 3.2.1.3)."""

    SUCCESS = 0
    FAILURE = 2
    PENDING = 3


class FailInfo(IntEnum):
    """SCEP failInfo values (RFC 8894 section 3.2.1.4)."""

    BAD_ALG = 0
    BAD_MESSAGE_CHECK = 1
    BAD_REQUEST = 2
    BAD_TIME = 3
    BAD_CERT_ID = 4
