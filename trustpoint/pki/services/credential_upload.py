# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Bounded parsing of credential uploads, independent of forms and API responses."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

from trustpoint_core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    CredentialSerializer,
    PrivateKeySerializer,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.core.files.uploadedfile import UploadedFile

MAX_PRIVATE_KEY_UPLOAD_BYTES = 64 * 1024
MAX_CERTIFICATE_UPLOAD_BYTES = 64 * 1024
MAX_CERTIFICATE_CHAIN_UPLOAD_BYTES = 256 * 1024
MAX_PKCS12_UPLOAD_BYTES = 256 * 1024


class CredentialFileKind(StrEnum):
    """Supported uploaded credential components."""

    PRIVATE_KEY = 'private_key'
    CERTIFICATE = 'certificate'
    CHAIN = 'chain'
    PKCS12 = 'pkcs12'


class CredentialUploadErrorCode(StrEnum):
    """Stable reasons for adapters to render using their existing error contracts."""

    MISSING = 'missing'
    TOO_LARGE = 'too_large'
    READ_FAILED = 'read_failed'
    INVALID_PASSWORD = 'invalid_password'  # noqa: S105 - Error classification, not a credential.
    MALFORMED = 'malformed'


class CredentialUploadError(ValueError):
    """A credential input failed before any persistence or backend import."""

    def __init__(self, code: CredentialUploadErrorCode) -> None:
        """Expose the reason without leaking parser or password details."""
        self.code = code
        super().__init__(code.value)


_LIMITS = {
    CredentialFileKind.PRIVATE_KEY: MAX_PRIVATE_KEY_UPLOAD_BYTES,
    CredentialFileKind.CERTIFICATE: MAX_CERTIFICATE_UPLOAD_BYTES,
    CredentialFileKind.CHAIN: MAX_CERTIFICATE_CHAIN_UPLOAD_BYTES,
    CredentialFileKind.PKCS12: MAX_PKCS12_UPLOAD_BYTES,
}


def _check_size(size: int, kind: CredentialFileKind) -> None:
    if size > _LIMITS[kind]:
        raise CredentialUploadError(CredentialUploadErrorCode.TOO_LARGE)


def read_credential_upload(upload: UploadedFile[bytes] | None, *, kind: CredentialFileKind) -> bytes:
    """Read at most the configured limit plus one byte, checking actual and declared sizes."""
    if upload is None:
        raise CredentialUploadError(CredentialUploadErrorCode.MISSING)
    size = getattr(upload, 'size', None)
    if isinstance(size, int):
        _check_size(size, kind)
    try:
        data = upload.read(_LIMITS[kind] + 1)
    except Exception as exc:
        raise CredentialUploadError(CredentialUploadErrorCode.READ_FAILED) from exc
    if not isinstance(data, bytes):
        raise CredentialUploadError(CredentialUploadErrorCode.READ_FAILED)
    _check_size(len(data), kind)
    return data


def encode_upload_password(password: str | bytes | None) -> bytes | None:
    """Encode text passwords as UTF-8, preserving supplied bytes and treating blanks as absent."""
    if password in (None, '', b''):
        return None
    if isinstance(password, bytes):
        return password
    if not isinstance(password, str):
        raise CredentialUploadError(CredentialUploadErrorCode.INVALID_PASSWORD)
    try:
        return password.encode('utf-8')
    except UnicodeEncodeError as exc:
        raise CredentialUploadError(CredentialUploadErrorCode.INVALID_PASSWORD) from exc


def _parse[Result](data: bytes, kind: CredentialFileKind, parser: Callable[[bytes], Result]) -> Result:
    _check_size(len(data), kind)
    try:
        return parser(data)
    except Exception as exc:
        raise CredentialUploadError(CredentialUploadErrorCode.MALFORMED) from exc


def parse_private_key(data: bytes, password: bytes | None = None) -> PrivateKeySerializer:
    """Decode a PEM/DER private key using the supplied optional password."""
    return _parse(data, CredentialFileKind.PRIVATE_KEY, lambda raw: PrivateKeySerializer.from_bytes(raw, password))


def parse_certificate(data: bytes) -> CertificateSerializer:
    """Decode a certificate using the supported Trustpoint Core certificate formats."""
    return _parse(data, CredentialFileKind.CERTIFICATE, CertificateSerializer.from_bytes)


def parse_certificate_chain(data: bytes) -> CertificateCollectionSerializer:
    """Decode a certificate collection without changing its order or trust semantics."""
    return _parse(data, CredentialFileKind.CHAIN, CertificateCollectionSerializer.from_bytes)


def parse_pkcs12(data: bytes, password: bytes | None = None) -> CredentialSerializer:
    """Extract a PKCS#12 credential; purpose and component checks belong to the caller."""
    return _parse(data, CredentialFileKind.PKCS12, lambda raw: CredentialSerializer.from_pkcs12_bytes(raw, password))
