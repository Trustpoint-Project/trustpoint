# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Form adapters for shared credential-upload validation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from pki.services import credential_upload as uploads

if TYPE_CHECKING:
    from django.core.files.uploadedfile import UploadedFile
    from django_stubs_ext import StrPromise
    from trustpoint_core.serializer import CertificateCollectionSerializer, CertificateSerializer, PrivateKeySerializer

# Preserve the existing import for callers using the original private-key helper.
MAX_PRIVATE_KEY_UPLOAD_BYTES = uploads.MAX_PRIVATE_KEY_UPLOAD_BYTES


def read_private_key_upload(upload: UploadedFile[bytes] | None) -> bytes:
    """Read a bounded private key for forms that parse it after password cleaning."""
    try:
        return uploads.read_credential_upload(upload, kind=uploads.CredentialFileKind.PRIVATE_KEY)
    except uploads.CredentialUploadError as exc:
        messages = {
            uploads.CredentialUploadErrorCode.MISSING: 'No private key file was uploaded.',
            uploads.CredentialUploadErrorCode.TOO_LARGE: 'Private key file is too large, max. 64 kiB.',
        }
        msg = messages.get(exc.code, 'Failed to parse the private key file. Either wrong password or file corrupted.')
        raise ValidationError(msg) from exc


def encode_credential_password(
    password: str | bytes | None,
    *,
    pkcs12: bool = False,
    error_message: str | StrPromise | None = None,
) -> bytes | None:
    """Encode a password and render the existing form-specific validation message."""
    try:
        return uploads.encode_upload_password(password)
    except uploads.CredentialUploadError as exc:
        msg = (
            error_message
            if error_message is not None
            else (
                _('The PKCS#12 password contains invalid data, that cannot be encoded in UTF-8.')
                if pkcs12
                else 'The private key password contains invalid data that cannot be encoded in UTF-8.'
            )
        )
        raise ValidationError(msg) from exc


def parse_private_key_data(data: bytes, password: bytes | None) -> PrivateKeySerializer:
    """Parse private-key bytes already read and bounded by a form."""
    try:
        return uploads.parse_private_key(data, password)
    except uploads.CredentialUploadError as exc:
        msg = _('Failed to parse the private key file. Either wrong password or file corrupted.')
        raise ValidationError(msg) from exc


def parse_private_key_upload(upload: UploadedFile[bytes] | None, password: str | None) -> PrivateKeySerializer:
    """Validate an uploaded private key and decrypt it with the optional password."""
    data = read_private_key_upload(upload)
    return parse_private_key_data(data, encode_credential_password(password))


def parse_certificate_upload(
    upload: UploadedFile[bytes] | None,
    *,
    missing_message: str | StrPromise,
    too_large_message: str | StrPromise,
    parse_message: str | StrPromise,
) -> CertificateSerializer:
    """Parse a bounded certificate while retaining the form's field-specific messages."""
    try:
        data = uploads.read_credential_upload(upload, kind=uploads.CredentialFileKind.CERTIFICATE)
        return uploads.parse_certificate(data)
    except uploads.CredentialUploadError as exc:
        msg = {
            uploads.CredentialUploadErrorCode.MISSING: missing_message,
            uploads.CredentialUploadErrorCode.TOO_LARGE: too_large_message,
        }.get(exc.code, parse_message)
        raise ValidationError(msg) from exc


def parse_certificate_chain_upload(
    upload: UploadedFile[bytes] | None,
    *,
    parse_message: str | StrPromise,
) -> CertificateCollectionSerializer | None:
    """Parse an optional, bounded chain without adding purpose-specific trust checks."""
    if not upload:
        return None
    try:
        data = uploads.read_credential_upload(upload, kind=uploads.CredentialFileKind.CHAIN)
        return uploads.parse_certificate_chain(data)
    except uploads.CredentialUploadError as exc:
        msg = (
            _('Certificate chain file is too large, max. 256 kiB.')
            if (exc.code == uploads.CredentialUploadErrorCode.TOO_LARGE)
            else parse_message
        )
        raise ValidationError(msg) from exc


def read_pkcs12_upload(
    upload: UploadedFile[bytes] | None,
    *,
    missing_message: str | StrPromise = 'PKCS#12 file is required.',
    read_message: str | StrPromise | None = None,
    read_error_code: str | None = 'unexpected-error',
) -> bytes:
    """Read a bounded PKCS#12 file using the calling form's existing read-error contract."""
    try:
        return uploads.read_credential_upload(upload, kind=uploads.CredentialFileKind.PKCS12)
    except uploads.CredentialUploadError as exc:
        if exc.code == uploads.CredentialUploadErrorCode.MISSING:
            raise ValidationError(missing_message) from exc
        if exc.code == uploads.CredentialUploadErrorCode.TOO_LARGE:
            msg: str | StrPromise = 'PKCS#12 file is too large, max. 256 kiB.'
            raise ValidationError(msg) from exc
        msg = (
            read_message
            if read_message is not None
            else _('Unexpected error occurred while trying to get file contents. Please see logs for further details.')
        )
        raise ValidationError(msg, code=read_error_code) from exc
