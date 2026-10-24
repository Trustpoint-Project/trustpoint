# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared validation for uploaded credential files."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from django.core.exceptions import ValidationError
from trustpoint_core.serializer import PrivateKeySerializer

if TYPE_CHECKING:
    from django.core.files.uploadedfile import UploadedFile

MAX_PRIVATE_KEY_UPLOAD_BYTES = 64 * 1024


def parse_private_key_upload(upload: UploadedFile[bytes] | None, password: str | None) -> PrivateKeySerializer:
    """Validate an uploaded private key and decrypt it with the optional password."""
    if not upload:
        msg = 'No private key file was uploaded.'
        raise ValidationError(msg)
    if cast('int', upload.size) > MAX_PRIVATE_KEY_UPLOAD_BYTES:
        msg = 'Private key file is too large, max. 64 kiB.'
        raise ValidationError(msg)

    try:
        encoded_password = password.encode('utf-8') if password else None
    except Exception as exc:
        msg = 'The private key password contains invalid data that cannot be encoded in UTF-8.'
        raise ValidationError(msg) from exc

    try:
        return PrivateKeySerializer.from_bytes(upload.read(), encoded_password)
    except Exception as exc:
        msg = 'Failed to parse the private key file. Either wrong password or file corrupted.'
        raise ValidationError(msg) from exc
