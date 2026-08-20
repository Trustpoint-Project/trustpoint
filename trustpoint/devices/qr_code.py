# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""QR code generation utilities for credential download workflows."""

from __future__ import annotations

import base64
import io
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Literal

    FileFormat = Literal['PKCS12', 'PEM_ZIP', 'PEM_TAR_GZ']

try:
    import qrcode  # type: ignore[import-untyped]

    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

# Maximum recommended size for QR code data (in bytes)
# QR codes can theoretically hold up to ~2953 bytes with error correction,
# but practical limit with good readability is around 2KB
MAX_QR_CODE_DATA_SIZE = 2048


def generate_qr_code(data: str, *, box_size: int = 10, border: int = 4) -> str:
    """Generate a QR code as a base64-encoded PNG image.

    Args:
        data: The data to encode in the QR code (typically a URL).
        box_size: Size of each box in pixels. Defaults to 10.
        border: Border size in boxes. Defaults to 4.

    Returns:
        Base64-encoded PNG image string that can be embedded in HTML img src.

    Raises:
        ImportError: If qrcode library is not installed.
    """
    if not QRCODE_AVAILABLE:
        msg = 'qrcode library is required for QR code generation. Install it with: uv add qrcode[pil]'
        raise ImportError(msg)

    # Create QR code instance
    qr = qrcode.QRCode(
        version=1,  # Auto-size
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=box_size,
        border=border,
    )

    # Add data and generate
    qr.add_data(data)
    qr.make(fit=True)

    # Create image
    img = qr.make_image(fill_color='black', back_color='white')

    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    return f'data:image/png;base64,{img_base64}'


def generate_pkcs12_qr_data(pkcs12_bytes: bytes) -> str:
    """Generate a data URI containing base64-encoded PKCS#12 data for QR code embedding.

    This creates a data URI that mobile devices can scan and import directly.
    WARNING: PKCS#12 files can be large. QR codes have a practical limit of ~2KB.

    Args:
        pkcs12_bytes: The PKCS#12 file as bytes.

    Returns:
        Data URI string in format: data:application/x-pkcs12;base64,<base64_data>

    Raises:
        ValueError: If the PKCS#12 data is too large for a QR code (>2KB).
    """
    # Encode PKCS#12 to base64
    pkcs12_base64 = base64.b64encode(pkcs12_bytes).decode('utf-8')

    # Create data URI
    data_uri = f'data:application/x-pkcs12;base64,{pkcs12_base64}'

    # Check size - QR codes can theoretically hold up to ~2953 bytes with error correction
    # but practical limit with good readability is around 2KB
    if len(data_uri) > MAX_QR_CODE_DATA_SIZE:
        msg = (
            f'PKCS#12 data is too large for QR code: {len(data_uri)} bytes. '
            f'Maximum recommended size is {MAX_QR_CODE_DATA_SIZE} bytes. '
            'Consider using a shorter password or reducing certificate chain length.'
        )
        raise ValueError(msg)

    return data_uri


def generate_file_download_qr_url(
    base_url: str,
    credential_id: int,
    token: str,
    *,
    file_format: FileFormat = 'PKCS12',
) -> str:
    """Generate a URL for direct file download that can be encoded in a QR code.

    Args:
        base_url: The base URL of the Trustpoint server.
        credential_id: The ID of the credential to download.
        token: The download token for authentication.
        file_format: The desired file format. Defaults to 'PKCS12'.

    Returns:
        Complete URL that can be encoded in a QR code for file download.
    """
    # Remove trailing slash from base_url if present
    base_url = base_url.rstrip('/')

    # Construct the download URL with token and format
    return f'{base_url}/devices/credentials/{credential_id}/qr-download?token={token}&format={file_format}'
