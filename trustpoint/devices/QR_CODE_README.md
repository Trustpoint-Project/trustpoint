# QR Code Credential Download Module

## Overview

This module provides QR code generation functionality for downloading credential files (PKCS#12, PEM ZIP, PEM TAR.GZ) directly to mobile devices or other systems by scanning a QR code.

## Features

- **QR Code Generation**: Generates QR codes that encode download URLs with embedded authentication tokens
- **Direct File Download**: Scanning the QR code immediately triggers the credential file download
- **Multiple File Formats**: Supports PKCS#12, PEM ZIP, and PEM TAR.GZ formats
- **Token-Based Security**: Uses time-limited tokens for authentication (3-minute validity)
- **Automatic Cleanup**: Download sessions are automatically cleaned up after successful download

## Architecture

### Components

1. **`devices/qr_code.py`**: Core QR code generation utilities
   - `generate_qr_code()`: Generates base64-encoded PNG QR code images
   - `generate_file_download_qr_url()`: Constructs download URLs with tokens

2. **`devices/views/qr_download.py`**: QR code download view
   - `QRCodeCredentialDownloadView`: Handles direct file downloads via QR code
   - `get_qr_code_data_url()`: Helper to generate QR code data URLs

3. **Template Integration**: `otp_view.html`
   - Displays QR code alongside traditional OTP workflow
   - Provides alternative download method

## Installation

The QR code functionality requires the `qrcode` library with PIL support:

```bash
uv add "qrcode[pil]"
```

If the library is not installed, the module gracefully degrades and the QR code option is hidden from users.

## Usage

### For End Users

1. Navigate to the credential download page
2. Choose between two methods:
   - **QR Code Method**: Scan the displayed QR code with your device's camera
   - **Traditional Method**: Copy the URL and OTP, then paste them in your device's browser

### For Developers

#### Generating a QR Code for Download

```python
from devices.qr_code import generate_qr_code, generate_file_download_qr_url

# Generate download URL
download_url = generate_file_download_qr_url(
    base_url='https://trustpoint.example.com',
    credential_id=123,
    token='secure_token_here',
    file_format='PKCS12'  # or 'PEM_ZIP', 'PEM_TAR_GZ'
)

# Generate QR code as base64 data URL
qr_code_data_url = generate_qr_code(download_url)

# Use in template
context['qr_code_data_url'] = qr_code_data_url
```

#### Integrating into Views

```python
from devices.qr_code import QRCODE_AVAILABLE, generate_qr_code
from devices.models import RemoteDeviceCredentialDownloadModel

if QRCODE_AVAILABLE:
    cdm = RemoteDeviceCredentialDownloadModel.objects.get(...)
    qr_url = generate_file_download_qr_url(
        base_url=base_url,
        credential_id=credential.id,
        token=cdm.download_token
    )
    context['qr_code_data_url'] = generate_qr_code(qr_url)
    context['qr_code_available'] = True
```

## Security Considerations

### Token Validity

- Download tokens are valid for **3 minutes** after OTP verification
- Tokens are single-use and deleted after successful download
- Expired tokens are automatically cleaned up

### Authentication Flow

1. User initiates browser onboarding workflow
2. System generates OTP and download token
3. QR code encodes URL with embedded token
4. User scans QR code
5. System validates token and serves file
6. Token is immediately deleted after download

### Rate Limiting

- OTP attempts are limited to 3 tries
- Failed OTP attempts invalidate the session
- Token expiration prevents replay attacks

## URL Structure

### QR Code Download Endpoint

```
/devices/credentials/<credential_id>/qr-download?token=<token>&format=<format>
```

**Parameters:**
- `credential_id`: Primary key of the IssuedCredentialModel
- `token`: Authentication token from RemoteDeviceCredentialDownloadModel
- `format`: File format (PKCS12, PEM_ZIP, PEM_TAR_GZ)
- `password`: (Optional) Password for key encryption

**Example:**
```
https://trustpoint.example.com/devices/credentials/123/qr-download?token=abc123&format=PKCS12
```

## File Formats

The QR code download supports the same formats as manual download:

### PKCS#12 (.p12, .pfx)
- Single file containing private key and certificate chain
- Password-protected
- Widely supported by browsers and mobile devices

### PEM ZIP (.zip)
- Archive containing separate PEM files:
  - `private_key.pem`: Password-protected private key
  - `certificate.pem`: End-entity certificate
  - `certificate_chain.pem`: Full certificate chain

### PEM TAR.GZ (.tar.gz)
- Compressed archive with same contents as PEM ZIP
- Better for Unix/Linux systems

## Error Handling

The module handles several error conditions gracefully:

- **Missing qrcode library**: QR code option is hidden
- **Invalid token**: Returns 404 with appropriate error message
- **Expired token**: Returns 404 and cleans up expired session
- **Invalid format**: Returns 404 with format error message
- **Missing credential**: Returns 404

## Testing

To test the QR code functionality:

1. Install the qrcode library
2. Create a device with browser onboarding
3. Navigate to the credential download OTP view
4. Verify QR code is displayed
5. Scan QR code with mobile device
6. Verify file downloads successfully

## Future Enhancements

Potential improvements for future versions:

- Support for custom QR code styling (colors, logos)
- QR code size configuration
- Multiple format selection in single QR code
- Batch credential download via QR codes
- QR code download analytics
- Support for password protection in QR URL
- Dynamic QR code refresh on token expiration

## Dependencies

- **qrcode**: QR code generation
- **pillow**: Image processing (via qrcode[pil])
- **Django**: Web framework
- **trustpoint-core**: Credential serialization

## Compatibility

- **Python**: 3.13+
- **Django**: 6.0+
- **Browsers**: All modern browsers with camera access
- **Mobile**: iOS 11+, Android 5.0+

## License

Copyright (c) 2026 The Trustpoint Project Authors  
SPDX-License-Identifier: MIT
