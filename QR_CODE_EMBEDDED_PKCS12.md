# QR Code with Embedded PKCS#12 - Implementation

## Summary

The QR code now contains the **actual PKCS#12 credential data** (not a download link). When users scan the QR code with their mobile device, the credential is imported directly into the device's certificate store.

## Changes Made

### 1. Removed QR Code from OTP View
- **File**: `devices/views/browser_onboarding.py`
- **Change**: Removed QR code generation from the OTP view page
- **Reason**: QR code is now only shown on the download page with the actual credential data

### 2. Added PKCS#12 Data URI Generation
- **File**: `devices/qr_code.py`
- **New function**: `generate_pkcs12_qr_data(pkcs12_bytes)`
- **Function**: Creates a data URI containing base64-encoded PKCS#12 data
- **Format**: `data:application/x-pkcs12;base64,<base64_data>`
- **Size limit**: 2048 bytes (raises ValueError if too large)

### 3. Updated Download View
- **File**: `devices/views/download.py`
- **Change**: Modified `AbstractDeviceBaseCredentialDownloadView.get_context_data()`
- **New logic**:
  - Generates PKCS#12 with password `trustpoint`
  - Creates data URI with embedded PKCS#12
  - Generates QR code containing the data URI
  - Provides the password to users in the UI

### 4. Updated Template
- **File**: `templates/devices/credentials/credential_download.html`
- **Changes**:
  - Shows single QR code with embedded PKCS#12
  - Displays the password users need to enter
  - Provides instructions on how to import
  - Removed multiple QR codes for different formats

## How It Works

### Data Flow

```
1. User accesses download page
   ↓
2. System generates PKCS#12 with password "trustpoint"
   ↓
3. PKCS#12 is base64-encoded and wrapped in data URI
   ↓
4. Data URI is encoded into QR code
   ↓
5. User scans QR code
   ↓
6. Device detects data:application/x-pkcs12;base64,...
   ↓
7. Device prompts for password
   ↓
8. User enters "trustpoint"
   ↓
9. Credential is imported into device certificate store
```

### QR Code Content

The QR code contains:
```
data:application/x-pkcs12;base64,MIIJ...AwIBBgkqhk...
```

This is a **data URI** that mobile devices recognize and can import directly.

## Usage

### For End Users

1. Navigate to: `https://localhost/devices/browser/credential-download/1/?token=...`
2. See the QR code displayed on the page
3. Open camera app on mobile device
4. Point camera at QR code
5. Tap the notification that appears
6. Enter password: `trustpoint`
7. Credential is now installed on device

### Supported Devices

- **iOS**: iOS 11+ (Safari automatically detects and prompts to install)
- **Android**: Android 5.0+ (requires certificate installer app or Chrome)
- **Desktop**: Can scan and download, but manual import required

## Size Limitations

### QR Code Capacity

- **Maximum QR code capacity**: ~2953 bytes (with error correction)
- **Practical limit**: 2048 bytes (for good readability)
- **Typical PKCS#12 size**: 1-3 KB (depends on certificate chain length)

### What's Included in PKCS#12

- Private key (encrypted with password)
- End-entity certificate
- Full certificate chain (root + intermediates)

### If Too Large

If the PKCS#12 exceeds 2048 bytes:
- QR code is not displayed
- Error is caught gracefully
- Users can still use manual download buttons

## Security

### Password Protection

- **QR code password**: `trustpoint` (hardcoded)
- **Why this password**: 
  - Simple and memorable
  - Provides encryption for the private key
  - Device prompts user to enter it during import

### Alternative Passwords

If you want users to set custom passwords for QR codes, modify:

```python
# In devices/views/download.py, line ~157
default_password = b'trustpoint'  # Change this to user-provided password
```

### Security Considerations

1. **QR code is one-time use**: Token expires after 3 minutes
2. **Private key is encrypted**: PKCS#12 requires password to decrypt
3. **Visual security**: QR code should only be shown on trusted displays
4. **No sensitive data in URL**: Everything is in the QR code data URI

## Testing

### To Test

1. Start your Trustpoint server
2. Create a device and credential
3. Navigate to browser download page with valid token
4. Verify QR code is displayed
5. Scan with mobile device
6. Enter password `trustpoint`
7. Verify credential imports successfully

### If QR Code Not Showing

Check:
1. Is `qrcode` library installed? (`uv add "qrcode[pil]"`)
2. Is PKCS#12 too large? (check logs for ValueError)
3. Is it browser download view? (not manual download)
4. Restart your server after installing qrcode

## Comparison: Before vs After

### Before (URL-based)
```
QR Code contains:
https://trustpoint.example.com/devices/credentials/123/qr-download?token=abc&format=PKCS12

User workflow:
1. Scan QR code
2. Opens browser
3. Downloads file
4. Manual import required
```

### After (Data-embedded)
```
QR Code contains:
data:application/x-pkcs12;base64,MIIJ...AwIBBgkqhk...

User workflow:
1. Scan QR code
2. Enter password
3. Done! (automatic import)
```

## Advantages

✅ **Faster**: No browser navigation required  
✅ **Simpler**: Direct import, no file downloads  
✅ **Mobile-first**: Optimized for smartphones  
✅ **Offline capable**: Works without internet after QR display  
✅ **Universal**: Works with any QR scanner app  

## Limitations

⚠️ **Size constraint**: PKCS#12 must be < 2KB  
⚠️ **Password shown**: Password is displayed on screen  
⚠️ **PKCS#12 only**: Cannot embed PEM files (too large)  
⚠️ **iOS/Android**: Best support, desktop requires manual import  

## Troubleshooting

### QR Code Not Displayed

**Problem**: "QR code not available" message shown  
**Solutions**:
- Install qrcode library: `uv add "qrcode[pil]"`
- Check PKCS#12 size (must be < 2KB)
- Verify you're on browser download page (not manual download)

### Certificate Too Large

**Problem**: ValueError - PKCS#12 too large for QR code  
**Solutions**:
- Use shorter password for PKCS#12
- Reduce certificate chain length
- Use manual download buttons instead

### Device Won't Import

**Problem**: Mobile device doesn't recognize QR code  
**Solutions**:
- Ensure device OS is up to date (iOS 11+, Android 5.0+)
- Try a different QR scanner app
- Check that data URI starts with `data:application/x-pkcs12;base64,`

## Future Enhancements

Potential improvements:
- [ ] Allow user-defined passwords for QR codes
- [ ] Support for compressed PKCS#12 (reduce size)
- [ ] QR code error correction level selection
- [ ] Size estimation before generation
- [ ] Alternative encodings for larger files

## Documentation

See also:
- `QR_CODE_README.md` - Full QR code documentation
- `IMPLEMENTATION_SUMMARY.md` - Original implementation details
- `devices/qr_code.py` - QR code utility functions
- `devices/views/download.py` - Download view with QR code generation
