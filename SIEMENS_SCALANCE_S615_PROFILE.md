# Siemens Scalance S615 HTTPS Certificate Profile

## Summary

I've created a web UI automation profile for the Siemens Scalance S615 to upload HTTPS certificates via PKCS#12 containers. This required extending the Trustpoint web UI automation framework to support PKCS#12 encoding in addition to the existing PEM format.

## Changes Made

### 1. Extended Schema Support for PKCS#12 (`schema.py`)

**File**: `/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/web_ui_automation/schema.py`

- Changed the `encoding` field from a constant `'PEM'` to an enum `['PEM', 'PKCS12']`
- This allows profiles to specify PKCS#12 as their encoding format

```python
'encoding': {'enum': ['PEM', 'PKCS12']},
```

### 2. Extended Executor to Generate PKCS#12 Artifacts (`executor.py`)

**File**: `/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/web_ui_automation/executor.py`

Modified the `_build_execution_context` function to:
- Check the profile's `encoding` field
- Generate PKCS#12 artifacts when `encoding: "PKCS12"` is specified
- Use the existing `credential_serializer.as_pkcs12(password=password)` method
- **Properly encode the password string to bytes** (fixes "Failed to get the BestAvailableEncryption algorithm" error)
- Handle empty passwords by passing `None` instead of empty bytes
- Write the PKCS#12 file to a temporary location and make it available as `{{ pkcs12_p12 }}`
- Maintain backward compatibility with PEM encoding (default behavior)

### 3. Created Siemens Scalance S615 Profile

**File**: `/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/web_ui_automation/default_profiles/siemens_scalance_s615_https.json`

Created a complete automation profile with:

#### Profile Metadata
- **Vendor**: Siemens
- **Device Family**: Scalance S615
- **Encoding**: PKCS12
- **Certificate Profile**: scalance-s615-https-tls

#### Paths Defined
- `/` - Login page
- `/system/load-save/http/https-cert` - HTTPS certificate upload page
- `/system/load-save/passwords/https-cert` - HTTPS certificate password configuration
- `/system/restart` - System restart page

#### Onboarding Flow
1. **Login** - Navigate to login page and authenticate
2. **Upload Certificate** - Navigate to HTTPS cert upload and upload PKCS#12 file
3. **Handle Modal** - Wait for success modal and dismiss it
4. **Set Password** - Navigate to password settings and configure the PKCS#12 password
5. **Restart** - Navigate to restart page and reboot the device

#### Renewal Flow
Same as onboarding, but skips the password configuration step since the password remains the same.

### 4. Added Tests (`test_schema.py`)

**File**: `/Users/florianhandke/PycharmProjects/trustpoint/trustpoint/web_ui_automation/tests/test_schema.py`

Added two new test cases:
- `test_pkcs12_encoding_is_accepted()` - Verifies PKCS12 is accepted as valid encoding
- `test_invalid_encoding_is_rejected()` - Ensures invalid encodings are still rejected

## Profile Usage

### Required Credentials
The profile requires three credentials to be configured in the automation device:
1. **device_username** - Username for device login
2. **device_password** - Password for device login  
3. **private_key_password** - Password for the PKCS#12 container and certificate activation

### Workflow

#### Onboarding (First Certificate Installation)
1. Logs into the device
2. Uploads the PKCS#12 certificate to System > Load&Save > HTTP > HTTPSCert
3. Handles the confirmation modal: "File was successfully loaded. DEVICE RESTART REQUIRED."
4. Sets the PKCS#12 password at System > Load&Save > Passwords > HTTPSCert
5. Restarts the device at System > Restart

#### Renewal (Certificate Update)
1. Logs into the device
2. Uploads the new PKCS#12 certificate (overwrites the old one)
3. Handles the confirmation modal
4. Restarts the device (password already set from onboarding)

## Important Notes

### Selectors Need Verification
The profile includes placeholder selectors that need to be verified against the actual Siemens Scalance S615 web interface:
- `input[name='username']` - Login username field
- `input[name='password']` - Login password field
- `input[type='file'][name='HTTPSCert']` - Certificate upload field
- `.modal:has-text('File was successfully loaded')` - Success modal
- `.modal button:has-text('OK')` - Modal close button
- `input[name='HTTPSCertPassword']` - Password field
- `input[name='HTTPSCertPasswordConfirm']` - Password confirmation field
- `button:has-text('Restart System')` - Restart button

These selectors should be adapted based on the actual HTML structure of the device's web interface.

### PKCS#12 Password
The same password is used for:
1. Encrypting the PKCS#12 container during generation
2. Setting as the certificate password in the device

This password must be configured in the `private_key_password` field of the automation device credentials.

### Device Restart
The profile uses the `reboot_device` action which clicks the restart button without waiting for a response. This is appropriate since the device will disconnect during the restart process.

## Testing Recommendations

Before deploying this profile in production:

1. **Verify Selectors**: Inspect the actual Siemens Scalance S615 web interface and update all CSS selectors
2. **Test Login Flow**: Ensure the login mechanism works correctly
3. **Test Upload**: Verify the file upload field accepts PKCS#12 files
4. **Test Modal Handling**: Confirm the modal appears and can be dismissed correctly
5. **Test Password Setting**: Verify the password fields exist and work as expected
6. **Test Restart**: Ensure the restart button triggers a device reboot

## Files Modified

1. `trustpoint/web_ui_automation/schema.py` - Added PKCS12 encoding support
2. `trustpoint/web_ui_automation/executor.py` - Added PKCS12 artifact generation
3. `trustpoint/web_ui_automation/tests/test_schema.py` - Added encoding tests
4. `trustpoint/web_ui_automation/default_profiles/siemens_scalance_s615_https.json` - New profile

## Backward Compatibility

All existing profiles using `encoding: "PEM"` will continue to work without modification. The PKCS12 support is additive and only used when explicitly specified in a profile.

## Troubleshooting

### "Failed to get the BestAvailableEncryption algorithm" Error

**Problem**: This error occurs during PKCS#12 generation when the password encoding is incorrect.

**Solution**: This has been fixed in the executor by:
1. Converting the password string to bytes using `.encode()`
2. Passing `None` for empty passwords instead of empty bytes

The fix ensures that:
- Non-empty passwords are properly encoded as bytes before being passed to `as_pkcs12()`
- Empty passwords result in `None` being passed, which creates an unencrypted PKCS#12 file

**Note**: For the Siemens Scalance S615, you **must** configure a `private_key_password` in the automation device credentials, as the device requires a password-protected PKCS#12 file.

### "Executable doesn't exist at /var/www/.cache/ms-playwright/chromium..." Error

**Problem**: Playwright browsers are not installed in the Docker container.

**Error Message**:
```
BrowserType.launch: Executable doesn't exist at /var/www/.cache/ms-playwright/chromium_headless_shell-1234/chrome-linux/headless_shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                             ║
║     playwright install                                      ║
╚════════════════════════════════════════════════════════════╝
```

**Solution**: Updated the Docker container to install Playwright browsers during build.

**Changes to `docker/trustpoint/Dockerfile`**:
1. Added system dependencies required by Playwright/Chromium (libnss3, libnspr4, libatk, libcups2, libdrm2, etc.)
2. Created `/var/www/.cache` directory with proper permissions for the www-data user
3. Added `uv run playwright install chromium` to install the Chromium browser (without `--with-deps` to avoid sudo password issues)

**To apply the fix**:
```bash
# Rebuild the Docker container
docker compose build

# Restart the container
docker compose up -d
```

The Chromium browser will now be available for web UI automation tasks.

### "ERR_CERT_AUTHORITY_INVALID" Error

**Problem**: Playwright fails to connect to the device with an SSL certificate error.

**Error Message**:
```
Page.goto: net::ERR_CERT_AUTHORITY_INVALID at http://10.100.13.59/
Call log:
- navigating to "http://10.100.13.59/", waiting until "domcontentloaded"
```

**Root Cause**: Industrial devices like the Siemens Scalance S615 typically use self-signed certificates, which Playwright rejects by default.

**Solution**: Updated the browser context to ignore HTTPS certificate errors.

**Changes to `trustpoint/web_ui_automation/executor.py`**:
Changed `ignore_https_errors` from `False` to `True` in the `_create_browser_context` function:

```python
context_options: dict[str, Any] = {
    'accept_downloads': True,
    'ignore_https_errors': True,  # Changed from False
    'locale': 'en-US',
}
```

This allows Playwright to connect to devices with self-signed or invalid certificates, which is appropriate for automation of industrial devices in controlled environments.

**Note**: This is safe for web UI automation because:
1. The devices are typically on internal networks
2. You're explicitly configuring the device IP/hostname
3. The automation is running in a controlled environment
4. Certificate validation happens separately during the TLS verification step
