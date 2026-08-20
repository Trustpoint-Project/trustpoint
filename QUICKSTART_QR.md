# Quick Start: Viewing QR Codes in Trustpoint

## What I've Added

I've implemented QR code support in **TWO places**:

### 1. OTP View Page (Recommended Workflow)
**URL Pattern:** `/devices/credential-download/browser/<credential_id>/`

This is the page that shows the **OTP and download URL**. It now also displays:
- ✅ A single QR code for PKCS#12 download
- ✅ Instructions for scanning
- ✅ Alternative workflow option

**How to access:**
1. Go to device details page
2. Click on a credential
3. Click "Download on Device browser" button
4. **You should see the QR code here!**

### 2. Browser Download Page (New!)
**URL Pattern:** `/devices/browser/credential-download/<credential_id>/?token=...`

This is the page you're currently viewing at:
`https://localhost/devices/browser/credential-download/1/?token=rm8khQP-vXiBA2rgnxehAFL5i0va1g-rUxsqLSHPh0M`

It now displays:
- ✅ Three QR codes (one for each format: PKCS#12, PEM ZIP, PEM TAR.GZ)
- ✅ Each QR code downloads the file directly with **no password** (empty password)
- ✅ Option to use custom password via the form buttons

## Steps to See QR Codes

### Option A: Restart Your Docker Container

Since you're running in Docker, you need to rebuild/restart:

```bash
# In your terminal at /Users/florianhandke/PycharmProjects/trustpoint
docker compose -f docker-compose.softhsm.yml restart trustpoint
```

OR if you want a full rebuild:

```bash
./docker_build.sh
```

### Option B: Check if qrcode is in Docker

The qrcode library needs to be installed in the Docker container. Check your `pyproject.toml` to ensure it's in the dependencies, then rebuild.

## Current Status

✅ **qrcode library installed locally** (just did this)  
❓ **qrcode library in Docker container** (may need to rebuild)

## What the QR Codes Do

When you scan a QR code:

1. **From OTP View Page:** Downloads PKCS#12 file with authentication token
2. **From Browser Download Page:** Downloads the selected format (PKCS#12, PEM ZIP, or TAR.GZ) immediately with **empty password**

## Troubleshooting

### If you don't see QR codes after restarting:

1. **Check browser console** for JavaScript errors
2. **Check Django logs** for Python errors
3. **Verify qrcode is installed** in the container:
   ```bash
   docker compose exec trustpoint python -c "import qrcode; print('QR code available!')"
   ```

### If QR codes appear but don't work:

1. **Check the URL** - It should be accessible from your mobile device
2. **Use HTTPS** - Some browsers block camera access on HTTP
3. **Try from a different device** - Test with your phone's camera

## Quick Test

1. **Restart your Docker container:**
   ```bash
   docker compose -f docker-compose.softhsm.yml restart trustpoint
   ```

2. **Navigate to:**
   ```
   https://localhost/devices/certificate-lifecycle-management/<device_id>/credential-download/
   ```

3. **Click:** "Download on Device browser"

4. **You should see:** 
   - Download URL (copyable)
   - OTP (copyable)
   - **QR Code** (new!)

5. **Or navigate directly to the browser download page** (where you are now) and refresh - you should see 3 QR codes

## Files Changed

- ✅ `devices/qr_code.py` - QR generation utilities
- ✅ `devices/views/download.py` - Added QR codes to browser download view
- ✅ `devices/views/browser_onboarding.py` - Added QR code to OTP view
- ✅ `templates/devices/credentials/credential_download.html` - Display QR codes
- ✅ `templates/devices/credentials/onboarding/browser/otp_view.html` - Display QR code
- ✅ `devices/urls.py` - Added QR download endpoint
- ✅ `pyproject.toml` - Added qrcode[pil] dependency (via `uv add`)

## Next Steps

1. Restart Docker container
2. Refresh the page at `https://localhost/devices/browser/credential-download/1/?token=...`
3. You should see **3 QR codes** at the top of the page!
4. Scan one with your phone to test the download

Let me know if you see the QR codes after restarting! 📱
