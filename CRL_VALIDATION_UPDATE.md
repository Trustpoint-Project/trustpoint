# CRL Validation Update

## Summary
Updated the GDS Push service to make CRL (Certificate Revocation List) mandatory and validate CRL expiration.

## Changes Made

### 1. Mandatory CRL Requirement
**Location**: `_build_trustlist_for_server()` method

**Before**: CRLs were optional
```python
if ca.crl_pem:
    crl_crypto = x509.load_pem_x509_crl(ca.crl_pem.encode(), default_backend())
    crl_der = crl_crypto.public_bytes(encoding=serialization.Encoding.DER)
    trusted_crls.append(crl_der)
    issuer_crls.append(crl_der)
    logger.debug('Added CRL from CA "%s"', ca.unique_name)
else:
    logger.debug('No CRL available for CA "%s"', ca.unique_name)
```

**After**: CRLs are mandatory with validation
```python
# CRL is mandatory for OPC UA GDS Push
if not ca.crl_pem:
    msg = (
        f'CA "{ca.unique_name}" has no CRL configured. '
        f'CRL is mandatory for OPC UA GDS Push trustlist.'
    )
    raise GdsPushError(msg)

# Load and validate CRL
try:
    crl_crypto = x509.load_pem_x509_crl(ca.crl_pem.encode(), default_backend())
except Exception as e:
    msg = f'Failed to load CRL for CA "{ca.unique_name}": {e}'
    raise GdsPushError(msg) from e

# Validate CRL is still valid
now = datetime.datetime.now(tz=datetime.UTC)
if crl_crypto.next_update and crl_crypto.next_update < now:
    msg = (
        f'CRL for CA "{ca.unique_name}" has expired. '
        f'Next update was: {crl_crypto.next_update.isoformat()}, '
        f'Current time: {now.isoformat()}'
    )
    raise GdsPushError(msg)

crl_der = crl_crypto.public_bytes(encoding=serialization.Encoding.DER)
trusted_crls.append(crl_der)
issuer_crls.append(crl_der)

logger.debug(
    'Added valid CRL from CA "%s" (next update: %s)',
    ca.unique_name,
    crl_crypto.next_update.isoformat() if crl_crypto.next_update else 'N/A'
)
```

### 2. Validation Logic

The implementation now performs three checks for each CA's CRL:

1. **Existence Check**: Ensures CRL is configured
   - Error: `"CA '{name}' has no CRL configured. CRL is mandatory for OPC UA GDS Push trustlist."`

2. **Loading Check**: Validates CRL can be parsed
   - Error: `"Failed to load CRL for CA '{name}': {error}"`

3. **Expiration Check**: Validates CRL is still valid
   - Compares `crl_crypto.next_update` with current time
   - Error: `"CRL for CA '{name}' has expired. Next update was: {timestamp}, Current time: {timestamp}"`

### 3. Documentation Updates

Updated the docstring for `_build_trustlist_for_server()`:

```python
"""Build OPC UA TrustList to push to server.

The TrustList tells the OPC UA server which CAs to trust for client
certificate validation. It includes:
- All CA certificates in the chain (issuing CA to root)
- Valid CRLs from all CAs in the chain (mandatory)

Returns:
    TrustListDataType ready to push to server.

Raises:
    GdsPushError: If trustlist cannot be built, any CA is missing a CRL,
                 or any CRL is expired.
"""
```

### 4. Improved Logging

Enhanced debug logging to show CRL validity information:
```python
logger.debug(
    'Added valid CRL from CA "%s" (next update: %s)',
    ca.unique_name,
    crl_crypto.next_update.isoformat() if crl_crypto.next_update else 'N/A'
)
```

## Rationale

### Why CRLs are Mandatory

1. **OPC UA Security Requirements**: OPC UA GDS Push protocol requires proper certificate validation
2. **Trust Validation**: CRLs are essential for the OPC UA server to validate that client certificates haven't been revoked
3. **Security Compliance**: Without CRLs, the trustlist would be incomplete and potentially insecure

### Why Validate Expiration

1. **Prevent Stale Data**: Expired CRLs may not contain recent revocations
2. **Security Risk**: Using expired CRLs defeats the purpose of revocation checking
3. **Early Detection**: Catch configuration issues before attempting to push to the server

## Impact

### Before
- CRLs were optional
- No validation of CRL expiration
- Potential security gap if CRLs were missing or outdated

### After
- ✅ CRLs are mandatory for all CAs in the chain
- ✅ CRL expiration is validated before use
- ✅ Clear error messages guide users to fix issues
- ✅ Better security compliance with OPC UA standards

## Error Messages

Users will now see clear, actionable error messages:

1. **Missing CRL**:
   ```
   CA "MyCA" has no CRL configured. CRL is mandatory for OPC UA GDS Push trustlist.
   ```

2. **Invalid CRL**:
   ```
   Failed to load CRL for CA "MyCA": Invalid PEM format
   ```

3. **Expired CRL**:
   ```
   CRL for CA "MyCA" has expired. 
   Next update was: 2025-12-01T10:00:00+00:00, 
   Current time: 2026-01-20T15:30:00+00:00
   ```

## Testing Checklist

- [ ] Test with all CAs having valid CRLs
- [ ] Test error when CA missing CRL
- [ ] Test error when CRL is expired
- [ ] Test error when CRL is malformed
- [ ] Verify error messages are clear and actionable
- [ ] Test CA chain with multiple CAs (all must have valid CRLs)

## Files Modified

- ✅ `trustpoint/request/gds_push/gds_push_service.py`
  - Lines ~290-320: CRL validation logic
  - Line 304: Updated to use `datetime.UTC` instead of `datetime.timezone.utc`
  - Lines 254-266: Updated docstring
