# AsyncUA Django ORM Fix

## Problem

When migrating to `asyncua`, we encountered this error:

```
django.core.exceptions.SynchronousOnlyOperation: You cannot call this from an async context - use a thread or sync_to_async.
```

This occurs because:
1. We wrap async service methods with `asyncio.run()` in Django views
2. Inside async methods, we access Django ORM objects (e.g., `self.device.domain`)
3. Django detects we're in an async context and blocks synchronous database queries

## Solution

We wrapped database-accessing methods with `sync_to_async` to safely perform Django ORM queries from async context.

### Changes Made

#### 1. Added `asgiref.sync.sync_to_async` Import

```python
from asgiref.sync import sync_to_async
```

#### 2. Converted `_build_ca_chain()` to Async

This method accesses `self.device.domain` and related ORM objects:

```python
async def _build_ca_chain(self) -> list[CaModel]:
    # Wrap database access in sync_to_async
    @sync_to_async
    def get_device_domain():
        return self.device.domain
    
    @sync_to_async
    def get_domain_issuing_ca(domain):
        return domain.issuing_ca
    
    @sync_to_async
    def get_ca_chain(issuing_ca):
        return issuing_ca.get_ca_chain_from_truststore()
    
    device_domain = await get_device_domain()
    if not device_domain:
        msg = f'Device "{self.device.common_name}" has no domain configured'
        raise GdsPushError(msg)

    issuing_ca = await get_domain_issuing_ca(device_domain)
    if not issuing_ca:
        msg = f'Domain "{device_domain.unique_name}" has no issuing CA configured'
        raise GdsPushError(msg)

    return await get_ca_chain(issuing_ca)
```

#### 3. Updated `_build_trustlist_for_server()` Loop

Wrapped CA certificate and CRL access in `sync_to_async`:

```python
for ca in ca_chain:
    # Wrap database access in sync_to_async
    @sync_to_async
    def get_ca_cert_and_crl():
        ca_cert_crypto = ca.ca_certificate_model.get_certificate_serializer().as_crypto()
        crl_pem = ca.crl_pem
        return ca_cert_crypto, crl_pem, ca.unique_name
    
    ca_cert_crypto, crl_pem, ca_unique_name = await get_ca_cert_and_crl()
    # ... rest of processing
```

#### 4. Converted `_get_client_credentials()` to Async

This method accesses `self.domain_credential.is_valid_domain_credential()` which internally accesses the `credential` Django relationship:

```python
async def _get_client_credentials(self) -> tuple[x509.Certificate, bytes]:
    if self.domain_credential is None:
        msg = 'No domain credential available'
        raise GdsPushError(msg)

    # Wrap Django ORM access in sync_to_async
    @sync_to_async
    def validate_and_get_credential():
        is_valid, reason = self.domain_credential.is_valid_domain_credential()
        if not is_valid:
            msg = f'Invalid domain credential: {reason}'
            raise GdsPushError(msg)
        
        cert_model = self.domain_credential.credential.certificate
        if not cert_model:
            msg = 'Domain credential has no certificate'
            raise GdsPushError(msg)
        
        return cert_model
    
    cert_model = await validate_and_get_credential()

    # Wrap certificate serialization in sync_to_async
    @sync_to_async
    def get_cert_crypto():
        return cert_model.get_certificate_serializer().as_crypto()
    
    cert_crypto = await get_cert_crypto()

    # Validate certificate for OPC UA usage
    self._validate_client_certificate(cert_crypto)

    # Wrap private key retrieval in sync_to_async
    @sync_to_async
    def get_private_key():
        return self.domain_credential.credential.get_private_key()
    
    try:
        key_crypto = await get_private_key()
    except RuntimeError as e:
        msg = f'Failed to get private key: {e}'
        raise GdsPushError(msg) from e

    # ... rest of method
```

Updated call site in `_create_secure_client()`:
```python
client_cert_crypto, client_key_pem = await self._get_client_credentials()
```

## Why This Works

- `sync_to_async` runs synchronous code in a thread pool
- Django ORM operations happen in synchronous thread context
- Async methods can await the result without blocking the event loop
- Django's async safety checks are satisfied

## Alternative Solutions Considered

### 1. select_related() / prefetch_related()
**Rejected**: Would require changing all query sets throughout the codebase. Too invasive.

### 2. Run entire operation in thread pool
**Rejected**: Defeats the purpose of async OPC UA library. We want async I/O for OPC UA operations.

### 3. Convert entire Django app to async views
**Rejected**: Django async views are still maturing. Would require rewriting many views.

## Testing

After this fix, the error should be resolved and operations should complete successfully:

```bash
# Test trustlist update
curl -X POST http://localhost:8000/devices/opc-ua-gds-push/40/update-trustlist/

# Check logs for success
tail -f logs/trustpoint.log
```

## Future Improvements

If more ORM accesses need wrapping, consider:
1. Creating a dedicated `_fetch_all_data()` async method that pre-fetches everything
2. Storing fetched data as instance attributes to avoid repeated DB queries
3. Using Django 4.1+ async ORM support (when it matures)

## References

- Django Async Documentation: https://docs.djangoproject.com/en/stable/topics/async/
- `asgiref.sync` API: https://github.com/django/asgiref
- AsyncUA Library: https://opcua-asyncio.readthedocs.io/
