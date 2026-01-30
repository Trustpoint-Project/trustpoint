# AsyncUA Migration - Complete ✅

## Migration Summary

Successfully migrated the OPC UA GDS Push service from the deprecated `opcua` library to the modern `asyncua` library.

## Changes Made

### 1. Dependency Update
- **File**: `pyproject.toml`
- **Change**: Updated `opcua==0.98.13` → `asyncua>=1.1.5`
- **Status**: ✅ Installed successfully via `uv sync`

### 2. Import Updates
- **File**: `trustpoint/request/gds_push/gds_push_service.py`
- **Changes**:
  ```python
  # Before
  from opcua import Client, ua
  from opcua.ua.uaerrors import BadCertificateInvalid
  
  # After
  from asyncua import Client, ua
  from asyncua.ua.uaerrors import BadCertificateInvalid
  ```

### 3. Service Methods Converted to Async

All methods in `gds_push_service.py` that perform OPC UA operations have been converted to async:

#### Main Public Methods:
1. **`discover_server()`** (line 898)
   - Signature: `async def discover_server() -> tuple[bool, str, dict | None]`
   - Changes: Added `await` to `client.connect()`, `client.disconnect()`, and `_gather_server_info()`

2. **`update_trustlist()`** (line 961)
   - Signature: `async def update_trustlist() -> tuple[bool, str]`
   - Changes: Added `await` to client operations and helper method calls

3. **`update_server_certificate()`** (line 1146)
   - Signature: `async def update_server_certificate() -> tuple[bool, str, bytes | None]`
   - Changes: Added `await` to client operations and helper method calls

#### Private Helper Methods:
4. **`_create_secure_client()`** (line 605)
   - Signature: `async def _create_secure_client() -> Client`
   - Changes: Changed to async (security setup remains sync in asyncua)

5. **`_gather_server_info()`** (line 924)
   - Signature: `async def _gather_server_info(client: Client) -> dict`
   - Changes: 
     - `await client.get_endpoints()`
     - `await server_node.read_browse_name()` (API change from `get_browse_name()`)

6. **`_discover_trustlist_nodes()`** (line 1044)
   - Signature: `async def _discover_trustlist_nodes(client: Client) -> list[Node]`
   - Changes:
     - `await server_node.get_child('ServerConfiguration')`
     - `await server_config.get_child('CertificateGroups')`
     - `await cert_groups_node.get_children()`
     - `await group_node.read_browse_name()` (API change)
     - `await group_node.get_child('TrustList')`

7. **`_update_single_trustlist()`** (line 1084)
   - Signature: `async def _update_single_trustlist(trustlist_node: Node, ...) -> None`
   - Changes: Added `await` to 9 node operations:
     - `await trustlist_node.get_child('Open')`
     - `await trustlist_node.call_method(open_method, mode)`
     - `await trustlist_node.get_child('Write')`
     - `await trustlist_node.call_method(write_method, ...)`
     - `await trustlist_node.get_child('CloseAndUpdate')`
     - `await trustlist_node.call_method(close_and_update_method, ...)`
     - `await trustlist_node.get_parent()` (chained twice)
     - `await server_node.get_child('ApplyChanges')`
     - `await server_node.call_method(apply_changes)`

8. **`_discover_certificate_groups()`** (line 1246)
   - Signature: `async def _discover_certificate_groups(client: Client) -> list[dict[str, Any]]`
   - Changes:
     - `await server_node.get_child('ServerConfiguration')`
     - `await server_config.get_child('CertificateGroups')`
     - `await cert_groups_node.get_children()`
     - `await group_node.read_browse_name()` (API change)

9. **`_update_single_certificate()`** (line 1283)
   - Signature: `async def _update_single_certificate(client: Client, ...) -> tuple[bool, bytes | None, list[bytes] | None]`
   - Changes: Added `await` to 7 node operations:
     - `await server_node.get_child('ServerConfiguration')`
     - `await server_config.get_child('CreateSigningRequest')`
     - `await server_config.call_method(create_signing_request, ...)`
     - `await server_config.get_child('UpdateCertificate')`
     - `await server_config.call_method(update_certificate, ...)`
     - `await server_config.get_child('ApplyChanges')`
     - `await server_config.call_method(apply_changes)`

### 4. Django Views Integration
- **File**: `trustpoint/devices/views.py`
- **Changes**: Added `asyncio.run()` wrappers for all async service method calls

#### Import Addition (line 6):
```python
import asyncio
```

#### View Updates:
1. **`DeviceOpcUaDiscoverServerView.post()`** (line 1449)
   ```python
   # Before
   success, message, server_info = service.discover_server()
   
   # After
   success, message, server_info = asyncio.run(service.discover_server())
   ```

2. **`DeviceOpcUaUpdateTrustlistView.post()`** (line 1888)
   ```python
   # Before
   success, message = service.update_trustlist()
   
   # After
   success, message = asyncio.run(service.update_trustlist())
   ```

3. **`DeviceOpcUaServerDiscoveryView.post()`** (line 1947)
   ```python
   # Before
   success, message, server_info = service.discover_server()
   
   # After
   success, message, server_info = asyncio.run(service.discover_server())
   ```

4. **`DeviceOpcUaUpdateServerCertificateView.post()`** (line 2107)
   ```python
   # Before
   success, message, certificate_bytes = service.update_server_certificate()
   
   # After
   success, message, certificate_bytes = asyncio.run(service.update_server_certificate())
   ```

## Key API Differences: opcua → asyncua

### 1. Async/Await Pattern
- All I/O operations require `async`/`await`
- Client methods: `connect()`, `disconnect()`, `get_endpoints()`
- Node methods: `get_child()`, `get_children()`, `call_method()`, `get_parent()`

### 2. Method Name Changes
- `node.get_browse_name()` → `await node.read_browse_name()`
- All other node methods just need `await` added

### 3. Security Setup
- `client.set_security()` remains synchronous (no await needed)

### 4. Django Integration
- Use `asyncio.run(async_method())` to call from synchronous Django views
- Ensures proper event loop management

## Testing Checklist

Before deploying to production, verify:

- [ ] **Discovery Operation**: Test `discover_server()` on insecure endpoints
- [ ] **Trustlist Update**: Test `update_trustlist()` with server truststores
- [ ] **Certificate Update**: Test `update_server_certificate()` with CSR workflow
- [ ] **Error Handling**: Verify exceptions are properly caught and logged
- [ ] **Performance**: Check that async operations don't block Django requests
- [ ] **Certificate Chain Validation**: Apply certificate validation fix to asyncua if needed

## Next Steps

### 1. Certificate Chain Validation Fix
The certificate validation fix that was applied to the old `opcua` library may need to be reapplied to `asyncua`:

**Location**: `.venv/lib/python3.12/site-packages/asyncua/client/client.py`

**Issue**: asyncua may load full certificate chain from truststore, causing validation failures when server only presents end-entity certificate.

**Solution**: Extract only the first certificate (end-entity) from the chain when loading from truststore, similar to what was done in the opcua library.

**Previous Fix Reference**: See `OPCUA_CERTIFICATE_CHAIN_VALIDATION_FIX.md` for details.

### 2. Integration Testing
Run end-to-end tests with real OPC UA servers to ensure:
- Secure channel establishment works correctly
- Certificate validation handles chains properly
- GDS Push workflows (trustlist + certificate updates) complete successfully

### 3. Documentation Updates
- Update deployment documentation to reference asyncua instead of opcua
- Document any asyncua-specific configuration or quirks
- Update troubleshooting guides for async error handling

## Benefits of AsyncUA

1. **Active Maintenance**: asyncua is actively maintained, opcua is deprecated
2. **Modern Python**: Uses async/await pattern (Python 3.7+)
3. **Better Performance**: Non-blocking I/O for concurrent operations
4. **Future-Proof**: Ongoing development and bug fixes

## References

- **AsyncUA GitHub**: https://github.com/FreeOpcUa/opcua-asyncio
- **AsyncUA Documentation**: https://opcua-asyncio.readthedocs.io/
- **Migration Guide**: `ASYNCUA_MIGRATION.md`
- **Remaining Changes**: `ASYNCUA_REMAINING_CHANGES.md` (now complete)

---

**Migration Completed**: 2024
**Total Methods Converted**: 9 methods + 4 Django view integrations
**Status**: ✅ Ready for testing
