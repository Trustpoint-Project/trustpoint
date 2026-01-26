# Remaining asyncua Migration Changes

## Status: ✅ IN PROGRESS

### Completed Changes

1. ✅ Updated `pyproject.toml` - changed from `opcua==0.98.13` to `asyncua>=1.1.5`
2. ✅ Updated imports in `gds_push_service.py` - changed from `opcua` to `asyncua`
3. ✅ Installed asyncua package with `uv sync`
4. ✅ Converted `discover_server()` to async
5. ✅ Converted `_gather_server_info()` to async  
6. ✅ Converted `update_trustlist()` to async

### Remaining Changes in gds_push_service.py

#### Methods that need to be converted to async:

1. **`_create_secure_client()`** (line ~605)
   - Change: `def _create_secure_client(self) -> Client:`
   - To: `async def _create_secure_client(self) -> Client:`
   - Add `await` before: `client.set_security(...)`
   
2. **`_discover_trustlist_nodes()`** (line ~1043)
   - Change signature to async
   - Add `await` to: `cert_groups_node.get_children()`
   - Add `await` to: `group_node.get_child('TrustList')`

3. **`_update_single_trustlist()`** (line ~1081)
   - Change signature to async
   - Add `await` to all: `trustlist_node.call_method(...)`
   - Add `await` to: `trustlist_node.get_child(...)`

4. **`update_server_certificate()`** (line ~1135)
   - Change signature to async
   - Add `await` before: `self._create_secure_client()`
   - Add `await` before: `client.connect()`
   - Add `await` before: `self._discover_certificate_groups(client)`
   - Add `await` before: `self._update_single_certificate(...)`
   - Add `await` before: `client.disconnect()`

5. **`_discover_certificate_groups()`** (line ~1211)
   - Change signature to async
   - Add `await` to: `cert_groups_node.get_children()`
   - Add `await` to: `group_node.get_browse_name()`

6. **`_update_single_certificate()`** (line ~1247)
   - Change signature to async
   - Add `await` to all: `server_config.call_method(...)`
   - Add `await` to: `server_config.get_child(...)`

### Changes in devices/views.py

Need to wrap async calls with `asyncio.run()`:

**Line ~1448**: Discovery view
```python
# OLD:
success, message, server_info = service.discover_server()

# NEW:
import asyncio
success, message, server_info = asyncio.run(service.discover_server())
```

**Line ~1886**: Update trustlist view
```python
# OLD:
success, message = service.update_trustlist()

# NEW:
import asyncio
success, message = asyncio.run(service.update_trustlist())
```

**Line ~1945**: Another discovery view
```python
# OLD:
success, message, server_info = service.discover_server()

# NEW:
import asyncio  
success, message, server_info = asyncio.run(service.discover_server())
```

**Line ~2105**: Update server certificate view
```python
# OLD:
success, message, certificate_bytes = service.update_server_certificate()

# NEW:
import asyncio
success, message, certificate_bytes = asyncio.run(service.update_server_certificate())
```

### Certificate Validation Fix for asyncua

After completing the method conversions, we need to apply the certificate chain validation fix to:

**File**: `.venv/lib/python3.12/site-packages/asyncua/client/client.py`

Find the certificate validation code (similar to what we did for opcua) and apply the same DER chain extraction logic.

### Node API Changes in asyncua

| Old (opcua) | New (asyncua) |
|-------------|---------------|
| `node.get_browse_name()` | `await node.read_browse_name()` |
| `node.get_children()` | `await node.get_children()` |
| `node.get_child(name)` | `await node.get_child(name)` |
| `node.call_method(method, *args)` | `await node.call_method(method, *args)` |
| `node.get_parent()` | `await node.get_parent()` |
| `node.get_value()` | `await node.read_value()` |

### Testing Checklist

After migration is complete:

- [ ] Test discover_server operation
- [ ] Test update_trustlist operation  
- [ ] Test update_server_certificate operation
- [ ] Verify certificate chain validation works
- [ ] Check error handling and logging
- [ ] Verify async operations don't block Django

## Next Steps

Would you like me to:

1. **Continue with full automated migration** - I'll complete all remaining async conversions
2. **Provide code snippets** - I'll give you the specific replacements to make manually
3. **Do it method-by-method** - We go through each change carefully with testing

The migration is straightforward but touches many lines. The asyncua library API is very similar to opcua, just with `await` keywords added.
