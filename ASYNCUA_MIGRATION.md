# Migration from opcua to asyncua

## Overview
Migrating from the deprecated `opcua` library to the modern `asyncua` library (also known as `opcua-asyncio`).

## Key Changes

### 1. Dependencies
- **Old**: `opcua==0.98.13`
- **New**: `asyncua>=1.1.5`

### 2. Import Changes
```python
# Old
from opcua import Client, ua
from opcua.crypto import security_policies
from opcua.ua.ua_binary import struct_to_binary

# New
from asyncua import Client, ua
from asyncua.crypto import security_policies
from asyncua.ua.ua_binary import struct_to_binary
```

### 3. API Changes

#### Client Methods (all become async)
```python
# Old (sync)
client = Client(url)
client.connect()
client.disconnect()
result = client.get_endpoints()
node = client.get_node(node_id)

# New (async)
client = Client(url)
await client.connect()
await client.disconnect()
result = await client.get_endpoints()
node = client.get_node(node_id)  # Still sync
```

#### Node Methods (all become async)
```python
# Old (sync)
value = node.get_value()
children = node.get_children()
node.call_method(method, *args)

# New (async)
value = await node.read_value()
children = await node.get_children()
await node.call_method(method, *args)
```

### 4. Service Method Signatures

All public methods in `GdsPushService` become async:

```python
# Old
def discover_server(self) -> tuple[bool, str, dict[str, Any] | None]:
def update_trustlist(self) -> tuple[bool, str]:
def update_server_certificate(self) -> tuple[bool, str, bytes | None]:

# New
async def discover_server(self) -> tuple[bool, str, dict[str, Any] | None]:
async def update_trustlist(self) -> tuple[bool, str]:
async def update_server_certificate(self) -> tuple[bool, str, bytes | None]:
```

### 5. Calling from Django Views

Django views are synchronous, so we need to use `asyncio.run()`:

```python
# Old
service = GdsPushService(device=device)
success, message = service.update_trustlist()

# New
import asyncio
service = GdsPushService(device=device)
success, message = asyncio.run(service.update_trustlist())
```

### 6. Context Managers

```python
# Old
client.connect()
try:
    # ... operations ...
finally:
    client.disconnect()

# New
async with client:
    # ... operations ...
    # auto-disconnects
```

### 7. Certificate Validation Fix

The certificate chain validation fix needs to be applied to asyncua instead of opcua.

**Location**: `.venv/lib/python3.12/site-packages/asyncua/client/client.py`

Same logic as before, but in the asyncua library.

## Benefits of Migration

1. ✅ **Active maintenance** - asyncua is actively developed
2. ✅ **Better performance** - async/await allows concurrent operations
3. ✅ **Modern Python** - follows async/await patterns
4. ✅ **Better error handling** - improved exception hierarchy
5. ✅ **More features** - newer OPC UA spec features

## Implementation Plan

### Phase 1: Update Dependencies ✅
- [x] Update `pyproject.toml` to use `asyncua>=1.1.5`
- [ ] Run `uv sync` to install new dependency

### Phase 2: Update GDS Push Service
- [ ] Update imports in `gds_push_service.py`
- [ ] Convert all methods to async
- [ ] Update all OPC UA client calls to use await
- [ ] Update context managers to use async with

### Phase 3: Update Django Views
- [ ] Add `asyncio.run()` wrapper for async calls in views
- [ ] Handle exceptions from async code

### Phase 4: Update Certificate Validation
- [ ] Apply certificate chain validation fix to asyncua library
- [ ] Test certificate chain handling

### Phase 5: Testing
- [ ] Test discover_server operation
- [ ] Test update_trustlist operation
- [ ] Test update_server_certificate operation
- [ ] Verify error handling and logging

## Files to Modify

1. ✅ `pyproject.toml` - dependency update
2. `trustpoint/request/gds_push/gds_push_service.py` - main service file
3. `trustpoint/devices/views.py` - Django views that call GDS Push
4. `.venv/lib/python3.12/site-packages/asyncua/client/client.py` - certificate validation fix

## Notes

- The asyncua API is very similar to opcua, mostly just adding `await`
- The certificate chain validation logic remains the same
- Django ORM calls remain synchronous and don't need changes
- Error handling patterns remain similar
