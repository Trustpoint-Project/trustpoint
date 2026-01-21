# Ruff and Mypy Compliance Report

## Summary

**Date**: 2026-01-20
**File**: `trustpoint/request/gds_push/gds_push_service.py`
**Status**: ⚠️ 25 Ruff errors, 21 Mypy errors

---

## Ruff Issues (25 total)

### Critical Issues (Should Fix)

#### 1. Import Location (PLC0415) - 1 occurrence
**Line 136**: Import inside function
```python
from devices.models import IssuedCredentialModel
```
**Reason**: Avoiding circular imports (legitimate use case)
**Action**: Can be suppressed with `# noqa: PLC0415` if needed

---

### Style Issues (Can be addressed or suppressed)

#### 2. Exception Handling - contextlib.suppress (SIM105) - 3 occurrences
**Lines**: 493, 582, 751

**Current**:
```python
try:
    client.disconnect()
except Exception:
    pass
```

**Suggested**:
```python
import contextlib

with contextlib.suppress(Exception):
    client.disconnect()
```

#### 3. Try-Except-Pass (S110) - 3 occurrences
**Lines**: 495, 584, 753

**Reason**: Silent exception handling in cleanup code
**Action**: Consider logging or use contextlib.suppress

#### 4. Blind Exception Catching (BLE001) - 10 occurrences
**Lines**: 495, 523, 584, 621, 625, 753, 788, 792, 861

**Current**:
```python
except Exception as e:
```

**Suggested**: Use specific exceptions where possible
- `opcua.ua.UaError` for OPC UA operations
- `ValueError` for parsing errors
- Keep `Exception` for cleanup code

#### 5. logging.error vs logging.exception (TRY400) - 3 occurrences
**Lines**: 626, 793, 862

**Current**:
```python
except Exception as e:
    logger.error('Failed to ...', e)
```

**Suggested**:
```python
except Exception:
    logger.exception('Failed to ...')
```

#### 6. Return in Else Block (TRY300) - 2 occurrences
**Lines**: 681, 859

**Current**:
```python
try:
    ...
    return True
except Exception:
    ...
```

**Suggested**:
```python
try:
    ...
except Exception:
    ...
else:
    return True
```

#### 7. Boolean Positional Argument (FBT003) - 1 occurrence
**Line 829**: `True` positional argument

**Current**:
```python
csr = server_config.call_method(
    create_signing_request,
    certificate_group_id,
    certificate_type_id,
    None,
    True,  # Regenerate private key
    None
)
```

**Suggested**: Not applicable - OPC UA library API

#### 8. Complexity Warning (C901) - 1 occurrence
**Line 691**: `update_server_certificate` too complex (11 > 10)

**Action**: Consider refactoring into smaller methods

#### 9. Abstract Raise (TRY301) - 2 occurrences
**Lines**: 885, 890

**Reason**: Simple validation pattern
**Action**: Can be suppressed or left as-is

---

## Mypy Issues (21 total)

### Import Issues (3 occurrences)

**Lines**: 23, 24, 25 - Missing stubs for `opcua` library
```
error: Skipping analyzing "opcua": module is installed, but missing library stubs
```
**Action**: Add `# type: ignore[import-untyped]` or install type stubs if available

---

### Type Annotation Issues

#### 1. Optional Type Confusion (7 occurrences)

**Lines**: 116, 118, 123, 124, 153, 351-390

**Problem**: Variables initialized as `None` but assigned concrete types
```python
self.domain_credential = None  # Type: None
self.server_truststore = None  # Type: None

# Later:
self.domain_credential = self._get_domain_credential()  # IssuedCredentialModel
self.server_truststore = self._get_server_truststore()  # TruststoreModel
```

**Solution**: Use `Optional` type hints
```python
from typing import Optional

self.domain_credential: Optional[IssuedCredentialModel] = None
self.server_truststore: Optional[TruststoreModel] = None
```

#### 2. Return Type Mismatch (1 occurrence)

**Line 156**: Function returns `IssuedCredentialModel | None` but signature says `IssuedCredentialModel`

**Current**:
```python
def _get_domain_credential(self) -> IssuedCredentialModel:
    ...
    return credential  # Could be None
```

**Fix**: Already handled - the method raises exception if None

#### 3. Dict Type Parameters (4 occurrences)

**Lines**: 468, 498, 507, 590, 760

**Current**:
```python
def discover_server(self) -> tuple[bool, str, dict | None]:
```

**Suggested**:
```python
def discover_server(self) -> tuple[bool, str, dict[str, Any] | None]:
```

**For server_info dict**:
```python
server_info: dict[str, Any] = {}
```

#### 4. Returning Any (1 occurrence)

**Line 394**: Returning cryptography object bytes
```python
return cert_crypto.public_bytes(encoding=serialization.Encoding.DER)
```

**Action**: Acceptable - cryptography library limitation

#### 5. Union Attribute Access (2 occurrences)

**Lines**: 153, 895 - Accessing attributes on Optional types

**Problem**:
```python
credential.common_name  # credential could be None
issuing_ca.credential.get_private_key()  # credential could be None
```

**Action**: Already protected by earlier checks

---

## Recommended Actions

### Priority 1: Fix Type Hints (Easy)

1. **Add Optional type annotations**:
```python
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from devices.models import DeviceModel, IssuedCredentialModel
    from pki.models import CaModel
    from pki.models.truststore import TruststoreModel

class GdsPushService:
    def __init__(self, device: DeviceModel, *, insecure: bool = False) -> None:
        self.device = device
        self.domain_credential: Optional[IssuedCredentialModel] = None
        self.server_truststore: Optional[TruststoreModel] = None
```

2. **Fix dict type annotations**:
```python
def discover_server(self) -> tuple[bool, str, dict[str, Any] | None]:
    """..."""

def _gather_server_info(self, client: Client) -> dict[str, Any]:
    server_info: dict[str, Any] = {}
```

### Priority 2: Improve Exception Handling (Medium)

1. **Use contextlib.suppress for cleanup**:
```python
import contextlib

finally:
    if client:
        with contextlib.suppress(Exception):
            client.disconnect()
```

2. **Use logging.exception instead of logging.error**:
```python
except Exception:
    logger.exception('Failed to discover trustlist nodes')
```

3. **Use specific exceptions where possible**:
```python
from opcua.ua import UaError

try:
    ...
except UaError as e:
    logger.error('OPC UA error: %s', e)
except ValueError as e:
    logger.error('Validation error: %s', e)
```

### Priority 3: Refactoring (Low - Optional)

1. **Reduce complexity of `update_server_certificate`**:
   - Extract certificate group filtering into separate method
   - Extract single certificate update into existing method

2. **Move return statements to else blocks**:
```python
try:
    # operation
except Exception:
    # error handling
else:
    return success_value
```

---

## Suppression Options

If these are intentional patterns, you can suppress specific warnings:

### File-level suppressions
Add to `pyproject.toml`:
```toml
[tool.ruff.lint]
ignore = [
    "PLC0415",  # Import outside top-level (circular import workaround)
    "TRY301",   # Abstract raise (simple validation pattern)
    "FBT003",   # Boolean positional (external library API)
]
```

### Line-level suppressions
```python
from devices.models import IssuedCredentialModel  # noqa: PLC0415
```

### Mypy suppressions
```python
from opcua import Client  # type: ignore[import-untyped]
```

---

## Testing After Fixes

```bash
# Check ruff
uv run ruff check trustpoint/request/gds_push/gds_push_service.py

# Check mypy
uv run mypy trustpoint/request/gds_push/gds_push_service.py

# Run with auto-fix
uv run ruff check trustpoint/request/gds_push/gds_push_service.py --fix

# Run tests
uv run pytest tests/ -k gds_push
```

---

## Current Status

- ✅ **Compiles successfully** - No syntax errors
- ✅ **Imports work** - All dependencies resolved
- ✅ **Django checks pass** - No configuration issues
- ⚠️ **Ruff warnings** - Mostly style issues, not functional bugs
- ⚠️ **Mypy errors** - Type annotation improvements needed

**Recommendation**: Fix Priority 1 (type hints) for better type safety. Priority 2 and 3 can be addressed in follow-up refactoring if desired.
