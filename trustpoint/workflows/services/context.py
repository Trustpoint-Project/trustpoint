"""Context assembly utilities for workflow templates and executors.

This module builds the per-instance template context (``ctx``) used by UI and
template rendering (Email/Webhook/etc.). It also exposes helpers for working
with nested dot paths and for compacting large step-context blobs.

Schema (top-level keys produced by :func:`build_context`):

- meta:            {"schema": int}
- workflow:        {"id": str, "name": str, "instance_id": Any, "instance_state": str}
- device:          {
                       "common_name": str,
                       "serial_number": str,
                       "device_id": Any,
                       "domain": Any,
                       "device_type": Any,
                       "created_at": Any,
                   }
- request:         {
                       "protocol": str | None,
                       "operation": str | None,
                       "enrollment_request_id": str | None,
                       "csr_pem": str | None,
                       ...CSR-derived fields from _parse_csr_info...
                   }
- steps:           dict[str, Any]   safe keys usable with dot lookup (e.g. "step_2")
- vars:            dict[str, Any]   merged global variables bucket ($vars)

Notes:
-----
* Use ``{{ ctx.steps.step_1 }}`` in templates (recommended).
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import NameOID
from devices.models import DeviceModel
from django.conf import settings

if TYPE_CHECKING:
    from workflows.models import WorkflowInstance

__all__ = [
    'CTX_SCHEMA_VERSION',
    'STEP_CTX_MAX_BYTES',
    'STEP_TEXT_EXCERPT',
    'VARS_MAX_BYTES',
    'build_context',
    'compact_context_blob',
    'get_in',
    'set_in',
]

# ---------------------------- constants ----------------------------

CTX_SCHEMA_VERSION: int = 1

# Size caps (engine enforces for $vars; compacting is for per-step blobs)
VARS_MAX_BYTES: int = int(getattr(settings, 'WF_CTX_VARS_MAX_BYTES', 256 * 1024))
STEP_CTX_MAX_BYTES: int = int(getattr(settings, 'WF_CTX_STEP_MAX_BYTES', 128 * 1024))
STEP_TEXT_EXCERPT: int = int(getattr(settings, 'WF_CTX_STEP_TEXT_EXCERPT', 2048))

# Reserved prefix for engine-managed blobs inside step_contexts
_RESERVED_PREFIX: str = '$'

# Path rules for get_in/set_in
_SEGMENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


# ---------------------------- small utils ----------------------------


def _json_size(obj: Any) -> int:
    """Return JSON-encoded length (UTF-8, ensure_ascii=False)."""
    return len(json.dumps(obj, ensure_ascii=False))


def _safe_step_key(raw_id: str) -> str:
    """Return a 'safe' key usable with template dot-lookup.

    - Replace any char not [A-Za-z0-9_] with '_'
    - Ensure first char is alpha or '_'
    """
    if not raw_id:
        return 'step'
    out_chars: list[str] = []
    for ch in raw_id:
        if ch.isalnum() or ch == '_':
            out_chars.append(ch)
        else:
            out_chars.append('_')
    safe = ''.join(out_chars)
    if not (safe[0].isalpha() or safe[0] == '_'):
        safe = f's_{safe}'
    return safe


def _parse_csr_info(csr_pem: Any) -> dict[str, Any] | None:
    """Best-effort parse of CSR details used in templates. Returns None on failure."""
    if not isinstance(csr_pem, str) or not csr_pem.strip():
        return None
    try:
        csr_obj = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
    except ValueError:
        return None

    # Common Name
    try:
        cn_attrs = csr_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = cn_attrs[0].value if cn_attrs else None
    except ValueError:
        common_name = None

    # SANs (DNS and IP)  # noqa: ERA001
    try:
        san_ext = csr_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_sans = san_ext.value.get_values_for_type(x509.DNSName)
        ip_sans = [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]
        sans = [*dns_sans, *ip_sans]
    except ExtensionNotFound:
        sans = []

    return {
        'subject': csr_obj.subject.rfc4514_string(),
        'common_name': common_name,
        'sans': sans,
        'public_key_type': csr_obj.public_key().__class__.__name__,
    }


# ---------------------------- dot-path helpers ----------------------------


def _split_path(path: str) -> list[str]:
    """Split and validate a dot path like 'a.b.c'. Raise ValueError on invalid."""
    segs = [s for s in (path or '').split('.') if s]
    if not segs:
        msg = 'empty path'
        raise ValueError(msg)
    for s in segs:
        if not _SEGMENT_RE.match(s):
            msg = f'illegal segment: {s!r}'
            raise ValueError(msg)
    return segs


def get_in(root: dict[str, Any], path: str) -> Any:
    """Return value at dot path from a nested dict or raise KeyError.

    Args:
        root: Root dictionary to traverse.
        path: Dot-separated path (e.g. ``"a.b.c"``).

    Returns:
        Any: The value found at the given path.

    Raises:
        KeyError: If the full path does not exist in the nested dictionaries.
        ValueError: If the path is empty or contains illegal segments.
    """
    cur: Any = root
    for seg in _split_path(path):
        if not isinstance(cur, dict) or seg not in cur:
            raise KeyError(path)
        cur = cur[seg]
    return cur


def set_in(root: dict[str, Any], path: str, value: Any, *, forbid_overwrite: bool = True) -> None:
    """Set value at dot path. If forbid_overwrite=True, raise on value change collisions."""
    segments = _split_path(path)
    cur: dict[str, Any] = root
    for s in segments[:-1]:
        nxt = cur.get(s)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[s] = nxt
        cur = nxt
    leaf = segments[-1]
    if forbid_overwrite and leaf in cur and cur[leaf] != value:
        msg = f'context collision at {path!r}'
        raise ValueError(msg)
    cur[leaf] = value


# ---------------------------- main API ----------------------------


def build_context(instance: WorkflowInstance) -> dict[str, Any]:
    """Compose the template context ``ctx`` for a workflow instance.

    Args:
        instance: Workflow instance for which to build the context.

    Returns:
        dict[str, Any]: A plain dict suitable for Django templates.
    """
    payload: dict[str, Any] = dict(instance.payload or {})
    step_contexts: dict[str, Any] = dict(instance.step_contexts or {})

    # Optional CSR enrichment
    csr_info = _parse_csr_info(payload.get('csr_pem')) or {}

    # Per-step outputs (exclude reserved keys like "$vars")
    steps_by_id: dict[str, Any] = {
        key: value
        for key, value in step_contexts.items()
        if isinstance(key, str) and not key.startswith(_RESERVED_PREFIX)
    }

    # Safe names for convenient template access
    step_names: dict[str, str] = {raw: _safe_step_key(raw) for raw in steps_by_id}
    steps_safe: dict[str, Any] = {step_names[raw]: value for raw, value in steps_by_id.items()}

    # Device (required for current usage; will raise if missing)
    device = DeviceModel.objects.get(pk=payload.get('device_id', ''))

    # Global variables bucket ($vars in engine)
    vars_map: dict[str, Any] = dict(step_contexts.get('$vars') or {})

    request = {
        'protocol': payload.get('protocol'),
        'operation': payload.get('operation'),
        'enrollment_request_id': payload.get('fingerprint'),
        'csr_pem': payload.get('csr_pem'),
        **csr_info,
    }

    ctx: dict[str, Any] = {
        'meta': {'schema': CTX_SCHEMA_VERSION},
        'workflow': {
            'id': str(instance.definition.pk),
            'name': instance.definition.name,
            'instance_id': instance.id,
            'instance_state': instance.state,
        },
        'device': {
            'common_name': device.common_name,
            'serial_number': device.serial_number,
            'device_id': device.pk,
            'domain': device.domain,
            'device_type': device.device_type,
            'created_at': device.created_at,
        },
        'request': request,
        'steps': steps_safe,
        'vars': vars_map,
    }
    return ctx


def compact_context_blob(blob: dict[str, Any]) -> dict[str, Any]:
    """Compact a step-context blob to fit STEP_CTX_MAX_BYTES.

    The compaction is lossy: long strings are truncated, large nested dicts
    are summarized. A ``"_meta"`` key indicates truncation and original size.

    Args:
        blob: Original step-context dictionary.

    Returns:
        dict[str, Any]: Either the original blob, or a compacted summary
        that fits within STEP_CTX_MAX_BYTES.
    """
    size = _json_size(blob)
    if size <= STEP_CTX_MAX_BYTES:
        return blob

    summary: dict[str, Any] = {}
    for key, value in blob.items():
        # skip values that cannot be serialized
        try:
            _ = _json_size(value)
        except ValueError:
            continue

        if isinstance(value, str):
            summary[key] = value[:STEP_TEXT_EXCERPT]
        elif isinstance(value, dict):
            # Keep first ~20 keys, redact very large leaf values
            small: dict[str, Any] = {}
            for i, (k, v) in enumerate(value.items()):
                if i >= 20:  # noqa: PLR2004
                    break
                try:
                    small[k] = '<omitted>' if _json_size(v) > 2048 else v  # noqa: PLR2004
                except ValueError:
                    # Non-serializable leaves are omitted
                    continue
            summary[key] = small
        else:
            summary[key] = value

    meta = {'_truncated': True, '_orig_size': size}
    summary['_meta'] = meta

    if _json_size(summary) <= STEP_CTX_MAX_BYTES:
        return summary

    # If still too large, only return the meta
    return {'_meta': meta}
