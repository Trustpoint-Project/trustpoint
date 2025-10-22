"""Context assembly utilities for workflow templates and executors.

This module builds the per-instance template context (`ctx`) used by UI and
template rendering (Email/Webhook/etc.). It also exposes helpers for working
with nested dot paths and for compacting large step-context blobs.

Schema (top-level keys produced by :func:`build_context`):

- meta.schema:     integer schema version
- workflow:        {"id": str, "name": str}
- instance:        {"id": str, "state": str, "current_step": str}
- payload:         dict (original trigger payload)
- csr:             dict | None  (best-effort CSR parse: subject/common_name/sans/public_key_type)
- steps_by_id:     dict[str, Any]   raw step ids (e.g. "step-2")
- steps_safe:      dict[str, Any]   safe keys usable with dot lookup (e.g. "step_2")
- steps:           dict[str, Any]   alias -> steps_safe (recommended for templates)
- step_names:      dict[str, str]   raw id -> safe key mapping
- vars:            dict[str, Any]   merged global variables bucket

Notes:
-----
* Use ``{{ ctx.steps.step_1 }}`` in templates (recommended).
* To reference raw ids with dashes, use bracket notation:
  ``{{ ctx.steps_by_id."step-1".outputs.subject }}``.
"""

from __future__ import annotations

import json
import re
from typing import Any

from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import NameOID
from django.conf import settings

from devices.models import DeviceModel
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
    except Exception:
        return None

    # Common Name
    try:
        cn_attrs = csr_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = cn_attrs[0].value if cn_attrs else None
    except Exception:
        common_name = None

    # SANs (DNS and IP)
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
        raise ValueError('empty path')
    for s in segs:
        if not _SEGMENT_RE.match(s):
            raise ValueError(f'illegal segment: {s!r}')
    return segs


def get_in(root: dict[str, Any], path: str) -> Any:
    """Return value at dot path from a nested dict or raise KeyError."""
    cur: Any = root
    for seg in _split_path(path):
        if not isinstance(cur, dict) or seg not in cur:
            raise KeyError(path)
        cur = cur[seg]
    return cur


def set_in(root: dict[str, Any], path: str, value: Any, *, forbid_overwrite: bool = True) -> None:
    """Set value at dot path. If forbid_overwrite=True, raise on value change collisions."""
    segs = _split_path(path)
    cur: dict[str, Any] = root
    for s in segs[:-1]:
        nxt = cur.get(s)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[s] = nxt
        cur = nxt
    leaf = segs[-1]
    if forbid_overwrite and leaf in cur and cur[leaf] != value:
        raise ValueError(f'context collision at {path!r}')
    cur[leaf] = value


# ---------------------------- main API ----------------------------


def build_context(instance: WorkflowInstance) -> dict[str, Any]:
    """Compose the template context `ctx` for a workflow instance.

    Returns:
        dict[str, Any]: A plain dict suitable for Django templates.
    """
    payload: dict[str, Any] = dict(instance.payload or {})
    step_contexts: dict[str, Any] = dict(instance.step_contexts or {})

    # Optional CSR enrichment
    csr_info = _parse_csr_info(payload.get('csr_pem')) or {}

    # Per-step outputs (exclude reserved keys like "$vars")
    steps_by_id: dict[str, Any] = {}
    for key, value in step_contexts.items():
        if not isinstance(key, str):
            continue
        if key.startswith(_RESERVED_PREFIX):
            continue
        steps_by_id[key] = value

    # Safe names for convenient template access
    step_names: dict[str, str] = {raw: _safe_step_key(raw) for raw in steps_by_id}
    steps_safe: dict[str, Any] = {step_names[raw]: value for raw, value in steps_by_id.items()}

    # Get devuice
    device = DeviceModel.objects.get(pk=payload.get('device_id', ''))

    # Global variables bucket ($vars in engine)
    vars_map: dict[str, Any] = dict(step_contexts.get('$vars') or {})

    request = dict({
            'protocol': payload.get('protocol'),
            'operation': payload.get('operation'),
            'enrollment_request_id': payload.get('fingerprint'),
            'csr_pem': payload.get('csr_pem'),
        }, **csr_info)

    ctx: dict[str, Any] = {
        'meta': {'schema': CTX_SCHEMA_VERSION},
        'workflow': {
            'id': str(instance.definition.pk),
            'name': instance.definition.name,
            'instance_id': instance.id,
            'instance_state': instance.state
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
    are summarized. A '_meta' key indicates truncation and original size.
    """
    size = _json_size(blob)
    if size <= STEP_CTX_MAX_BYTES:
        return blob

    summary: dict[str, Any] = {}
    for key, value in blob.items():
        # skip values that cannot be serialized
        try:
            _ = _json_size(value)
        except Exception:
            continue

        if isinstance(value, str):
            summary[key] = value[:STEP_TEXT_EXCERPT]
        elif isinstance(value, dict):
            # Keep first ~20 keys, redact very large leaf values
            small: dict[str, Any] = {}
            for i, (k, v) in enumerate(value.items()):
                if i >= 20:
                    break
                try:
                    small[k] = '<omitted>' if _json_size(v) > 2048 else v
                except Exception:
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
