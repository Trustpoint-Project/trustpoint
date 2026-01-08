"""Context assembly utilities for workflow templates and executors.

This module builds the per-instance template context (``ctx``) used by UI and
template rendering (Email/Webhook/etc.). It also exposes helpers for working
with nested dot paths and for compacting large step-context blobs.

Schema (top-level keys produced by :func:`build_context`):

- meta:            {"schema": int}
- workflow:        {"id": str, "name": str}
- instance:        {"id": str, "state": str, "current_step": str, "created_at": Any, "updated_at": Any}
- device:          {
                       "common_name": str | None,
                       "serial_number": str | None,
                       "device_id": Any,
                       "domain": Any,
                       "device_type": Any,
                       "created_at": Any,
                   }
- request:         {
                       "protocol": str | None,
                       "operation": str | None,
                       ... common request fields ...
                       "<protocol>": { ... protocol-specific tree ... }
                   }
- steps:           dict[str, Any]   safe keys usable with dot lookup (e.g. "step_2")
- vars:            dict[str, Any]   merged global variables bucket ($vars)

Notes:
-----
* Use ``{{ ctx.steps.step_1 }}`` in templates (recommended).
* If the UI offers a variable path, it should be resolvable at runtime.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import NameOID
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


def _lower(s: Any) -> str:
    """Lowercase string safely."""
    return str(s or '').strip().lower()


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
        msg = 'empty path'
        raise ValueError(msg)
    for s in segs:
        if not _SEGMENT_RE.match(s):
            msg = f'illegal segment: {s!r}'
            raise ValueError(msg)
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


# ---------------------------- request builders ----------------------------


def _extract_est_operation_fields(
    *,
    op: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Return EST operation-specific request fields."""
    if op == 'simplereenroll':
        # Example: value you asked for.
        return {
            'prev_cert_serial': payload.get('prev_cert_serial')
            or payload.get('previous_cert_serial')
            or payload.get('prevSerial'),
        }

    # Add other EST ops later (csrattrs, cacerts, etc.) as needed.
    return {}


def _extract_cmp_operation_fields(
    *,
    op: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Return CMP operation-specific request fields (example scaffolding)."""
    if op in {'certrequest', 'cert_request', 'certrequestmessage'}:
        return {
            # These are placeholders; wire to real payload fields once you have them.
            'transaction_id': payload.get('transaction_id') or payload.get('transactionId'),
            'sender_kid': payload.get('sender_kid') or payload.get('senderKID'),
            'certreq_id': payload.get('certreq_id') or payload.get('certReqId'),
        }

    if op in {'revocationrequest', 'revocation_request'}:
        return {
            'cert_serial': payload.get('cert_serial') or payload.get('certSerial'),
            'reason': payload.get('reason'),
        }

    return {}


def _build_request_context(instance: WorkflowInstance) -> dict[str, Any]:
    """Build ctx.request including protocol trees like ctx.request.est.<op>.*."""
    payload = instance.payload or {}
    if not isinstance(payload, dict):
        payload = {}

    req: dict[str, Any] = {}

    # EnrollmentRequest case
    if getattr(instance, 'enrollment_request_id', None) and instance.enrollment_request:
        er = instance.enrollment_request
        protocol_raw = er.protocol
        operation_raw = er.operation

        protocol = _lower(protocol_raw)
        operation = _lower(operation_raw)

        req = {
            'protocol': protocol_raw,
            'operation': operation_raw,
            'enrollment_request_id': str(er.id),
            'template': getattr(er, 'template', None),
            # CSR is typically in instance.payload (as in your current code)
            'csr_pem': payload.get('csr_pem'),
        }

        # Best-effort CSR parsing into the common request namespace
        csr_info = _parse_csr_info(req.get('csr_pem'))
        if csr_info:
            req.update(csr_info)

        # Protocol trees under ctx.request.<protocol>...
        if protocol == 'est':
            req.setdefault('est', {})
            req['est'].setdefault('common', {})
            # Common EST fields you likely want across ops:
            req['est']['common'].update(
                {
                    'csr_pem': req.get('csr_pem'),
                    'subject': req.get('subject'),
                    'common_name': req.get('common_name'),
                    'sans': req.get('sans'),
                    'public_key_type': req.get('public_key_type'),
                }
            )
            if operation:
                req['est'].setdefault(operation, {})
                req['est'][operation].update(_extract_est_operation_fields(op=operation, payload=payload))

        elif protocol == 'cmp':
            req.setdefault('cmp', {})
            req['cmp'].setdefault('common', {})
            # CMP common placeholders:
            req['cmp']['common'].update(
                {
                    'transaction_id': payload.get('transaction_id') or payload.get('transactionId'),
                }
            )
            if operation:
                req['cmp'].setdefault(operation, {})
                req['cmp'][operation].update(_extract_cmp_operation_fields(op=operation, payload=payload))

        # Add more protocols later (scep, etc.) in the same pattern.

        return req

    # DeviceRequest case
    if getattr(instance, 'device_request_id', None) and instance.device_request:
        dr = instance.device_request
        req = {
            'protocol': 'device',
            'operation': getattr(dr, 'action', None),
            'device_request_id': str(dr.id),
        }

        dr_payload = dr.payload or {}
        if isinstance(dr_payload, dict):
            for k in ('old_domain', 'new_domain', 'domain_old', 'domain_new'):
                if k in dr_payload:
                    req[k] = dr_payload.get(k)

        return req

    # Fallback
    return {
        'protocol': payload.get('protocol'),
        'operation': payload.get('operation'),
    }


# ---------------------------- vars builder ----------------------------


def _build_vars_context(instance: WorkflowInstance) -> dict[str, Any]:
    """Return the engine-managed $vars bucket for templates (if available)."""
    candidates = [
        getattr(instance, 'vars', None),
        getattr(instance, 'context_vars', None),
        getattr(instance, 'variables', None),
    ]
    for c in candidates:
        if isinstance(c, dict):
            # Apply a conservative size cap to avoid template abuse / huge blobs.
            if _json_size(c) <= VARS_MAX_BYTES:
                return c
            # Too large: keep empty (or you can truncate; current choice is conservative).
            return {}
    return {}


# ---------------------------- main API ----------------------------


def build_context(instance: WorkflowInstance) -> dict[str, Any]:
    """Build the runtime template context (ctx) for executors (email/webhook/etc.).

    Important:
    - This runtime context is the single source of truth for what templates can use.
    - UI catalog strategies should only expose paths that this runtime context provides.
    """
    ctx: dict[str, Any] = {
        'meta': {'schema': CTX_SCHEMA_VERSION},
        'workflow': {
            'id': str(instance.definition.id),
            'name': str(instance.definition.name),
        },
        'instance': {
            'id': str(instance.id),
            'state': str(instance.state),
            'current_step': str(instance.current_step),
            'created_at': instance.created_at,
            'updated_at': instance.updated_at,
        },
        'device': {},
        'request': {},
        'steps': {},
        'vars': {},
    }

    # ---- device -------------------------------------------------------------
    device_obj = None
    if getattr(instance, 'device_request_id', None) and instance.device_request:
        device_obj = instance.device_request.device
    elif getattr(instance, 'enrollment_request_id', None) and instance.enrollment_request:
        device_obj = instance.enrollment_request.device

    if device_obj:
        ctx['device'] = {
            'common_name': getattr(device_obj, 'common_name', None),
            'serial_number': getattr(device_obj, 'serial_number', None),
            'device_id': getattr(device_obj, 'id', None),
            'domain': getattr(getattr(device_obj, 'domain', None), 'unique_name', None)
            if getattr(device_obj, 'domain', None)
            else None,
            'device_type': getattr(device_obj, 'device_type', None),
            'created_at': getattr(device_obj, 'created_at', None),
        }

    # ---- request ------------------------------------------------------------
    ctx['request'] = _build_request_context(instance)

    # ---- steps --------------------------------------------------------------
    step_contexts = instance.step_contexts or {}
    if isinstance(step_contexts, dict):
        for raw_step_id, blob in step_contexts.items():
            if not isinstance(raw_step_id, str):
                continue
            if not isinstance(blob, dict):
                continue
            safe_key = _safe_step_key(raw_step_id)
            ctx['steps'][safe_key] = compact_context_blob(blob)

    # ---- vars ---------------------------------------------------------------
    ctx['vars'] = _build_vars_context(instance)

    return ctx


def compact_context_blob(blob: dict[str, Any]) -> dict[str, Any]:
    """Compact a step-context blob to fit STEP_CTX_MAX_BYTES."""
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
                    continue
            summary[key] = small
        else:
            summary[key] = value

    meta = {'_truncated': True, '_orig_size': size}
    summary['_meta'] = meta

    if _json_size(summary) <= STEP_CTX_MAX_BYTES:
        return summary

    return {'_meta': meta}
