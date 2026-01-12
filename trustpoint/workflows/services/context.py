"""Context assembly utilities for workflow templates and executors.

This module builds the per-instance runtime context (``ctx``) used by executors
(Email/Webhook/etc.) and by UI preview.

Runtime schema (top-level keys produced by build_context):

- meta:            {"schema": int}
- workflow:        {"id": str, "name": str}
- instance:        {"id": str, "state": str, "current_step": str, "created_at": Any, "updated_at": Any}
- device:          {"common_name": ..., "serial_number": ..., ...}
- request:         {"protocol": ..., "operation": ..., ... plus protocol-specific trees ...}
- steps:           dict[str, Any]   safe keys usable with dot lookup (e.g. "step_1")
- vars:            dict[str, Any]   global variables bucket (stored under step_contexts["$vars"])

Conventions:
- Per-step contexts are stored by the engine under step_contexts[<step_id>].
- Engine-reserved keys in step_contexts begin with '$' (e.g. '$vars').
- Templates should reference step contexts via safe keys: ctx.steps.step_1.outputs...
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

VARS_MAX_BYTES: int = int(getattr(settings, 'WF_CTX_VARS_MAX_BYTES', 256 * 1024))
STEP_CTX_MAX_BYTES: int = int(getattr(settings, 'WF_CTX_STEP_MAX_BYTES', 128 * 1024))
STEP_TEXT_EXCERPT: int = int(getattr(settings, 'WF_CTX_STEP_TEXT_EXCERPT', 2048))

STEP_DICT_MAX_KEYS: int = 20
STEP_VALUE_MAX_BYTES: int = 2048

_RESERVED_PREFIX: str = '$'
_SEGMENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


# ---------------------------- small utils ----------------------------


def _json_size(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=False))


def _safe_step_key(raw_id: str) -> str:
    """Return a key usable in template dot-lookup.

    Example:
        "step-1" -> "step_1"
    """
    if not raw_id:
        return 'step'
    safe = ''.join(ch if (ch.isalnum() or ch == '_') else '_' for ch in raw_id)
    if not (safe[0].isalpha() or safe[0] == '_'):
        safe = f's_{safe}'
    return safe


def _lower(s: Any) -> str:
    return str(s or '').strip().lower()


def _parse_csr_info(csr_pem: Any) -> dict[str, Any] | None:
    """Best-effort parse CSR details used in templates. Returns None on failure."""
    if not isinstance(csr_pem, str) or not csr_pem.strip():
        return None
    try:
        csr_obj = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
    except ValueError:
        return None

    try:
        cn_attrs = csr_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = cn_attrs[0].value if cn_attrs else None
    except ValueError:
        common_name = None

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
    """Return the value at a dot-separated path inside a nested dict.

    Raises KeyError if any path segment is missing or not a dict.
    """
    cur: Any = root
    for seg in _split_path(path):
        if not isinstance(cur, dict) or seg not in cur:
            raise KeyError(path)
        cur = cur[seg]
    return cur


def set_in(root: dict[str, Any], path: str, value: Any, *, forbid_overwrite: bool = True) -> None:
    """Set a value at a dot-separated path inside a nested dict.

    Intermediate dictionaries are created as needed. If forbid_overwrite
    is True, assigning a different value to an existing leaf raises ValueError.
    """
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


def _extract_est_operation_fields(*, op: str, payload: dict[str, Any]) -> dict[str, Any]:
    if op == 'simplereenroll':
        return {
            'prev_cert_serial': payload.get('prev_cert_serial')
            or payload.get('previous_cert_serial')
            or payload.get('prevSerial'),
        }
    return {}


def _extract_cmp_operation_fields(*, op: str, payload: dict[str, Any]) -> dict[str, Any]:
    if op in {'certrequest', 'cert_request', 'certrequestmessage'}:
        return {
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


def _build_est_request(op: str | None, payload: dict[str, Any], req: dict[str, Any]) -> None:
    req.setdefault('est', {})
    req['est'].setdefault('common', {})
    req['est']['common'].update(
        {
            'csr_pem': req.get('csr_pem'),
            'subject': req.get('subject'),
            'common_name': req.get('common_name'),
            'sans': req.get('sans'),
            'public_key_type': req.get('public_key_type'),
        }
    )
    if op:
        req['est'].setdefault(op, {})
        req['est'][op].update(_extract_est_operation_fields(op=op, payload=payload))


def _build_cmp_request(op: str | None, payload: dict[str, Any], req: dict[str, Any]) -> None:
    req.setdefault('cmp', {})
    req['cmp'].setdefault('common', {})
    req['cmp']['common'].update(
        {
            'transaction_id': payload.get('transaction_id') or payload.get('transactionId'),
        }
    )
    if op:
        req['cmp'].setdefault(op, {})
        req['cmp'][op].update(_extract_cmp_operation_fields(op=op, payload=payload))


def _build_enrollment_request_context(
    instance: WorkflowInstance,
    payload: dict[str, Any],
) -> dict[str, Any] | None:
    """Build request context for an instance backed by an EnrollmentRequest."""
    if not (getattr(instance, 'enrollment_request_id', None) and instance.enrollment_request):
        return None

    er = instance.enrollment_request
    protocol_raw = er.protocol
    operation_raw = er.operation

    protocol = _lower(protocol_raw)
    operation = _lower(operation_raw)

    req: dict[str, Any] = {
        'protocol': protocol_raw,
        'operation': operation_raw,
        'enrollment_request_id': str(er.id),
        'template': getattr(er, 'template', None),
        'csr_pem': payload.get('csr_pem'),
    }

    csr_info = _parse_csr_info(req.get('csr_pem'))
    if csr_info:
        req.update(csr_info)

    if protocol == 'est':
        _build_est_request(operation, payload, req)
    elif protocol == 'cmp':
        _build_cmp_request(operation, payload, req)

    return req


def _build_device_request_context(instance: WorkflowInstance) -> dict[str, Any] | None:
    """Build request context for an instance backed by a DeviceRequest."""
    if not (getattr(instance, 'device_request_id', None) and instance.device_request):
        return None

    dr = instance.device_request
    req: dict[str, Any] = {
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


def _build_fallback_request_context(payload: dict[str, Any]) -> dict[str, Any]:
    """Build a minimal request context from the instance payload."""
    return {
        'protocol': payload.get('protocol'),
        'operation': payload.get('operation'),
    }


def _build_request_context(instance: WorkflowInstance) -> dict[str, Any]:
    payload = instance.payload or {}
    if not isinstance(payload, dict):
        payload = {}

    enr = _build_enrollment_request_context(instance, payload)
    if enr is not None:
        return enr

    dev = _build_device_request_context(instance)
    if dev is not None:
        return dev

    return _build_fallback_request_context(payload)


# ---------------------------- steps + vars builders ----------------------------


def _build_steps_context(instance: WorkflowInstance) -> dict[str, Any]:
    """Expose per-step contexts under ctx.steps.<safe_step_id>.

    Reserved engine keys (starting with '$') are not exposed as steps.
    """
    out: dict[str, Any] = {}

    sc = instance.step_contexts or {}
    if not isinstance(sc, dict):
        return out

    for raw_step_id, blob in sc.items():
        if not isinstance(raw_step_id, str):
            continue
        if raw_step_id.startswith(_RESERVED_PREFIX):
            continue
        if not isinstance(blob, dict):
            continue
        out[_safe_step_key(raw_step_id)] = compact_context_blob(blob)

    return out


def _build_vars_context(instance: WorkflowInstance) -> dict[str, Any]:
    """Expose engine global vars bucket under ctx.vars.

    The engine stores this under step_contexts['$vars'].
    """
    sc = instance.step_contexts or {}
    if not isinstance(sc, dict):
        return {}

    v = sc.get('$vars')
    if not isinstance(v, dict):
        return {}

    if _json_size(v) > VARS_MAX_BYTES:
        return {}

    return v


# ---------------------------- main API ----------------------------


def build_context(instance: WorkflowInstance) -> dict[str, Any]:
    """Build the runtime template context (ctx)."""
    ctx: dict[str, Any] = {
        'meta': {'schema': CTX_SCHEMA_VERSION},
        'workflow': {'id': str(instance.definition.id), 'name': str(instance.definition.name)},
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

    # device projection
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

    ctx['request'] = _build_request_context(instance)
    ctx['steps'] = _build_steps_context(instance)
    ctx['vars'] = _build_vars_context(instance)

    return ctx


def compact_context_blob(blob: dict[str, Any]) -> dict[str, Any]:
    """Compact a context blob to fit STEP_CTX_MAX_BYTES."""
    size = _json_size(blob)
    if size <= STEP_CTX_MAX_BYTES:
        return blob

    summary: dict[str, Any] = {}
    for key, value in blob.items():
        try:
            _ = _json_size(value)
        except ValueError:
            continue

        if isinstance(value, str):
            summary[key] = value[:STEP_TEXT_EXCERPT]
        elif isinstance(value, dict):
            small: dict[str, Any] = {}
            for i, (k, v) in enumerate(value.items()):
                if i >= STEP_DICT_MAX_KEYS:  # limit keys for readability
                    break
                try:
                    small[k] = '<omitted>' if _json_size(v) > STEP_VALUE_MAX_BYTES else v
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
