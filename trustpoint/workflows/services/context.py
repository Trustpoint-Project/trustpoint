"""Context assembly, export application, and design-time catalog/schema."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from django.conf import settings
from django.db import transaction

from workflows.models import WorkflowInstance

CTX_SCHEMA_VERSION = 1

# Path rules and size caps
_SEGMENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
VARS_MAX_BYTES = getattr(settings, 'WF_CTX_VARS_MAX_BYTES', 256 * 1024)
STEP_CTX_MAX_BYTES = getattr(settings, 'WF_CTX_STEP_MAX_BYTES', 128 * 1024)
STEP_TEXT_EXCERPT = getattr(settings, 'WF_CTX_STEP_TEXT_EXCERPT', 2048)


def _split_path(path: str) -> list[str]:
    segs = [s for s in (path or '').split('.') if s]
    if not segs:
        raise ValueError('empty path')
    for s in segs:
        if not _SEGMENT_RE.match(s):
            raise ValueError(f'illegal segment: {s!r}')
    return segs


def get_in(root: dict[str, Any], path: str) -> Any:
    cur: Any = root
    for seg in _split_path(path):
        if not isinstance(cur, dict) or seg not in cur:
            raise KeyError(path)
        cur = cur[seg]
    return cur


def set_in(root: dict[str, Any], path: str, value: Any, *, forbid_overwrite: bool = True) -> None:
    segs = _split_path(path)
    cur = root
    for s in segs[:-1]:
        if s not in cur or not isinstance(cur[s], dict):
            cur[s] = {}
        cur = cur[s]
    leaf = segs[-1]
    if forbid_overwrite and leaf in cur and cur[leaf] != value:
        raise ValueError(f'context collision at {path!r}')
    cur[leaf] = value


def _json_size(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=False))


def _safe_key(name_or_id: str) -> str:
    base = re.sub(r'[^A-Za-z0-9_]+', '_', (name_or_id or '').strip())
    if not base or not base[0].isalpha():
        base = f's_{base}'
    return base


def _build_id_map(instance: WorkflowInstance) -> dict[str, str]:
    definition = instance.definition.definition or {}
    nodes = list(definition.get('nodes') or [])
    used: set[str] = set()
    id_map: dict[str, str] = {}
    for idx, n in enumerate(nodes, start=1):
        node_id = str(n.get('id'))
        params = n.get('params') or {}
        human = str(params.get('name') or '') or node_id
        sk = _safe_key(human)
        base = sk
        c = 2
        while sk in used:
            sk = f'{base}_{c}'
            c += 1
        used.add(sk)
        id_map[node_id] = sk
    return id_map


@dataclass(slots=True)
class Context:
    data: dict[str, Any]


def build_context(instance: WorkflowInstance) -> Context:
    """Compose `ctx` dict (stateless, rebuildable)."""
    payload = instance.payload or {}
    sc = instance.step_contexts or {}

    # derive CSR (best-effort)
    csr_extra: dict[str, Any] | None = None
    csr_pem = payload.get('csr_pem')
    if isinstance(csr_pem, str):
        try:
            csr_obj = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
            try:
                cn_attrs = csr_obj.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                cn = cn_attrs[0].value if cn_attrs else None
            except Exception:
                cn = None
            try:
                san_ext = csr_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                dns_sans = san_ext.value.get_values_for_type(x509.DNSName)
                ip_sans = [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]
                sans = [*dns_sans, *ip_sans]
            except ExtensionNotFound:
                sans = []
            csr_extra = {
                'subject': csr_obj.subject.rfc4514_string(),
                'common_name': cn,
                'sans': sans,
                'public_key_type': csr_obj.public_key().__class__.__name__,
            }
        except Exception:
            csr_extra = None

    # per-step blobs (exclude reserved)
    steps_by_id: dict[str, Any] = {}
    for key, val in sc.items():
        if key.startswith('$'):
            continue
        steps_by_id[str(key)] = val

    # vars aggregator from global $vars
    vars_map = dict(sc.get('$vars') or {})

    # id_map (computed from definition each time; stable if node ids/names stable)
    id_map = _build_id_map(instance)
    steps_by_key: dict[str, Any] = {}
    for node_id, blob in steps_by_id.items():
        sk = id_map.get(node_id, _safe_key(node_id))
        steps_by_key[sk] = blob

    ctx = {
        'meta': {'schema': CTX_SCHEMA_VERSION},
        'workflow': {'id': str(instance.definition_id), 'name': instance.definition.name},
        'instance': {'id': str(instance.id), 'state': instance.state, 'current_step': instance.current_step},
        'payload': payload,
        'csr': csr_extra,  # may be None
        'steps': steps_by_key,     # preferred by templates/UI
        'steps_by_id': steps_by_id,  # raw ids, for debugging
        'vars': vars_map,
    }
    return Context(ctx)


def compact_context_blob(blob: dict[str, Any]) -> dict[str, Any]:
    size = _json_size(blob)
    if size <= STEP_CTX_MAX_BYTES:
        return blob
    summary: dict[str, Any] = {}
    for k, v in blob.items():
        try:
            _ = _json_size(v)
        except Exception:
            continue
        if isinstance(v, str):
            summary[k] = v[:STEP_TEXT_EXCERPT]
        elif isinstance(v, dict):
            summary[k] = {kk: ('<omitted>' if _json_size(vv) > 2048 else vv) for kk, vv in list(v.items())[:20]}
        else:
            summary[k] = v
    meta = {'_truncated': True, '_orig_size': size}
    summary['_meta'] = meta
    if _json_size(summary) <= STEP_CTX_MAX_BYTES:
        return summary
    return {'_meta': meta}

