# workflows/services/context_catalog.py
from __future__ import annotations
from typing import Any, Iterable

MAX_SAMPLE_LEN = 160
MAX_ITEMS      = 500      # guardrail

def _is_scalar(v: Any) -> bool:
    return isinstance(v, (str, int, float, bool)) or v is None

def _sample(v: Any) -> str:
    if isinstance(v, str):
        s = v.replace('\n', ' ')
        return (s[:MAX_SAMPLE_LEN] + '…') if len(s) > MAX_SAMPLE_LEN else s
    if _is_scalar(v):
        return str(v)
    if isinstance(v, list):
        return f'[{len(v)} items]'
    if isinstance(v, dict):
        return '{…}'
    return type(v).__name__

def _flatten(obj: Any, prefix: str = '') -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    stack: list[tuple[str, Any, str]] = [(prefix, obj, '')]
    while stack and len(out) < MAX_ITEMS:
        base, cur, key = stack.pop()
        path = f'{base}.{key}' if base and key else (key or base)
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k.startswith('_') or k in {'csr_pem'}:
                    continue
                stack.append((path, v, k))
        elif isinstance(cur, list):
            # expose length and first item’s fields (if dict) for discoverability
            out.append((f'{path}[]', f'[{len(cur)}]',))
            if cur and isinstance(cur[0], dict):
                stack.append((f'{path}.0', cur[0], ''))  # show example shape
        else:
            out.append((path, cur))
    return out

def build_catalog(ctx: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for p, v in _flatten(ctx):
        if not p:
            continue
        # Skip very deep technical trees that add noise
        if p.startswith('steps_by_id'):
            continue
        rows.append({
            'key': p,
            'label': p.split('.')[-1].replace('_', ' ').title(),
            'sample': _sample(v),
        })
    # Provide a few “nice” aliases up top
    rows.insert(0, {'key': 'steps', 'label': 'Steps (safe keys)', 'sample': '{…}'})
    return {
        'usage': 'Insert variables using {{ ctx.<path> }}',
        'vars': rows,
    }
