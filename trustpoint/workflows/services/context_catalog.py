"""Helpers to build a flattened catalog of context keys for runtime debug UI.

This is intended for *runtime inspection* of a specific WorkflowInstance:
- Build ctx via workflows.services.context.build_context(instance)
- Flatten ctx into dot-path keys with small sample values

The output is useful for:
- debugging templates
- debugging executor outputs
- UI variable pickers for "what exists right now"
"""

from __future__ import annotations

from typing import Any

MAX_SAMPLE_LEN = 160
MAX_ITEMS = 500  # guardrail to avoid huge payloads


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
    """Flatten nested dict/list into (dotpath, value) tuples.

    Notes:
      - Skips private keys (_*) and large/secret-ish fields by name.
      - Does not descend into non-dict/list objects.
      - Adds a synthetic "<path>[] = [len]" row for lists.
    """
    out: list[tuple[str, Any]] = []
    stack: list[tuple[str, Any, str]] = [(prefix, obj, '')]

    while stack and len(out) < MAX_ITEMS:
        base, cur, key = stack.pop()
        path = f'{base}.{key}' if base and key else (key or base)

        if isinstance(cur, dict):
            for k, v in cur.items():
                if not isinstance(k, str):
                    continue
                if k.startswith('_'):
                    continue
                # Avoid dumping PEM / CSR material into the catalog
                if k in {'csr_pem', 'private_key', 'secret', 'token'}:
                    continue
                stack.append((path, v, k))
            continue

        if isinstance(cur, list):
            out.append((f'{path}[]', f'[{len(cur)}]'))
            if cur and isinstance(cur[0], dict):
                # show shape of first item for discoverability
                stack.append((f'{path}.0', cur[0], ''))
            continue

        out.append((path, cur))

    return out


def build_catalog(ctx: dict[str, Any]) -> dict[str, Any]:
    """Build catalog rows (key/label/sample) for use in the UI."""
    rows: list[dict[str, Any]] = []

    for p, v in _flatten(ctx):
        if not p:
            continue
        rows.append(
            {
                'key': p,
                'label': p.split('.')[-1].replace('_', ' ').title(),
                'sample': _sample(v),
            }
        )

    # A couple of “nice” top items for the UI
    rows.insert(0, {'key': 'steps', 'label': 'Steps (safe keys)', 'sample': '{…}'})
    rows.insert(0, {'key': 'vars', 'label': 'Vars ($vars)', 'sample': '{…}'})

    return {
        'usage': 'Insert variables using {{ ctx.<path> }}',
        'vars': rows,
        'meta': {
            'max_items': MAX_ITEMS,
            'max_sample_len': MAX_SAMPLE_LEN,
        },
    }
