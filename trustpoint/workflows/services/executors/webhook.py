from __future__ import annotations

import json as _json
import logging
from typing import Any

import requests
from django.template import Context, Template

from workflows.models import WorkflowInstance
from workflows.services.executors.factory import AbstractNodeExecutor
from workflows.services.types import ExecStatus, NodeResult

logger = logging.getLogger(__name__)


class WebhookExecutor(AbstractNodeExecutor):
    """Execute an outbound HTTP call and optionally export values to vars.

    Features
    - URL, headers, and (string) body templating with Django templates using a 'ctx' dict
    - Supports method, headers, body, auth (basic|bearer), timeoutSecs
    - result_to/result_source for simple whole-response capture
    - fine-grained exports: [{"from_path":"json.foo","to_path":"vars.serial"}]
    - Stores both per-step context and a 'vars' map for later steps (e.g., Email)

    from_path:
        "status"                -> HTTP status code (int)
        "text"                  -> response text (str)
        "json" or "json.a.b.0"  -> JSON root or a nested path
        "headers" or "headers.x_y"
            Header names are normalized for lookup by lower-case with '-' -> '_' so
            "Content-Type" is addressable via "headers.content_type".

    to_path:
        Must start with "vars." and be a valid dot-path (validated server-side).
    """

    def do_execute(self, instance: WorkflowInstance, _signal: str | None) -> NodeResult:
        node = next(n for n in instance.get_steps() if n['id'] == instance.current_step)
        params = dict(node.get('params') or {})

        method = str(params.get('method') or 'POST').upper()
        url_tpl = str(params.get('url') or '').strip()
        headers_raw = dict(params.get('headers') or {})
        body_raw = params.get('body')
        timeout_secs = _safe_int(params.get('timeoutSecs'), default=15)

        # auth: {"type":"basic","username":"","password":""} | {"type":"bearer","token":""}
        auth_cfg = params.get('auth')
        auth = None
        bearer_token: str | None = None
        if isinstance(auth_cfg, dict):
            t = str(auth_cfg.get('type') or '').lower()
            if t == 'basic':
                auth = (str(auth_cfg.get('username') or ''), str(auth_cfg.get('password') or ''))
            elif t == 'bearer':
                bearer_token = str(auth_cfg.get('token') or '')

        # result capture
        result_to = str(params.get('result_to') or '').strip()
        result_source = str(params.get('result_source') or 'auto').strip().lower()  # auto|json|text|status|headers

        exports = list(params.get('exports') or [])

        # Build template context ('ctx') including aggregated vars from earlier steps
        ctx = _build_ctx(instance)
        dj_ctx = Context({'ctx': ctx})

        # Render URL and header values; render body when it is a string
        try:
            url = Template(url_tpl).render(dj_ctx)
        except Exception as exc:
            logger.exception('Webhook: URL template render failed')
            return NodeResult(status=ExecStatus.FAIL, context={'error': f'URL template error: {exc!s}'})

        headers: dict[str, str] = {}
        for k, v in headers_raw.items():
            sval = str(v)
            try:
                sval = Template(sval).render(dj_ctx)
            except Exception:
                # best-effort rendering; keep original if template fails
                pass
            headers[str(k)] = sval

        if bearer_token:
            headers.setdefault('Authorization', f'Bearer {bearer_token}')

        data_kwargs: dict[str, Any] = {}
        if isinstance(body_raw, str) and body_raw.strip():
            try:
                rendered = Template(body_raw).render(dj_ctx)
            except Exception as exc:
                logger.exception('Webhook: body template render failed')
                return NodeResult(status=ExecStatus.FAIL, context={'error': f'Body template error: {exc!s}'})

            # If it parses as JSON, send JSON; else send as text
            try:
                data_kwargs['json'] = _json.loads(rendered)
            except Exception:
                data_kwargs['data'] = rendered.encode('utf-8')

        elif isinstance(body_raw, (dict, list)):
            # We do not recursively template objects for now; send as JSON as-is
            data_kwargs['json'] = body_raw

        # Execute request
        try:
            resp = requests.request(method, url, headers=headers, timeout=timeout_secs, auth=auth, **data_kwargs)
        except Exception as exc:
            logger.exception('Webhook: request failed')
            return NodeResult(status=ExecStatus.FAIL, context={'error': f'HTTP request failed: {exc!s}'})

        # Try decode JSON; keep text also (but we won’t store giant blobs in vars)
        resp_json: Any | None
        try:
            resp_json = resp.json()
        except Exception:
            resp_json = None

        # Build per-step context (always stored under step_contexts[current_step])
        step_ctx: dict[str, Any] = {
            'webhook': {
                'method': method,
                'url': url,
                'status': resp.status_code,
                'headers': dict(resp.headers),
                'json': resp_json,
                'text': None if resp_json is not None else resp.text,
            }
        }

        # Build 'vars' updates according to result_to/result_source/exports
        vars_out: dict[str, Any] = {}

        if result_to:
            val = _select_source_value(resp, resp_json, result_source)
            _vars_dot_set(vars_out, result_to, val)

        if isinstance(exports, list):
            norm_headers = _normalize_headers_for_lookup(resp.headers)
            for exp in exports:
                if not isinstance(exp, dict):
                    continue
                from_path = str(exp.get('from_path') or '').strip()
                to_path = str(exp.get('to_path') or '').strip()
                if not from_path or not to_path:
                    continue
                val = _extract_from_path(resp, resp_json, norm_headers, from_path)
                _vars_dot_set(vars_out, to_path, val)

        # Success — let engine advance. Note: vars are returned to engine for merging into $vars.
        return NodeResult(status=ExecStatus.PASSED, context=step_ctx, vars=(vars_out or None))


# ---------------------------- helpers ----------------------------


def _safe_int(v: Any, *, default: int) -> int:
    try:
        return int(v)
    except Exception:  # noqa: BLE001
        return default


def _build_ctx(instance: WorkflowInstance) -> dict[str, Any]:
    """Return the template context for URL/body/header rendering (`ctx`)."""
    # Aggregate vars from prior steps: union of any step_contexts[...]['vars']
    acc_vars: dict[str, Any] = {}
    sc = instance.step_contexts or {}
    for v in sc.values():
        if isinstance(v, dict):
            cand = v.get('vars')
            if isinstance(cand, dict):
                acc_vars.update(cand)

    return {
        'instance': instance,
        'workflow': instance.definition,
        'payload': instance.payload or {},
        'current_step': instance.current_step,
        'state': instance.state,
        'vars': acc_vars,
    }


def _select_source_value(resp: requests.Response, resp_json: Any | None, source: str) -> Any:
    if source == 'status':
        return resp.status_code
    if source == 'text':
        return resp.text
    if source == 'headers':
        return dict(resp.headers)
    if source == 'json':
        return resp_json
    # auto (default)
    return resp_json if resp_json is not None else resp.text


def _normalize_headers_for_lookup(headers: Any) -> dict[str, Any]:
    """Lower-case keys and replace '-' with '_' to support dot lookups like headers.content_type."""
    out: dict[str, Any] = {}
    try:
        for k, v in dict(headers).items():
            out[str(k).lower().replace('-', '_')] = v
    except Exception:  # noqa: BLE001
        pass
    return out


def _extract_from_path(
    resp: requests.Response,
    resp_json: Any | None,
    norm_headers: dict[str, Any],
    from_path: str,
) -> Any:
    if from_path == 'status':
        return resp.status_code
    if from_path == 'text':
        return resp.text
    if from_path == 'json':
        return resp_json
    if from_path.startswith('json.') and resp_json is not None:
        return _traverse(resp_json, from_path.split('.')[1:])
    if from_path == 'headers':
        return dict(resp.headers)
    if from_path.startswith('headers.'):
        return _traverse(norm_headers, from_path.split('.')[1:])
    return None


def _traverse(root: Any, parts: list[str]) -> Any:
    cur = root
    for p in parts:
        if isinstance(cur, dict):
            cur = cur.get(p)
        elif isinstance(cur, list):
            try:
                idx = int(p)
            except Exception:  # noqa: BLE001
                return None
            if 0 <= idx < len(cur):
                cur = cur[idx]
            else:
                return None
        else:
            return None
    return cur


def _vars_dot_set(root: dict[str, Any], to_path: str, value: Any) -> None:
    """Set a value into a nested dict under a 'vars.*' dot path."""
    if not to_path.startswith('vars.'):
        return
    parts = to_path.split('.')[1:]  # drop 'vars'
    cur: dict[str, Any] = root.setdefault('vars', {}) if parts and parts[0] != '' else root
    # if to_path is exactly 'vars', store whole value under that key
    if not parts:
        root['vars'] = value
        return
    # create/descend
    cur = root.setdefault('vars', {})
    for i, seg in enumerate(parts):
        is_last = i == len(parts) - 1
        if is_last:
            cur[seg] = value
        else:
            nxt = cur.get(seg)
            if not isinstance(nxt, dict):
                nxt = {}
                cur[seg] = nxt
            cur = nxt
