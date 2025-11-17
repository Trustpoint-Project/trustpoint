from __future__ import annotations

import json as _json
import logging
from typing import Any

import requests
from django.template import Context, Template

from workflows.models import State, WorkflowInstance
from workflows.services.context import build_context, set_in
from workflows.services.executors.factory import AbstractStepExecutor
from workflows.services.types import ExecutorResult

logger = logging.getLogger(__name__)


class WebhookExecutor(AbstractStepExecutor):
    """Execute an outbound HTTP call and optionally export values to $vars.

    - URL, headers, and string body templating with Django templates using a 'ctx' dict
    - Supports method, headers, body, auth (basic|bearer), timeoutSecs
    - result_to/result_source for whole-response capture
    - fine-grained exports: [{"from_path":"json.foo","to_path":"serial"}]  # note: bare key allowed
    - Stores per-step context and returns a flat vars map for $vars merging.

    to_path:
        Accepts either "serial" or "vars.serial" (we strip optional "vars." and store under $vars).
    """

    def do_execute(self, instance: WorkflowInstance, _signal: str | None) -> ExecutorResult:
        step = next(n for n in instance.get_steps() if n['id'] == instance.current_step)
        params = dict(step.get('params') or {})

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
        result_to_raw = str(params.get('result_to') or '').strip()
        result_source = str(params.get('result_source') or 'auto').strip().lower()  # auto|json|text|status|headers
        exports = list(params.get('exports') or [])

        ctx: dict[str, Any] = build_context(instance)
        dj_ctx = Context({'ctx': ctx})

        # Render URL and header values; render body when it is a string
        try:
            url = Template(url_tpl).render(dj_ctx)
        except Exception as exc:
            logger.exception('Webhook: URL template render failed')
            return ExecutorResult(
                status=State.FAILED,
                context={'type': 'Webhook', 'status': 'failed', 'error': f'URL template error: {exc!s}', 'outputs': {}},
            )

        headers: dict[str, str] = {}
        for k, v in headers_raw.items():
            sval = str(v)
            try:
                sval = Template(sval).render(dj_ctx)
            except Exception:
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
                return ExecutorResult(
                    status=State.FAILED,
                    context={'type': 'Webhook', 'status': 'failed', 'error': f'Body template error: {exc!s}', 'outputs': {}},
                )
            try:
                data_kwargs['json'] = _json.loads(rendered)
            except Exception:
                data_kwargs['data'] = rendered.encode('utf-8')
        elif isinstance(body_raw, (dict, list)):
            data_kwargs['json'] = body_raw

        # Execute request
        try:
            resp = requests.request(method, url, headers=headers, timeout=timeout_secs, auth=auth, **data_kwargs)
        except Exception as exc:
            logger.exception('Webhook: request failed')
            return ExecutorResult(
                status=State.FAILED,
                context={'type': 'Webhook', 'status': 'failed', 'error': f'HTTP request failed: {exc!s}', 'outputs': {}},
            )

        # Try decode JSON; keep text also
        resp_json: Any | None
        try:
            resp_json = resp.json()
        except Exception:
            resp_json = None

        # Per-step context summary
        step_ctx: dict[str, Any] = {
            'type': 'Webhook',
            'status': 'passed',
            'error': None,
            'outputs': {
                'webhook': {
                    'method': method,
                    'url': url,
                    'status': resp.status_code,
                    'headers': dict(resp.headers),
                    'json': resp_json,
                    'text': None if resp_json is not None else resp.text,
                }
            },
        }

        # Build a FLAT vars map for $vars (no extra 'vars' nesting)
        flat_vars: dict[str, Any] = {}

        # Whole-result capture
        if result_to_raw:
            dest = result_to_raw[5:] if result_to_raw.startswith('vars.') else result_to_raw
            if dest:  # dot path validation is handled server-side; here we best-effort set
                val = _select_source_value(resp, resp_json, result_source)
                try:
                    set_in(flat_vars, dest, val, forbid_overwrite=True)
                except Exception:
                    pass  # invalid path or collision → ignore; validator should guard

        # Fine-grained exports
        if isinstance(exports, list):
            norm_headers = _normalize_headers_for_lookup(resp.headers)
            for exp in exports:
                if not isinstance(exp, dict):
                    continue
                from_path = str(exp.get('from_path') or '').strip()
                to_path_raw = str(exp.get('to_path') or '').strip()
                if not from_path or not to_path_raw:
                    continue
                dest = to_path_raw[5:] if to_path_raw.startswith('vars.') else to_path_raw
                try:
                    val = _extract_from_path(resp, resp_json, norm_headers, from_path)
                    set_in(flat_vars, dest, val, forbid_overwrite=True)
                except Exception:
                    pass

        return ExecutorResult(
            status=State.PASSED,
            context=step_ctx,
            vars=(flat_vars or None),
        )


# ---------------------------- helpers ----------------------------

def _safe_int(v: Any, *, default: int) -> int:
    try:
        return int(v)
    except Exception:  # noqa: BLE001
        return default

def _select_source_value(resp: requests.Response, resp_json: Any | None, source: str) -> Any:
    if source == 'status':
        return resp.status_code
    if source == 'text':
        return resp.text
    if source == 'headers':
        return dict(resp.headers)
    if source == 'json':
        return resp_json
    return resp_json if resp_json is not None else resp.text


def _normalize_headers_for_lookup(headers: Any) -> dict[str, Any]:
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
