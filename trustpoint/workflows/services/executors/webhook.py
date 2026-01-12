"""Webhook step executor.

Executes an outbound HTTP call and optionally exports values to $vars.

Templating:
- URL, headers, and string body are rendered using Django templates with context:
    {"ctx": build_context(instance)}

Exports:
- webhook_variable captures a "whole result" under a destination path in $vars.
- exports is a list of dicts: {"from_path":"json.foo", "to_path":"serial"}
- to_path may be "serial" or "vars.serial"; "vars." is stripped and stored under $vars.

Collision policy:
- Exports and webhook_variable writes are no-overwrite.
- Collisions raise ValueError and are handled by the engine as a FAILED instance.
"""

from __future__ import annotations

import contextlib
import json as _json
import logging
from typing import Any

import requests
from django.template import TemplateSyntaxError, engines

from workflows.models import State, WorkflowInstance
from workflows.services.context import build_context, set_in
from workflows.services.executors.factory import AbstractStepExecutor
from workflows.services.types import ExecutorResult, StepContext

logger = logging.getLogger(__name__)


class WebhookExecutor(AbstractStepExecutor):
    """Execute an outbound HTTP call and optionally export values to $vars."""

    def do_execute(self, instance: WorkflowInstance, _signal: str | None) -> ExecutorResult:
        """Execute the webhook step for the current workflow instance.

        Performs template rendering, executes the HTTP request, builds a StepContext
        describing the outcome, and returns exported variables for merging into ctx.vars.
        """
        params = _get_step_params(instance)

        (
            method,
            url_tpl,
            headers_raw,
            body_raw,
            timeout_secs,
            auth_cfg,
            webhook_variable_raw,
            result_source,
            exports,
        ) = _extract_webhook_config(params)

        ctx: dict[str, Any] = build_context(instance)
        dj = engines['django']
        template_ctx = {'ctx': ctx}

        auth, bearer_token = _build_auth(auth_cfg)

        ok, url, err_msg = _render_template_str(dj, template_ctx, url_tpl, label='URL')
        if not ok:
            return ExecutorResult(status=State.FAILED, context=_make_error_context(err_msg))

        ok, headers, hdr_err = _render_headers(dj, template_ctx, headers_raw, bearer_token=bearer_token)
        if not ok:
            return ExecutorResult(status=State.FAILED, context=_make_error_context(hdr_err))

        ok, data_kwargs, body_err = _build_body(dj, template_ctx, body_raw)
        if not ok:
            return ExecutorResult(status=State.FAILED, context=_make_error_context(body_err))

        options = {
            'headers': headers,
            'timeout_secs': timeout_secs,
            'auth': auth,
            'data_kwargs': data_kwargs,
        }
        resp, resp_json, req_err = _perform_request(method, url, options)
        if req_err is not None or resp is None:
            return ExecutorResult(
                status=State.FAILED,
                context=_make_error_context(req_err or 'HTTP request failed'),
            )

        step_ctx = _build_step_context(method, url, resp, resp_json)

        # no silent suppression; collisions propagate to engine (FAILED + engine context)
        flat_vars = _build_flat_vars(resp, resp_json, webhook_variable_raw, result_source, exports)

        return ExecutorResult(
            status=State.PASSED,
            context=step_ctx,
            vars=(flat_vars or None),
        )


def _get_step_params(instance: WorkflowInstance) -> dict[str, Any]:
    step = next((s for s in instance.get_steps() if s.get('id') == instance.current_step), None)
    if step is None:
        msg = f'Unknown current step id {instance.current_step!r}'
        raise ValueError(msg)
    return dict(step.get('params') or {})


def _extract_webhook_config(
    params: dict[str, Any],
) -> tuple[str, str, dict[str, Any], Any, int, Any, str, str, list[Any]]:
    method = str(params.get('method') or 'POST').upper()
    url_tpl = str(params.get('url') or '').strip()
    headers_raw = dict(params.get('headers') or {})
    body_raw = params.get('body')
    timeout_secs = _safe_int(params.get('timeoutSecs'), default=15)
    auth_cfg = params.get('auth')
    webhook_variable_raw = str(params.get('webhook_variable') or '').strip()
    result_source = str(params.get('result_source') or 'auto').strip().lower()
    exports = list(params.get('exports') or [])
    return (
        method,
        url_tpl,
        headers_raw,
        body_raw,
        timeout_secs,
        auth_cfg,
        webhook_variable_raw,
        result_source,
        exports,
    )


def _build_auth(auth_cfg: Any) -> tuple[Any, str | None]:
    auth = None
    bearer_token: str | None = None
    if isinstance(auth_cfg, dict):
        t = str(auth_cfg.get('type') or '').lower()
        if t == 'basic':
            auth = (str(auth_cfg.get('username') or ''), str(auth_cfg.get('password') or ''))
        elif t == 'bearer':
            bearer_token = str(auth_cfg.get('token') or '')
    return auth, bearer_token


def _render_template_str(dj: Any, template_ctx: dict[str, Any], src: str, *, label: str) -> tuple[bool, str, str]:
    if not isinstance(src, str) or not src.strip():
        return False, '', f'{label} is missing.'
    try:

        rendered = dj.from_string(src).render(template_ctx).strip()
    except TemplateSyntaxError as exc:
        logger.exception('Webhook: %s template syntax error', label)
        return False, '', f'{label} template syntax error: {exc}'
    except Exception as exc:
        logger.exception('Webhook: %s render failed', label)
        return False, '', f'{label} render error: {exc!s}'
    return True, rendered, ''


def _render_headers(
    dj: Any,
    template_ctx: dict[str, Any],
    headers_raw: dict[str, Any],
    *,
    bearer_token: str | None,
) -> tuple[bool, dict[str, str], str]:
    headers: dict[str, str] = {}
    for k, v in headers_raw.items():
        sval = str(v)
        try:
            # keep autoescape default; headers are plain strings
            sval = dj.from_string(sval).render(template_ctx).strip()
        except TemplateSyntaxError as exc:
            return False, {}, f'Header template syntax error for {k!r}: {exc}'
        except Exception as exc:  # noqa: BLE001
            return False, {}, f'Header render error for {k!r}: {exc!s}'
        headers[str(k)] = sval

    if bearer_token:
        headers.setdefault('Authorization', f'Bearer {bearer_token}')

    return True, headers, ''


def _build_body(dj: Any, template_ctx: dict[str, Any], body_raw: Any) -> tuple[bool, dict[str, Any], str]:
    data_kwargs: dict[str, Any] = {}

    if isinstance(body_raw, str) and body_raw.strip():
        try:
            rendered = dj.from_string(body_raw).render(template_ctx)
        except TemplateSyntaxError as exc:
            logger.exception('Webhook: body template syntax error')
            return False, {}, f'Body template syntax error: {exc}'
        except Exception as exc:
            logger.exception('Webhook: body render failed')
            return False, {}, f'Body render error: {exc!s}'

        try:
            data_kwargs['json'] = _json.loads(rendered)
        except _json.JSONDecodeError:
            data_kwargs['data'] = rendered.encode('utf-8')

    elif isinstance(body_raw, (dict, list)):
        data_kwargs['json'] = body_raw

    return True, data_kwargs, ''


def _perform_request(
    method: str,
    url: str,
    options: dict[str, Any],
) -> tuple[requests.Response | None, Any | None, str | None]:
    headers = options.get('headers') or {}
    timeout_secs = options.get('timeout_secs') or 0
    auth = options.get('auth')
    data_kwargs = options.get('data_kwargs') or {}

    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            timeout=timeout_secs,
            auth=auth,
            **data_kwargs,
        )
    except Exception as exc:
        logger.exception('Webhook: request failed')
        return None, None, f'HTTP request failed: {exc!s}'

    try:
        resp_json: Any | None = resp.json()
    except ValueError:
        resp_json = None

    return resp, resp_json, None


def _build_step_context(method: str, url: str, resp: requests.Response, resp_json: Any | None) -> StepContext:
    outputs: dict[str, Any] = {
        'webhook': {
            'method': method,
            'url': url,
            'status': resp.status_code,
            'headers': dict(resp.headers),
            'json': resp_json,
            'text': None if resp_json is not None else resp.text,
        }
    }
    return StepContext(
        step_type='Webhook',
        step_status='passed',
        error=None,
        outputs=outputs,
    )


def _build_flat_vars(
    resp: requests.Response,
    resp_json: Any | None,
    webhook_variable_raw: str,
    result_source: str,
    exports: list[Any],
) -> dict[str, Any]:
    flat_vars: dict[str, Any] = {}

    if webhook_variable_raw:
        dest = webhook_variable_raw.removeprefix('vars.')
        if dest:
            val = _select_source_value(resp, resp_json, result_source)
            set_in(flat_vars, dest, val, forbid_overwrite=True)

    if isinstance(exports, list):
        norm_headers = _normalize_headers_for_lookup(resp.headers)
        for exp in exports:
            if not isinstance(exp, dict):
                continue
            from_path = str(exp.get('from_path') or '').strip()
            to_path_raw = str(exp.get('to_path') or '').strip()
            if not from_path or not to_path_raw:
                continue
            dest = to_path_raw.removeprefix('vars.')
            val = _extract_from_path(resp, resp_json, norm_headers, from_path)
            set_in(flat_vars, dest, val, forbid_overwrite=True)

    return flat_vars


def _make_error_context(message: str) -> StepContext:
    outputs: dict[str, Any] = {
        'webhook': {
            'method': None,
            'url': None,
            'status': None,
            'headers': {},
            'json': None,
            'text': None,
        }
    }
    return StepContext(
        step_type='Webhook',
        step_status='failed',
        error=message,
        outputs=outputs,
    )


def _safe_int(v: Any, *, default: int) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
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
    with contextlib.suppress(Exception):
        for k, v in dict(headers).items():
            out[str(k).lower().replace('-', '_')] = v
    return out


def _extract_from_path(
    resp: requests.Response,
    resp_json: Any | None,
    norm_headers: dict[str, Any],
    from_path: str,
) -> Any:
    value: Any = None
    if from_path == 'status':
        value = resp.status_code
    elif from_path == 'text':
        value = resp.text
    elif from_path == 'json':
        value = resp_json
    elif from_path.startswith('json.') and resp_json is not None:
        value = _traverse(resp_json, from_path.split('.')[1:])
    elif from_path == 'headers':
        value = dict(resp.headers)
    elif from_path.startswith('headers.'):
        value = _traverse(norm_headers, from_path.split('.')[1:])
    return value


def _traverse(root: Any, parts: list[str]) -> Any:
    cur = root
    for p in parts:
        if isinstance(cur, dict):
            cur = cur.get(p)
        elif isinstance(cur, list):
            try:
                idx = int(p)
            except (TypeError, ValueError):
                return None
            if 0 <= idx < len(cur):
                cur = cur[idx]
            else:
                return None
        else:
            return None
    return cur
