"""Webhook step executor."""

from __future__ import annotations

import contextlib
import ipaddress
import json as _json
import logging
import re
import socket
from typing import Any
from urllib.parse import quote, urlparse

import requests

from workflows.models import State, WorkflowInstance
from workflows.services.context import build_context, set_in
from workflows.services.executors.factory import AbstractStepExecutor
from workflows.services.types import ExecutorResult

_CTX_PLACEHOLDER_RE = re.compile(r'\{\{\s*ctx\.([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*)\s*\}\}')

def _lookup_ctx_path(ctx: dict[str, Any], path: str) -> Any:
    cur: Any = ctx
    for part in path.split('.'):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur

def _render_ctx_placeholders(template: str, ctx: dict[str, Any]) -> str:
    def repl(m: re.Match[str]) -> str:
        path = m.group(1)
        val = _lookup_ctx_path(ctx, path)
        if val is None:
            return ''
        return quote(str(val))

    return _CTX_PLACEHOLDER_RE.sub(repl, template)

def _is_safe_url(url: str) -> bool:
    """Return True if the URL is allowed for outbound webhook calls.

    This enforces:
    - scheme is http or https
    - a hostname is present
    - resolved IP is not private/loopback/link-local/multicast/reserved
    """
    parsed = urlparse(url)
    if parsed.scheme not in {'http', 'https'}:
        return False
    if not parsed.hostname:
        return False

    hostname = parsed.hostname
    try:
        addrinfos = socket.getaddrinfo(hostname, parsed.port or 0, type=socket.SOCK_STREAM)
    except OSError:
        # DNS resolution failed: treat as unsafe
        return False

    if not addrinfos:
        return False

    for family, _type, _proto, _canonname, sockaddr in addrinfos:
        ip_str = sockaddr[0] if family in (socket.AF_INET, socket.AF_INET6) else None
        if not ip_str:
            continue
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        # Reject private, loopback, link-local, multicast, and reserved addresses
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return False

    return True


def _validate_url(url: str) -> tuple[bool, str]:
    """Validate the rendered URL and return (ok, error_message)."""
    if not _is_safe_url(url):
        return False, 'Rendered URL is not allowed for webhook execution'
    return True, ''


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
        """Execute the webhook step.

        Args:
            instance: Workflow instance being executed.
            _signal: Optional signal (unused for webhook steps).

        Returns:
            ExecutorResult describing step outcome and exported vars.
        """
        params = _get_step_params(instance)

        (
            method,
            url_tpl,
            headers_raw,
            body_raw,
            timeout_secs,
            auth_cfg,
            result_to_raw,
            result_source,
            exports,
        ) = _extract_webhook_config(params)

        ctx: dict[str, Any] = build_context(instance)

        auth, bearer_token = _build_auth(auth_cfg)

        ok, url, err_msg = _render_url(url_tpl, ctx)
        if not ok:
            return ExecutorResult(
                status=State.FAILED,
                context=_make_error_context(err_msg),
            )

        headers = _build_headers(headers_raw, ctx, bearer_token)

        ok, data_kwargs, body_err = _build_body(body_raw, ctx)
        if not ok:
            return ExecutorResult(
                status=State.FAILED,
                context=_make_error_context(body_err),
            )

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
        flat_vars = _build_flat_vars(resp, resp_json, result_to_raw, result_source, exports)

        return ExecutorResult(
            status=State.PASSED,
            context=step_ctx,
            vars=(flat_vars or None),
        )


# ---------------------------- helpers ----------------------------


def _get_step_params(instance: WorkflowInstance) -> dict[str, Any]:
    """Return the params dict for the current step, or raise if not found."""
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
    result_to_raw = str(params.get('result_to') or '').strip()
    result_source = str(params.get('result_source') or 'auto').strip().lower()
    exports = list(params.get('exports') or [])
    return (
        method,
        url_tpl,
        headers_raw,
        body_raw,
        timeout_secs,
        auth_cfg,
        result_to_raw,
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


def _render_url(url_tpl: str, ctx: dict[str, Any]) -> tuple[bool, str, str]:
    try:
        url = _render_ctx_placeholders(url_tpl, ctx)
    except Exception as exc:
        logger.exception('Webhook: URL render failed')
        return False, '', f'URL render error: {exc!s}'

    ok, validation_error = _validate_url(url)
    if not ok:
        logger.warning('Webhook: URL validation failed for rendered URL %r: %s', url, validation_error)
        return False, '', validation_error

    return True, url, ''


def _build_headers(
    headers_raw: dict[str, Any],
    ctx: dict[str, Any],
    bearer_token: str | None,
) -> dict[str, str]:
    headers: dict[str, str] = {}
    for k, v in headers_raw.items():
        sval = str(v)
        with contextlib.suppress(Exception):
            sval = _render_ctx_placeholders(sval, ctx)
        headers[str(k)] = sval

    if bearer_token:
        headers.setdefault('Authorization', f'Bearer {bearer_token}')

    return headers

def _build_body(body_raw: Any, ctx: dict[str, Any]) -> tuple[bool, dict[str, Any], str]:
    data_kwargs: dict[str, Any] = {}

    if isinstance(body_raw, str) and body_raw.strip():
        try:
            rendered = _render_ctx_placeholders(body_raw, ctx)
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
    """Perform HTTP request with comprehensive SSRF protection.
    
    The URL has already been validated in _render_url(), but we perform
    a final validation here as a defense-in-depth measure to ensure
    no malicious URLs can reach the HTTP request.
    """
    headers = options.get('headers') or {}
    timeout_secs = options.get('timeout_secs') or 0
    auth = options.get('auth')
    data_kwargs = options.get('data_kwargs') or {}

    # Defense-in-depth: Final URL validation before making the request
    ok, validation_error = _validate_url(url)
    if not ok:
        logger.error('Webhook: final URL validation failed for %s: %s', url, validation_error)
        return None, None, f'URL validation error: {validation_error}'

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


def _build_step_context(
    method: str,
    url: str,
    resp: requests.Response,
    resp_json: Any | None,
) -> dict[str, Any]:
    return {
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


def _build_flat_vars(
    resp: requests.Response,
    resp_json: Any | None,
    result_to_raw: str,
    result_source: str,
    exports: list[Any],
) -> dict[str, Any]:
    flat_vars: dict[str, Any] = {}

    # Whole-result capture
    if result_to_raw:
        dest = result_to_raw.removeprefix('vars.')
        if dest:
            val = _select_source_value(resp, resp_json, result_source)
            with contextlib.suppress(Exception):
                set_in(flat_vars, dest, val, forbid_overwrite=True)

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
            dest = to_path_raw.removeprefix('vars.')
            with contextlib.suppress(Exception):
                val = _extract_from_path(resp, resp_json, norm_headers, from_path)
                set_in(flat_vars, dest, val, forbid_overwrite=True)

    return flat_vars


def _make_error_context(message: str) -> dict[str, Any]:
    return {
        'type': 'Webhook',
        'status': 'failed',
        'error': message,
        'outputs': {},
    }


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
