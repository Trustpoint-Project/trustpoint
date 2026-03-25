"""Execute compiled Workflow 2 IR one step at a time."""
from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from .adapters import (
    DjangoEmailAdapter,
    EmailAdapter,
    RequestsWebhookAdapter,
    WebhookAdapter,
    WebhookResponse,
)
from .context import RuntimeContext
from .errors import StepExecutionError
from .eval import eval_condition, eval_expr, render_template
from .types import ExecutionResult, RunStatus, StepRun

OnStepRun = Callable[[StepRun], None]

_TERMINAL_RUN_STATUSES = {'failed', 'awaiting', 'rejected'}
_END_TARGETS = {'$end', '$reject'}


class WorkflowExecutor:
    """Deterministic IR executor.

    Important:
      - Approval is DB-driven, NOT blocking in executor.run()
      - The approval step returns status="awaiting"
    """

    def __init__(
        self,
        *,
        email: EmailAdapter | None = None,
        webhook: WebhookAdapter | None = None,
        on_step_run: OnStepRun | None = None,
        max_steps: int = 200,
    ) -> None:
        """Initialize the executor with adapters and an optional hook."""
        self.email = email or DjangoEmailAdapter()
        self.webhook = webhook or RequestsWebhookAdapter()
        self.on_step_run = on_step_run
        self.max_steps = max_steps

    def execute_single_step(
        self,
        *,
        ir: dict[str, Any],
        step_id: str,
        run_index: int,
        ctx: RuntimeContext,
        transitions: Any,
    ) -> StepRun:
        """Execute one compiled step and return its step-run record."""
        wf = ir.get('workflow') or {}
        steps: dict[str, Any] = wf.get('steps') or {}
        if step_id not in steps:
            raise StepExecutionError(step_id, 'Missing step definition')

        step = steps.get(step_id)
        assert isinstance(step, dict)

        step_type = str(step.get('type') or '')
        params = step.get('params') or {}

        return self._execute_step(
            run_index=run_index,
            step_id=step_id,
            step_type=step_type,
            params=params,
            transitions=transitions,
            ctx=ctx,
        )

    def run(
        self,
        ir: dict[str, Any],
        *,
        event: dict[str, Any],
        vars_json: dict[str, Any] | None = None,
        **legacy_kwargs: Any,
    ) -> ExecutionResult:
        """Run a workflow IR document until it finishes or blocks."""
        if 'vars' in legacy_kwargs and vars_json is None:
            vars_json = legacy_kwargs.pop('vars')
        if legacy_kwargs:
            unexpected = ', '.join(sorted(legacy_kwargs))
            raise TypeError(f'Unexpected keyword arguments: {unexpected}')

        wf = ir.get('workflow') or {}
        start = wf.get('start')
        steps: dict[str, Any] = wf.get('steps') or {}
        transitions: dict[str, Any] = wf.get('transitions') or {}

        if not isinstance(start, str) or start not in steps:
            raise StepExecutionError('<engine>', 'Invalid start step')
        if not isinstance(steps, dict) or not isinstance(transitions, dict):
            raise StepExecutionError('<engine>', 'Invalid IR workflow structure')

        ctx = RuntimeContext(event=event, vars=dict(vars_json or {}))
        runs: list[StepRun] = []

        step_id: str | None = start
        end_step: str | None = None
        status: RunStatus = 'ok'

        for run_index in range(1, self.max_steps + 1):
            if step_id is None:
                break

            try:
                run = self.execute_single_step(
                    ir=ir,
                    step_id=step_id,
                    run_index=run_index,
                    ctx=ctx,
                    transitions=transitions.get(step_id),
                )
            except StepExecutionError as e:
                run = StepRun(
                    run_index=run_index,
                    step_id=step_id,
                    step_type=str((steps.get(step_id) or {}).get('type') or ''),
                    status='failed',
                    outcome=None,
                    next_step=None,
                    vars_delta={},
                    output=None,
                    error=e.message,
                    created_at=_now(),
                )
                runs.append(run)
                self._emit(run)
                status = 'failed'
                end_step = step_id
                break

            runs.append(run)
            self._emit(run)

            if run.status in _TERMINAL_RUN_STATUSES:
                status = run.status
                end_step = step_id
                break

            if run.next_step is None:
                status = 'succeeded'
                end_step = step_id
                break

            step_id = run.next_step

        else:
            status = 'failed'
            end_step = step_id

        return ExecutionResult(
            status=status,
            start_step=start,
            end_step=end_step,
            vars=ctx.vars,
            runs=runs,
        )

    def _execute_step(
        self,
        *,
        run_index: int,
        step_id: str,
        step_type: str,
        params: dict[str, Any],
        transitions: Any,
        ctx: RuntimeContext,
    ) -> StepRun:
        vars_before = dict(ctx.vars)
        output: dict[str, Any] | None = None
        outcome: str | None = None

        if step_type == 'set':
            self._step_set(step_id, params, ctx)
        elif step_type == 'compute':
            self._step_compute(step_id, params, ctx)
        elif step_type == 'logic':
            outcome = self._step_logic(step_id, params, ctx)
        elif step_type == 'email':
            output = self._step_email(step_id, params, ctx)
        elif step_type == 'webhook':
            output = self._step_webhook(step_id, params, ctx)
        elif step_type == 'approval':
            return StepRun(
                run_index=run_index,
                step_id=step_id,
                step_type=step_type,
                status='awaiting',
                outcome=None,
                next_step=None,
                vars_delta=_delta(vars_before, ctx.vars),
                output={
                    'approved_outcome': params.get('approved_outcome'),
                    'rejected_outcome': params.get('rejected_outcome'),
                    'timeout_seconds': params.get('timeout_seconds'),
                },
                error=None,
                created_at=_now(),
            )
        else:
            raise StepExecutionError(step_id, f'Unknown step type "{step_type}"')

        next_step = self._choose_next(step_id, outcome, transitions)

        # $reject means "end rejected" without a step
        if next_step == '$reject':
            return StepRun(
                run_index=run_index,
                step_id=step_id,
                step_type=step_type,
                status='rejected',
                outcome=outcome,
                next_step=None,
                vars_delta=_delta(vars_before, ctx.vars),
                output=output,
                error=None,
                created_at=_now(),
            )

        return StepRun(
            run_index=run_index,
            step_id=step_id,
            step_type=step_type,
            status='ok',
            outcome=outcome,
            next_step=next_step,
            vars_delta=_delta(vars_before, ctx.vars),
            output=output,
            error=None,
            created_at=_now(),
        )

    def _step_set(self, step_id: str, params: dict[str, Any], ctx: RuntimeContext) -> None:
        vars_map = params.get('vars')
        if not isinstance(vars_map, dict):
            raise StepExecutionError(step_id, 'Invalid set.vars')
        rendered = render_template(vars_map, ctx)
        if not isinstance(rendered, dict):
            raise StepExecutionError(step_id, 'Invalid set.vars render')
        for k, v in rendered.items():
            ctx.vars[str(k)] = v

    def _step_compute(self, step_id: str, params: dict[str, Any], ctx: RuntimeContext) -> None:
        set_map = params.get('set')
        if not isinstance(set_map, dict) or not set_map:
            raise StepExecutionError(step_id, 'Invalid compute.set')

        for target, spec in set_map.items():
            if not (isinstance(target, str) and target.startswith('vars.')):
                raise StepExecutionError(step_id, 'compute target must be vars.*')
            if not isinstance(spec, dict) or spec.get('kind') != 'expr':
                raise StepExecutionError(step_id, 'compute value must be expr')

            val = eval_expr(spec.get('expr'), ctx)

            name = target.split('.', 1)[1]
            if not name:
                raise StepExecutionError(step_id, 'compute target must be vars.<name>')
            ctx.vars[name] = val

    def _step_logic(self, step_id: str, params: dict[str, Any], ctx: RuntimeContext) -> str:
        cases = params.get('cases')
        default = params.get('default')
        if not isinstance(cases, list) or not isinstance(default, str) or not default:
            raise StepExecutionError(step_id, 'Invalid logic params')

        for c in cases:
            if not isinstance(c, dict):
                continue
            when_ir = c.get('when')
            out = c.get('outcome')
            if not isinstance(out, str) or not out:
                continue
            if eval_condition(when_ir, ctx):
                return out

        return default

    def _step_email(self, step_id: str, params: dict[str, Any], ctx: RuntimeContext) -> dict[str, Any]:
        to = params.get('to') or []
        cc = params.get('cc') or []
        bcc = params.get('bcc') or []
        subject = render_template(params.get('subject'), ctx)
        body = render_template(params.get('body'), ctx)

        if not (isinstance(to, list) and all(isinstance(x, str) for x in to)):
            raise StepExecutionError(step_id, 'Invalid email.to')
        if not (isinstance(cc, list) and all(isinstance(x, str) for x in cc)):
            raise StepExecutionError(step_id, 'Invalid email.cc')
        if not (isinstance(bcc, list) and all(isinstance(x, str) for x in bcc)):
            raise StepExecutionError(step_id, 'Invalid email.bcc')
        if not isinstance(subject, str) or not isinstance(body, str):
            raise StepExecutionError(step_id, 'Invalid email template rendering')

        self.email.send(to=to, cc=cc, bcc=bcc, subject=subject, body=body)
        return {'sent': True, 'to': to}

    def _step_webhook(self, step_id: str, params: dict[str, Any], ctx: RuntimeContext) -> dict[str, Any]:
        method = params.get('method')
        url = render_template(params.get('url'), ctx)
        headers = render_template(params.get('headers', {}), ctx)
        body = render_template(params.get('body'), ctx)
        timeout_seconds = params.get('timeout_seconds', 10)
        capture = params.get('capture', [])

        if not isinstance(method, str) or not method:
            raise StepExecutionError(step_id, 'Invalid webhook.method')
        if not isinstance(url, str) or not url:
            raise StepExecutionError(step_id, 'Invalid webhook.url')
        if not isinstance(headers, dict):
            raise StepExecutionError(step_id, 'Invalid webhook.headers')
        if not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
            raise StepExecutionError(step_id, 'Invalid webhook.timeout_seconds')
        if capture is None:
            capture = []
        if not isinstance(capture, list):
            raise StepExecutionError(step_id, 'Invalid webhook.capture (expected list)')

        resp: WebhookResponse = self.webhook.request(
            method=method,
            url=url,
            headers={str(k): str(v) for k, v in headers.items()},
            body=body,
            timeout_seconds=timeout_seconds,
        )

        def _get_from_body(path: list[str]) -> Any:
            cur = resp.body
            for seg in path:
                if isinstance(cur, dict) and seg in cur:
                    cur = cur[seg]
                else:
                    return None
            return cur

        def _get_from_headers(name: str) -> Any:
            if not isinstance(resp.headers, dict):
                return None
            # case-insensitive lookup
            lower = {str(k).lower(): v for k, v in resp.headers.items()}
            return lower.get(name.lower())

        for rule in capture:
            if not isinstance(rule, dict):
                continue
            target = rule.get('target')
            source = rule.get('source')

            if not (
                isinstance(target, list)
                and len(target) == 2
                and target[0] == 'vars'
                and isinstance(target[1], str)
                and target[1]
            ):
                continue
            var_name = target[1]

            if not (isinstance(source, list) and len(source) >= 1 and isinstance(source[0], str)):
                continue

            src0 = source[0]

            if src0 == 'status_code':
                ctx.vars[var_name] = resp.status_code
            elif src0 == 'body':
                if len(source) == 1:
                    ctx.vars[var_name] = resp.body
                else:
                    ctx.vars[var_name] = _get_from_body([str(x) for x in source[1:]])
            elif src0 == 'headers':
                if len(source) == 1:
                    ctx.vars[var_name] = resp.headers
                else:
                    # we compile headers.<name> as ["headers", "<name>"]
                    ctx.vars[var_name] = _get_from_headers(str(source[1]))
            else:
                # unknown capture source => ignore (shouldn't happen if compiler validated)
                continue

        return {'status_code': resp.status_code}

    def _choose_next(self, step_id: str, outcome: str | None, transitions: Any) -> str | None:
        if transitions is None:
            if outcome is None:
                return None
            raise StepExecutionError(step_id, f'No route for outcome "{outcome}"')

        if not isinstance(transitions, dict) or 'kind' not in transitions:
            raise StepExecutionError(step_id, 'Invalid transitions format')

        kind = transitions.get('kind')

        def _normalize_to(to: str) -> str | None:
            if to == '$end':
                return None
            if to == '$reject':
                return '$reject'
            return to

        if kind == 'linear':
            nxt = transitions.get('to')
            if not isinstance(nxt, str):
                raise StepExecutionError(step_id, 'Invalid linear transition')
            return _normalize_to(nxt)

        if kind == 'by_outcome':
            if outcome is None:
                raise StepExecutionError(step_id, 'Missing outcome for outcome transition')
            m = transitions.get('map')
            if not isinstance(m, dict):
                raise StepExecutionError(step_id, 'Invalid outcome map')
            nxt = m.get(outcome)
            if not isinstance(nxt, str):
                raise StepExecutionError(step_id, f'No route for outcome "{outcome}"')
            return _normalize_to(nxt)

        raise StepExecutionError(step_id, 'Unknown transition kind')

    def _emit(self, run: StepRun) -> None:
        if self.on_step_run:
            self.on_step_run(run)


def _delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    delta: dict[str, Any] = {}
    for k, v in after.items():
        if k not in before or before[k] != v:
            delta[k] = v
    return delta


def _now() -> datetime:
    return datetime.now(UTC)
