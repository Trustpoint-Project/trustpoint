# workflows2/compiler/compiler.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from workflows2.compiler.step_types import StepTypes
from workflows2.events.registry import get_event_registry

from .conditions import compile_condition
from .errors import CompileError
from .hashing import sha256_json, sha256_text
from .lint import SchemaLinter
from .templates import compile_template, compile_templates_deep
from .yaml_loader import load_yaml_text

HttpMethod = Literal['GET', 'POST', 'PUT', 'PATCH', 'DELETE']

COMPUTE_OPERATORS: tuple[str, ...] = (
    'add',
    'sub',
    'mul',
    'div',
    'min',
    'max',
    'round',
    'int',
    'float',
)

_ALLOWED_COMPUTE_OPS: set[str] = set(COMPUTE_OPERATORS)

_END_TARGETS: set[str] = {'$end', '$reject'}


@dataclass(frozen=True)
class TriggerIR:
    on: str
    sources: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            'on': self.on,
            'sources': self.sources,
        }


@dataclass(frozen=True)
class CompileMeta:
    compiler_version: str
    source_hash: str
    ir_hash: str


class WorkflowCompiler:
    """YAML → IR compiler for TrustPoint workflow v2."""

    SUPPORTED_SCHEMA = 'trustpoint.workflow.v2'
    IR_VERSION = 'v2'

    OUTCOME_TYPES: set[str] = {StepTypes.LOGIC, StepTypes.APPROVAL}

    def __init__(self, *, compiler_version: str = 'dev') -> None:
        self.compiler_version = compiler_version

    def compile(self, yaml_text: str) -> dict[str, Any]:
        src = load_yaml_text(yaml_text)
        SchemaLinter().lint(src)
        self._validate_top_level(src)

        trigger_ir = self._compile_trigger(src['trigger'], path='trigger')

        apply_raw = src.get('apply', []) or []
        if not isinstance(apply_raw, list):
            raise CompileError('"apply" must be a list', path='apply')
        apply_ir = [compile_condition(c, path=f'apply[{i}]') for i, c in enumerate(apply_raw)]

        wf_raw = src['workflow']
        start_id, steps_raw, flow_raw = self._extract_workflow_parts(wf_raw)

        steps_ir = self._compile_steps(steps_raw)
        self._validate_steps_allowed_for_trigger(trigger_ir, steps_ir)

        if start_id not in steps_ir:
            raise CompileError('workflow.start must reference an existing step id', path='workflow.start')

        transitions_ir = self._compile_flow(flow_raw, steps_ir)
        self._validate_flow_completeness(steps_ir, transitions_ir)

        ir: dict[str, Any] = {
            'ir_version': self.IR_VERSION,
            'name': src['name'],
            'enabled': bool(src.get('enabled', True)),
            'trigger': trigger_ir.to_dict(),
            'apply': apply_ir,
            'workflow': {
                'start': start_id,
                'steps': steps_ir,
                'transitions': transitions_ir,
            },
        }

        meta = self._build_meta(yaml_text, ir)
        ir['meta'] = {
            'compiler_version': meta.compiler_version,
            'source_hash': meta.source_hash,
            'ir_hash': meta.ir_hash,
        }
        return ir

    @classmethod
    def _validate_top_level(cls, src: dict[str, Any]) -> None:
        schema = src.get('schema')
        if schema != cls.SUPPORTED_SCHEMA:
            raise CompileError(
                f'Unsupported or missing "schema" (expected {cls.SUPPORTED_SCHEMA})',
                path='schema',
            )

        name = src.get('name')
        if not isinstance(name, str) or not name.strip():
            raise CompileError('"name" must be a non-empty string', path='name')

        trigger = src.get('trigger')
        if not isinstance(trigger, dict):
            raise CompileError('"trigger" must be a mapping', path='trigger')

        workflow = src.get('workflow')
        if not isinstance(workflow, dict):
            raise CompileError('"workflow" must be a mapping', path='workflow')

    @staticmethod
    def _extract_workflow_parts(wf_raw: dict[str, Any]) -> tuple[str, dict[str, Any], list[Any]]:
        start_id = wf_raw.get('start')
        if not isinstance(start_id, str) or not start_id.strip():
            raise CompileError('"workflow.start" must be a non-empty string', path='workflow.start')
        start_id = start_id.strip()

        steps_raw = wf_raw.get('steps')
        if not isinstance(steps_raw, dict) or not steps_raw:
            raise CompileError('"workflow.steps" must be a non-empty object', path='workflow.steps')

        flow_raw = wf_raw.get('flow', [])
        if flow_raw is None:
            flow_raw = []
        if not isinstance(flow_raw, list):
            raise CompileError('"workflow.flow" must be a list', path='workflow.flow')

        if len(steps_raw) > 1 and len(flow_raw) == 0:
            raise CompileError('"workflow.flow" must be a non-empty list', path='workflow.flow')

        return start_id, steps_raw, flow_raw

    @staticmethod
    def _compile_trigger(trigger: dict[str, Any], *, path: str) -> TriggerIR:
        on = trigger.get('on')
        if not isinstance(on, str) or not on.strip():
            keys = ', '.join(sorted(str(k) for k in trigger))
            raise CompileError(
                f'"trigger.on" must be a non-empty string (trigger keys: {keys})',
                path=f'{path}.on',
            )
        on = on.strip()

        reg = get_event_registry()
        if not reg.is_known(on):
            known = ', '.join(reg.all_keys())
            raise CompileError(
                f'Unknown trigger.on "{on}". Allowed: {known}',
                path=f'{path}.on',
            )

        sources = trigger.get('sources', {}) or {}
        if not isinstance(sources, dict):
            raise CompileError('"trigger.sources" must be a mapping', path=f'{path}.sources')

        trustpoint = bool(sources.get('trustpoint', False))
        ca_ids = sources.get('ca_ids', []) or []
        domain_ids = sources.get('domain_ids', []) or []
        device_ids = sources.get('device_ids', []) or []

        if not isinstance(ca_ids, list) or any(not isinstance(x, int) for x in ca_ids):
            raise CompileError('"trigger.sources.ca_ids" must be a list[int]', path=f'{path}.sources.ca_ids')
        if not isinstance(domain_ids, list) or any(not isinstance(x, int) for x in domain_ids):
            raise CompileError('"trigger.sources.domain_ids" must be a list[int]', path=f'{path}.sources.domain_ids')
        if not isinstance(device_ids, list) or any(not isinstance(x, str) for x in device_ids):
            raise CompileError('"trigger.sources.device_ids" must be a list[str]', path=f'{path}.sources.device_ids')

        if not trustpoint and not (ca_ids or domain_ids or device_ids):
            raise CompileError(
                'If trigger.sources.trustpoint is false, at least one of ca_ids/domain_ids/device_ids must be set',
                path=f'{path}.sources',
            )

        return TriggerIR(
            on=on,
            sources={
                'trustpoint': trustpoint,
                'ca_ids': ca_ids,
                'domain_ids': domain_ids,
                'device_ids': device_ids,
            },
        )

    def _validate_steps_allowed_for_trigger(self, trigger_ir: TriggerIR, steps_ir: dict[str, Any]) -> None:
        spec = get_event_registry().get(trigger_ir.on)
        if spec is None:
            return

        allowed = spec.allowed_step_types
        if allowed is None:
            return

        allowed_set = {str(x).strip() for x in allowed if str(x).strip()}

        for step_id, s in steps_ir.items():
            typ = s.get('type')
            if typ not in allowed_set:
                raise CompileError(
                    f'Step type "{typ}" is not allowed for trigger "{trigger_ir.on}"',
                    path=f'workflow.steps.{step_id}.type',
                )

    def _compile_steps(self, steps: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}

        for step_id, step in steps.items():
            if not isinstance(step_id, str) or not step_id.strip():
                raise CompileError('Step id must be a non-empty string', path='workflow.steps')
            if not isinstance(step, dict):
                raise CompileError('Step must be a mapping', path=f'workflow.steps.{step_id}')

            typ = step.get('type')
            if not isinstance(typ, str) or not typ.strip():
                raise CompileError('Step "type" must be a non-empty string', path=f'workflow.steps.{step_id}.type')
            typ = typ.strip()

            if typ not in StepTypes.all():
                allowed = ', '.join(sorted(StepTypes.all()))
                raise CompileError(
                    f'Unknown step type "{typ}". Allowed: {allowed}',
                    path=f'workflow.steps.{step_id}.type',
                )

            title = step.get('title')
            if title is not None and not isinstance(title, str):
                raise CompileError('"title" must be a string', path=f'workflow.steps.{step_id}.title')

            params = self._compile_step_params(step_id, typ, step)
            produces, outcomes = self._step_outcomes(typ, params)

            out[step_id] = {
                'id': step_id,
                'type': typ,
                'title': title,
                'params': params,
                'produces_outcome': produces,
                'outcomes': outcomes,
            }

        return out

    def _compile_step_params(self, step_id: str, typ: str, step: dict[str, Any]) -> dict[str, Any]:
        base = f'workflow.steps.{step_id}'
        if typ == StepTypes.EMAIL:
            return self._compile_email_params(step, base)
        if typ == StepTypes.WEBHOOK:
            return self._compile_webhook_params(step, base)
        if typ == StepTypes.LOGIC:
            return self._compile_logic_params(step, base)
        if typ == StepTypes.SET:
            return self._compile_set_params(step, base)
        if typ == StepTypes.COMPUTE:
            return self._compile_compute_params(step, base)
        if typ == StepTypes.APPROVAL:
            return self._compile_approval_params(step, base)

        raise CompileError(f'Unknown step type "{typ}"', path=f'{base}.type')

    @staticmethod
    def _compile_email_params(step: dict[str, Any], base: str) -> dict[str, Any]:
        to = step.get('to')
        if not isinstance(to, list) or not to or any(not isinstance(x, str) for x in to):
            raise CompileError('"email.to" must be a non-empty list[str]', path=f'{base}.to')

        cc = step.get('cc', []) or []
        bcc = step.get('bcc', []) or []
        if not isinstance(cc, list) or any(not isinstance(x, str) for x in cc):
            raise CompileError('"email.cc" must be a list[str]', path=f'{base}.cc')
        if not isinstance(bcc, list) or any(not isinstance(x, str) for x in bcc):
            raise CompileError('"email.bcc" must be a list[str]', path=f'{base}.bcc')

        subject_raw = step.get('subject')
        body_raw = step.get('body')
        if not isinstance(subject_raw, str):
            raise CompileError('"email.subject" must be a string', path=f'{base}.subject')
        if not isinstance(body_raw, str):
            raise CompileError('"email.body" must be a string', path=f'{base}.body')

        return {
            'to': to,
            'cc': cc,
            'bcc': bcc,
            'subject': compile_template(subject_raw, path=f'{base}.subject'),
            'body': compile_template(body_raw, path=f'{base}.body'),
        }

    @staticmethod
    def _compile_webhook_params(step: dict[str, Any], base: str) -> dict[str, Any]:
        method = step.get('method')
        if method not in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE'):
            raise CompileError('"webhook.method" must be one of GET/POST/PUT/PATCH/DELETE', path=f'{base}.method')

        url = step.get('url')
        if not isinstance(url, str) or not url.strip():
            raise CompileError('"webhook.url" must be a non-empty string', path=f'{base}.url')

        headers = step.get('headers', {}) or {}
        if not isinstance(headers, dict) or any(not isinstance(k, str) for k in headers.keys()):
            raise CompileError('"webhook.headers" must be a mapping with string keys', path=f'{base}.headers')
        headers_ir = compile_templates_deep(headers, path=f'{base}.headers')

        body = step.get('body')
        if body is None:
            body_ir = None
        elif isinstance(body, (str, list, dict)):
            body_ir = compile_templates_deep(body, path=f'{base}.body')
        else:
            raise CompileError('"webhook.body" must be string/list/mapping/null', path=f'{base}.body')

        timeout_seconds = step.get('timeout_seconds', 10)
        if not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
            raise CompileError('"timeout_seconds" must be a positive int', path=f'{base}.timeout_seconds')

        capture = step.get('capture', {}) or {}
        if not isinstance(capture, dict):
            raise CompileError('"webhook.capture" must be a mapping', path=f'{base}.capture')

        LEGACY_KEYS = {'status_code', 'body', 'headers'}
        if any(str(k) in LEGACY_KEYS for k in capture.keys()):
            raise CompileError(
                'Legacy webhook.capture format is not supported anymore. '
                'Use "vars.<name>: <source>" (e.g. vars.http_status: status_code).',
                path=f'{base}.capture',
            )

        def _parse_vars_target(key: Any, *, path: str) -> list[str]:
            if not isinstance(key, str) or not key.startswith('vars.'):
                raise CompileError('Capture key must be "vars.<name>"', path=path)
            parts = key.split('.')
            if len(parts) != 2 or not parts[1]:
                raise CompileError('Capture key must be "vars.<name>" (single name)', path=path)
            return ['vars', parts[1]]

        def _parse_source(val: Any, *, path: str) -> list[str]:
            if not isinstance(val, str) or not val.strip():
                raise CompileError('Capture value must be a non-empty string', path=path)
            s = val.strip()

            if s in {'status_code', 'body', 'headers'}:
                return [s]

            if s.startswith('headers.'):
                rest = s[len('headers.') :].strip()
                if not rest:
                    raise CompileError('Capture source must be "headers.<name>"', path=path)
                return ['headers', rest]

            if s.startswith('body.'):
                rest = s[len('body.') :].strip()
                if not rest:
                    raise CompileError('Capture source must be "body.<path>"', path=path)
                segs = [p for p in rest.split('.') if p]
                return ['body', *segs]

            raise CompileError(
                'Unknown capture source. Allowed: status_code | body | headers | headers.<name> | body.<path>',
                path=path,
            )

        capture_rules: list[dict[str, Any]] = []
        for k, v in capture.items():
            target = _parse_vars_target(k, path=f'{base}.capture.{k}')
            source = _parse_source(v, path=f'{base}.capture.{k}')
            capture_rules.append({'target': target, 'source': source})

        return {
            'method': method,
            'url': compile_template(url, path=f'{base}.url'),
            'headers': headers_ir,
            'body': body_ir,
            'timeout_seconds': timeout_seconds,
            'capture': capture_rules,
        }

    @staticmethod
    def _compile_logic_params(step: dict[str, Any], base: str) -> dict[str, Any]:
        cases = step.get('cases')
        default = step.get('default')

        if not isinstance(cases, list) or not cases:
            raise CompileError('"logic.cases" must be a non-empty list', path=f'{base}.cases')
        if not isinstance(default, str) or not default.strip():
            raise CompileError('"logic.default" must be a non-empty string', path=f'{base}.default')

        cases_ir: list[dict[str, Any]] = []
        for i, c in enumerate(cases):
            if not isinstance(c, dict):
                raise CompileError('Each case must be a mapping', path=f'{base}.cases[{i}]')

            when = c.get('when')
            outcome = c.get('outcome')

            if when is None:
                raise CompileError('Case missing "when"', path=f'{base}.cases[{i}].when')
            if not isinstance(outcome, str) or not outcome.strip():
                raise CompileError('Case "outcome" must be a non-empty string', path=f'{base}.cases[{i}].outcome')

            cases_ir.append(
                {
                    'when': compile_condition(when, path=f'{base}.cases[{i}].when'),
                    'outcome': outcome.strip(),
                }
            )

        return {'cases': cases_ir, 'default': default.strip()}

    @staticmethod
    def _compile_set_params(step: dict[str, Any], base: str) -> dict[str, Any]:
        vars_map = step.get('vars')
        if not isinstance(vars_map, dict):
            raise CompileError('"set.vars" must be a mapping', path=f'{base}.vars')
        return {'vars': compile_templates_deep(vars_map, path=f'{base}.vars')}

    @staticmethod
    def _compile_compute_params(step: dict[str, Any], base: str) -> dict[str, Any]:
        from .expr import parse_required_expr_string
        from .templates import _expr_to_ir

        set_map = step.get('set')
        if not isinstance(set_map, dict) or not set_map:
            raise CompileError('"compute.set" must be a non-empty mapping', path=f'{base}.set')

        out: dict[str, Any] = {}
        for target, rhs in set_map.items():
            if not isinstance(target, str) or not target.startswith('vars.') or len(target.split('.')) < 2:
                raise CompileError('compute.set keys must be "vars.<name>"', path=f'{base}.set')

            if isinstance(rhs, str):
                ast = parse_required_expr_string(rhs, path=f'{base}.set.{target}')
                out[target] = {'kind': 'expr', 'expr': _expr_to_ir(ast)}
                continue

            if isinstance(rhs, dict):
                expr_ir = WorkflowCompiler._compile_compute_yaml_op(rhs, path=f'{base}.set.{target}')
                out[target] = {'kind': 'expr', 'expr': expr_ir}
                continue

            raise CompileError(
                'compute.set values must be either an expression string like "${add(...)}" or an op mapping like {add: [...]}',
                path=f'{base}.set.{target}',
            )

        return {'set': out}

    @staticmethod
    def _compile_compute_yaml_op(node: dict[str, Any], *, path: str) -> dict[str, Any]:
        if not isinstance(node, dict):
            raise CompileError('Compute op must be a mapping', path=path)

        if len(node) != 1:
            raise CompileError('Compute op must have exactly one operator key', path=path)

        op, args = next(iter(node.items()))

        if not isinstance(op, str) or not op:
            raise CompileError('Compute operator must be a non-empty string', path=path)

        if op not in _ALLOWED_COMPUTE_OPS:
            raise CompileError(f'Compute operator "{op}" is not allowed', path=f'{path}.{op}')

        if not isinstance(args, list) or not args:
            raise CompileError(f'Compute operator "{op}" requires a non-empty list of args', path=f'{path}.{op}')

        compiled_args = [
            WorkflowCompiler._compile_compute_value(a, path=f'{path}.{op}[{i}]')
            for i, a in enumerate(args)
        ]
        return {'kind': 'call', 'name': op, 'args': compiled_args}

    @staticmethod
    def _compile_compute_value(v: Any, *, path: str) -> dict[str, Any]:
        if isinstance(v, dict):
            return WorkflowCompiler._compile_compute_yaml_op(v, path=path)

        if isinstance(v, str):
            s = v.strip()
            if s.startswith('${') and s.endswith('}'):
                from .expr import parse_required_expr_string
                from .templates import _expr_to_ir

                ast = parse_required_expr_string(s, path=path)
                return _expr_to_ir(ast)

            return {'kind': 'lit', 'value': v}

        if isinstance(v, (int, float, bool)) or v is None:
            return {'kind': 'lit', 'value': v}

        raise CompileError('Invalid compute value type', path=path)

    @staticmethod
    def _compile_approval_params(step: dict[str, Any], base: str) -> dict[str, Any]:
        a = step.get('approved_outcome')
        r = step.get('rejected_outcome')
        if not isinstance(a, str) or not a.strip():
            raise CompileError('"approval.approved_outcome" must be a non-empty string', path=f'{base}.approved_outcome')
        if not isinstance(r, str) or not r.strip():
            raise CompileError('"approval.rejected_outcome" must be a non-empty string', path=f'{base}.rejected_outcome')

        timeout_seconds = step.get('timeout_seconds')
        if timeout_seconds is not None:
            if not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
                raise CompileError('"approval.timeout_seconds" must be a positive int', path=f'{base}.timeout_seconds')

        out: dict[str, Any] = {
            'approved_outcome': a.strip(),
            'rejected_outcome': r.strip(),
        }
        if timeout_seconds is not None:
            out['timeout_seconds'] = timeout_seconds
        return out

    @classmethod
    def _step_outcomes(cls, typ: str, params: dict[str, Any]) -> tuple[bool, list[str]]:
        if typ == StepTypes.LOGIC:
            outs = [c['outcome'] for c in params['cases']] + [params['default']]
            uniq: list[str] = []
            seen: set[str] = set()
            for o in outs:
                if o not in seen:
                    seen.add(o)
                    uniq.append(o)
            return True, uniq

        if typ == StepTypes.APPROVAL:
            return True, [params['approved_outcome'], params['rejected_outcome']]

        return False, []

    @staticmethod
    def _compile_flow(flow: list[Any], steps_ir: dict[str, Any]) -> dict[str, Any]:
        transitions: dict[str, Any] = {}

        for i, t in enumerate(flow):
            if not isinstance(t, dict):
                raise CompileError('Each flow item must be a mapping', path=f'workflow.flow[{i}]')

            frm = t.get('from')
            to = t.get('to')
            on = t.get('on', None)

            if not isinstance(frm, str) or frm not in steps_ir:
                raise CompileError('"from" must reference an existing step id', path=f'workflow.flow[{i}].from')

            if not isinstance(to, str) or not to.strip():
                raise CompileError('"to" must be a non-empty string', path=f'workflow.flow[{i}].to')
            to = to.strip()

            if to not in steps_ir and to not in _END_TARGETS:
                raise CompileError('"to" must reference an existing step id or be $end/$reject', path=f'workflow.flow[{i}].to')

            if on is None:
                if frm in transitions:
                    raise CompileError('Duplicate transition for step', path=f'workflow.flow[{i}].from')
                transitions[frm] = {'kind': 'linear', 'to': to}
                continue

            if not isinstance(on, str) or not on.strip():
                raise CompileError('"on" must be a non-empty string', path=f'workflow.flow[{i}].on')

            existing = transitions.get(frm)
            if existing is None:
                transitions[frm] = {'kind': 'by_outcome', 'map': {on.strip(): to}}
                continue

            if existing.get('kind') != 'by_outcome':
                raise CompileError(
                    'Cannot mix linear and outcome transitions for the same step',
                    path=f'workflow.flow[{i}].from',
                )

            m = existing['map']
            if on.strip() in m:
                raise CompileError('Duplicate (from,on) transition', path=f'workflow.flow[{i}].on')
            m[on.strip()] = to

        return transitions

    def _validate_flow_completeness(self, steps_ir: dict[str, Any], transitions: dict[str, Any]) -> None:
        for step_id, s in steps_ir.items():
            produces = bool(s['produces_outcome'])
            outs: list[str] = list(s['outcomes'])

            tr = transitions.get(step_id)

            if produces:
                if tr is None or tr.get('kind') != 'by_outcome':
                    raise CompileError(
                        'Outcome-producing step requires outcome transitions',
                        path=f'workflow.flow({step_id})',
                    )
                mapped = set(tr['map'].keys())
                missing = [o for o in outs if o not in mapped]
                if missing:
                    raise CompileError(
                        f'Missing flow mappings for outcomes: {missing}',
                        path=f'workflow.flow({step_id})',
                    )
            else:
                if tr is None:
                    continue
                if tr.get('kind') != 'linear':
                    raise CompileError(
                        'Non-outcome step requires a linear transition (or omit it to end)',
                        path=f'workflow.flow({step_id})',
                    )

    def _build_meta(self, yaml_text: str, ir: dict[str, Any]) -> CompileMeta:
        source_hash = sha256_text(yaml_text)
        ir_hash = sha256_json(ir)
        return CompileMeta(
            compiler_version=self.compiler_version,
            source_hash=source_hash,
            ir_hash=ir_hash,
        )


def compile_workflow_yaml(yaml_text: str, *, compiler_version: str = 'dev') -> dict[str, Any]:
    return WorkflowCompiler(compiler_version=compiler_version).compile(yaml_text)