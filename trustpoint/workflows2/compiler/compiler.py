"""Compile Workflow 2 YAML documents into normalized IR."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Literal, cast

from workflows2.compiler.step_types import StepTypes
from workflows2.events.registry import get_event_registry

from .conditions import compile_condition
from .errors import CompileError
from .expr import parse_required_expr_string
from .hashing import sha256_json, sha256_text
from .lint import SchemaLinter
from .templates import _expr_to_ir, compile_template, compile_templates_deep
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

VARS_PATH_MIN_PARTS = 2
MIN_CAPTURE_TARGET_PARTS = 2


@dataclass(frozen=True)
class TriggerIR:
    """Normalized trigger configuration stored in compiled IR."""

    on: str
    sources: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the trigger IR to a plain dictionary."""
        return {
            'on': self.on,
            'sources': self.sources,
        }


@dataclass(frozen=True)
class CompileMeta:
    """Hashes and provenance metadata attached to compiled IR."""

    compiler_version: str
    source_hash: str
    ir_hash: str


class WorkflowCompiler:
    """YAML → IR compiler for TrustPoint workflow v2."""

    SUPPORTED_SCHEMA = 'trustpoint.workflow.v2'
    IR_VERSION = 'v2'

    OUTCOME_TYPES: ClassVar[set[str]] = {StepTypes.LOGIC, StepTypes.APPROVAL}

    def __init__(self, *, compiler_version: str = 'dev') -> None:
        """Initialize the compiler with a version label for IR metadata."""
        self.compiler_version = compiler_version

    def compile(self, yaml_text: str) -> dict[str, Any]:
        """Compile one workflow YAML document into normalized IR."""
        src = load_yaml_text(yaml_text)
        SchemaLinter().lint(src)
        self._validate_top_level(src)

        trigger_ir = self._compile_trigger(src['trigger'], path='trigger')

        apply_raw = src.get('apply', []) or []
        if not isinstance(apply_raw, list):
            msg = '"apply" must be a list'
            raise CompileError(msg, path='apply')
        apply_ir = [compile_condition(c, path=f'apply[{i}]') for i, c in enumerate(apply_raw)]

        wf_raw = src['workflow']
        start_id, steps_raw, flow_raw = self._extract_workflow_parts(wf_raw)

        steps_ir = self._compile_steps(steps_raw)
        self._validate_steps_allowed_for_trigger(trigger_ir, steps_ir)

        if start_id not in steps_ir:
            msg = 'workflow.start must reference an existing step id'
            raise CompileError(msg, path='workflow.start')

        transitions_ir = self._compile_flow(flow_raw, steps_ir)
        self._validate_flow_completeness(steps_ir, transitions_ir)
        self._validate_flow_reachability(start_id, steps_ir, transitions_ir)
        self._validate_step_variable_references(start_id, steps_ir, transitions_ir)

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
            msg = f'Unsupported or missing "schema" (expected {cls.SUPPORTED_SCHEMA})'
            raise CompileError(
                msg,
                path='schema',
            )

        name = src.get('name')
        if not isinstance(name, str) or not name.strip():
            msg = '"name" must be a non-empty string'
            raise CompileError(msg, path='name')

        trigger = src.get('trigger')
        if not isinstance(trigger, dict):
            msg = '"trigger" must be a mapping'
            raise CompileError(msg, path='trigger')

        workflow = src.get('workflow')
        if not isinstance(workflow, dict):
            msg = '"workflow" must be a mapping'
            raise CompileError(msg, path='workflow')

    @staticmethod
    def _extract_workflow_parts(wf_raw: dict[str, Any]) -> tuple[str, dict[str, Any], list[Any]]:
        start_id = wf_raw.get('start')
        if not isinstance(start_id, str) or not start_id.strip():
            msg = '"workflow.start" must be a non-empty string'
            raise CompileError(msg, path='workflow.start')
        start_id = start_id.strip()

        steps_raw = wf_raw.get('steps')
        if not isinstance(steps_raw, dict) or not steps_raw:
            msg = '"workflow.steps" must be a non-empty object'
            raise CompileError(msg, path='workflow.steps')

        flow_raw = wf_raw.get('flow', [])
        if flow_raw is None:
            flow_raw = []
        if not isinstance(flow_raw, list):
            msg = '"workflow.flow" must be a list'
            raise CompileError(msg, path='workflow.flow')

        if len(steps_raw) > 1 and len(flow_raw) == 0:
            msg = '"workflow.flow" must be a non-empty list'
            raise CompileError(msg, path='workflow.flow')

        return start_id, steps_raw, flow_raw

    @staticmethod
    def _compile_trigger(trigger: dict[str, Any], *, path: str) -> TriggerIR:
        on = trigger.get('on')
        if not isinstance(on, str) or not on.strip():
            keys = ', '.join(sorted(str(k) for k in trigger))
            msg = f'"trigger.on" must be a non-empty string (trigger keys: {keys})'
            raise CompileError(
                msg,
                path=f'{path}.on',
            )
        on = on.strip()

        reg = get_event_registry()
        if not reg.is_known(on):
            known = ', '.join(reg.all_keys())
            msg = f'Unknown trigger.on "{on}". Allowed: {known}'
            raise CompileError(
                msg,
                path=f'{path}.on',
            )

        sources = trigger.get('sources', {}) or {}
        if not isinstance(sources, dict):
            msg = '"trigger.sources" must be a mapping'
            raise CompileError(msg, path=f'{path}.sources')

        trustpoint = bool(sources.get('trustpoint', False))
        ca_ids = sources.get('ca_ids', []) or []
        domain_ids = sources.get('domain_ids', []) or []
        device_ids = sources.get('device_ids', []) or []

        if not isinstance(ca_ids, list) or any(not isinstance(x, int) for x in ca_ids):
            msg = '"trigger.sources.ca_ids" must be a list[int]'
            raise CompileError(msg, path=f'{path}.sources.ca_ids')
        if not isinstance(domain_ids, list) or any(not isinstance(x, int) for x in domain_ids):
            msg = '"trigger.sources.domain_ids" must be a list[int]'
            raise CompileError(msg, path=f'{path}.sources.domain_ids')
        if not isinstance(device_ids, list) or any(not isinstance(x, str) for x in device_ids):
            msg = '"trigger.sources.device_ids" must be a list[str]'
            raise CompileError(msg, path=f'{path}.sources.device_ids')

        if not trustpoint and not (ca_ids or domain_ids or device_ids):
            msg = 'If trigger.sources.trustpoint is false, at least one of ca_ids/domain_ids/device_ids must be set'
            raise CompileError(
                msg,
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
                msg = f'Step type "{typ}" is not allowed for trigger "{trigger_ir.on}"'
                raise CompileError(
                    msg,
                    path=f'workflow.steps.{step_id}.type',
                )

    def _compile_steps(self, steps: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}

        for step_id, step in steps.items():
            if not isinstance(step_id, str) or not step_id.strip():
                msg = 'Step id must be a non-empty string'
                raise CompileError(msg, path='workflow.steps')
            if not isinstance(step, dict):
                msg = 'Step must be a mapping'
                raise CompileError(msg, path=f'workflow.steps.{step_id}')

            typ = step.get('type')
            if not isinstance(typ, str) or not typ.strip():
                msg = 'Step "type" must be a non-empty string'
                raise CompileError(msg, path=f'workflow.steps.{step_id}.type')
            typ = typ.strip()

            if typ not in StepTypes.all():
                allowed = ', '.join(sorted(StepTypes.all()))
                msg = f'Unknown step type "{typ}". Allowed: {allowed}'
                raise CompileError(
                    msg,
                    path=f'workflow.steps.{step_id}.type',
                )

            title = step.get('title')
            if title is not None and not isinstance(title, str):
                msg = '"title" must be a string'
                raise CompileError(msg, path=f'workflow.steps.{step_id}.title')

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

        msg = f'Unknown step type "{typ}"'
        raise CompileError(msg, path=f'{base}.type')

    @staticmethod
    def _compile_email_params(step: dict[str, Any], base: str) -> dict[str, Any]:
        to = step.get('to')
        if not isinstance(to, list) or not to or any(not isinstance(x, str) for x in to):
            msg = '"email.to" must be a non-empty list[str]'
            raise CompileError(msg, path=f'{base}.to')

        cc = step.get('cc', []) or []
        bcc = step.get('bcc', []) or []
        if not isinstance(cc, list) or any(not isinstance(x, str) for x in cc):
            msg = '"email.cc" must be a list[str]'
            raise CompileError(msg, path=f'{base}.cc')
        if not isinstance(bcc, list) or any(not isinstance(x, str) for x in bcc):
            msg = '"email.bcc" must be a list[str]'
            raise CompileError(msg, path=f'{base}.bcc')

        subject_raw = step.get('subject')
        body_raw = step.get('body')
        if not isinstance(subject_raw, str):
            msg = '"email.subject" must be a string'
            raise CompileError(msg, path=f'{base}.subject')
        if not isinstance(body_raw, str):
            msg = '"email.body" must be a string'
            raise CompileError(msg, path=f'{base}.body')

        return {
            'to': to,
            'cc': cc,
            'bcc': bcc,
            'subject': compile_template(subject_raw, path=f'{base}.subject'),
            'body': compile_template(body_raw, path=f'{base}.body'),
        }

    @staticmethod
    def _require_non_empty_string(value: Any, *, path: str, label: str) -> str:
        if not isinstance(value, str) or not value.strip():
            msg = f'{label} must be a non-empty string'
            raise CompileError(msg, path=path)
        return value.strip()

    @staticmethod
    def _require_positive_int(value: Any, *, path: str, label: str) -> int:
        if not isinstance(value, int) or value <= 0:
            msg = f'{label} must be a positive int'
            raise CompileError(msg, path=path)
        return value

    @staticmethod
    def _require_webhook_method(value: Any, *, path: str) -> HttpMethod:
        if value not in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE'):
            msg = '"webhook.method" must be one of GET/POST/PUT/PATCH/DELETE'
            raise CompileError(msg, path=path)
        return cast('HttpMethod', value)

    @staticmethod
    def _compile_webhook_headers(headers: Any, *, path: str) -> dict[str, Any]:
        if not isinstance(headers, dict) or any(not isinstance(k, str) for k in headers):
            msg = '"webhook.headers" must be a mapping with string keys'
            raise CompileError(msg, path=path)
        return cast('dict[str, Any]', compile_templates_deep(headers, path=path))

    @staticmethod
    def _compile_webhook_body(body: Any, *, path: str) -> Any:
        if body is None:
            return None
        if isinstance(body, (str, list, dict)):
            return compile_templates_deep(body, path=path)

        msg = '"webhook.body" must be string/list/mapping/null'
        raise CompileError(msg, path=path)

    @staticmethod
    def _parse_capture_target(key: Any, *, path: str) -> list[str]:
        if not isinstance(key, str) or not key.startswith('vars.'):
            msg = 'Capture key must be "vars.<name>"'
            raise CompileError(msg, path=path)

        parts = key.split('.')
        if len(parts) != MIN_CAPTURE_TARGET_PARTS or not parts[1]:
            msg = 'Capture key must be "vars.<name>" (single name)'
            raise CompileError(msg, path=path)

        return ['vars', parts[1]]

    @staticmethod
    def _parse_capture_source(value: Any, *, path: str) -> list[str]:
        if not isinstance(value, str) or not value.strip():
            msg = 'Capture value must be a non-empty string'
            raise CompileError(msg, path=path)

        source = value.strip()

        if source in {'status_code', 'body', 'headers'}:
            return [source]

        if source.startswith('headers.'):
            rest = source[len('headers.') :].strip()
            if not rest:
                msg = 'Capture source must be "headers.<name>"'
                raise CompileError(msg, path=path)
            return ['headers', rest]

        if source.startswith('body.'):
            rest = source[len('body.') :].strip()
            if not rest:
                msg = 'Capture source must be "body.<path>"'
                raise CompileError(msg, path=path)
            return ['body', *[part for part in rest.split('.') if part]]

        msg = 'Unknown capture source. Allowed: status_code | body | headers | headers.<name> | body.<path>'
        raise CompileError(msg, path=path)

    @staticmethod
    def _compile_webhook_capture(capture: Any, *, path: str) -> list[dict[str, Any]]:
        if not isinstance(capture, dict):
            msg = '"webhook.capture" must be a mapping'
            raise CompileError(msg, path=path)

        legacy_keys = {'status_code', 'body', 'headers'}
        if any(str(key) in legacy_keys for key in capture):
            msg = (
                'Legacy webhook.capture format is not supported anymore. '
                'Use "vars.<name>: <source>" (e.g. vars.http_status: status_code).'
            )
            raise CompileError(msg, path=path)

        rules: list[dict[str, Any]] = []
        for key, value in capture.items():
            item_path = f'{path}.{key}'
            target = WorkflowCompiler._parse_capture_target(key, path=item_path)
            source = WorkflowCompiler._parse_capture_source(value, path=item_path)
            rules.append({'target': target, 'source': source})

        return rules

    @staticmethod
    def _compile_webhook_params(step: dict[str, Any], base: str) -> dict[str, Any]:
        method = WorkflowCompiler._require_webhook_method(step.get('method'), path=f'{base}.method')
        url = WorkflowCompiler._require_non_empty_string(
            step.get('url'),
            path=f'{base}.url',
            label='"webhook.url"',
        )
        headers_ir = WorkflowCompiler._compile_webhook_headers(
            step.get('headers', {}) or {},
            path=f'{base}.headers',
        )
        body_ir = WorkflowCompiler._compile_webhook_body(
            step.get('body'),
            path=f'{base}.body',
        )
        timeout_seconds = WorkflowCompiler._require_positive_int(
            step.get('timeout_seconds', 10),
            path=f'{base}.timeout_seconds',
            label='"timeout_seconds"',
        )
        capture_rules = WorkflowCompiler._compile_webhook_capture(
            step.get('capture', {}) or {},
            path=f'{base}.capture',
        )

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
            msg = '"logic.cases" must be a non-empty list'
            raise CompileError(msg, path=f'{base}.cases')
        if not isinstance(default, str) or not default.strip():
            msg = '"logic.default" must be a non-empty string'
            raise CompileError(msg, path=f'{base}.default')

        cases_ir: list[dict[str, Any]] = []
        for i, c in enumerate(cases):
            if not isinstance(c, dict):
                msg = 'Each case must be a mapping'
                raise CompileError(msg, path=f'{base}.cases[{i}]')

            when = c.get('when')
            outcome = c.get('outcome')

            if when is None:
                msg = 'Case missing "when"'
                raise CompileError(msg, path=f'{base}.cases[{i}].when')
            if not isinstance(outcome, str) or not outcome.strip():
                msg = 'Case "outcome" must be a non-empty string'
                raise CompileError(msg, path=f'{base}.cases[{i}].outcome')

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
            msg = '"set.vars" must be a mapping'
            raise CompileError(msg, path=f'{base}.vars')

        compiled_map = compile_templates_deep(vars_map, path=f'{base}.vars')
        normalized: dict[str, Any] = {}

        for raw_key, compiled_value in compiled_map.items():
            if not isinstance(raw_key, str) or not raw_key.strip():
                msg = 'set.vars keys must be non-empty strings'
                raise CompileError(msg, path=f'{base}.vars')

            key = raw_key.strip()
            if key.startswith('vars.'):
                key = key.split('.', 1)[1].strip()

            if not key:
                msg = 'set.vars keys must be "vars.<name>" or "<name>"'
                raise CompileError(msg, path=f'{base}.vars.{raw_key}')

            if key in normalized:
                msg = f'Duplicate set.vars target "{key}"'
                raise CompileError(
                    msg,
                    path=f'{base}.vars.{raw_key}',
                )

            normalized[key] = compiled_value

        return {'vars': normalized}

    @staticmethod
    def _compile_compute_params(step: dict[str, Any], base: str) -> dict[str, Any]:
        set_map = step.get('set')
        if not isinstance(set_map, dict) or not set_map:
            msg = '"compute.set" must be a non-empty mapping'
            raise CompileError(msg, path=f'{base}.set')

        out: dict[str, Any] = {}
        for target, rhs in set_map.items():
            if not isinstance(target, str):
                msg = 'compute.set keys must be "vars.<path>"'
                raise CompileError(msg, path=f'{base}.set')

            parts = target.split('.')
            if (
                parts[0] != 'vars'
                or len(parts) < VARS_PATH_MIN_PARTS
                or any(not part.strip() for part in parts[1:])
            ):
                msg = 'compute.set keys must be "vars.<path>"'
                raise CompileError(msg, path=f'{base}.set')

            if isinstance(rhs, str):
                ast = parse_required_expr_string(rhs, path=f'{base}.set.{target}')
                out[target] = {'kind': 'expr', 'expr': _expr_to_ir(ast)}
                continue

            if isinstance(rhs, dict):
                expr_ir = WorkflowCompiler._compile_compute_yaml_op(rhs, path=f'{base}.set.{target}')
                out[target] = {'kind': 'expr', 'expr': expr_ir}
                continue

            msg = (
                'compute.set values must be either an expression string like '
                '"${add(...)}" or an op mapping like {add: [...]}'
            )
            raise CompileError(msg, path=f'{base}.set.{target}')

        return {'set': out}

    @staticmethod
    def _compile_compute_yaml_op(node: dict[str, Any], *, path: str) -> dict[str, Any]:
        if not isinstance(node, dict):
            msg = 'Compute op must be a mapping'
            raise CompileError(msg, path=path)

        if len(node) != 1:
            msg = 'Compute op must have exactly one operator key'
            raise CompileError(msg, path=path)

        op, args = next(iter(node.items()))

        if not isinstance(op, str) or not op:
            msg = 'Compute operator must be a non-empty string'
            raise CompileError(msg, path=path)

        if op not in _ALLOWED_COMPUTE_OPS:
            msg = f'Compute operator "{op}" is not allowed'
            raise CompileError(msg, path=f'{path}.{op}')

        if not isinstance(args, list) or not args:
            msg = f'Compute operator "{op}" requires a non-empty list of args'
            raise CompileError(msg, path=f'{path}.{op}')

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
                ast = parse_required_expr_string(s, path=path)
                return cast('dict[str, Any]', _expr_to_ir(ast))

            return {'kind': 'lit', 'value': v}

        if isinstance(v, (int, float, bool)) or v is None:
            return {'kind': 'lit', 'value': v}

        msg = 'Invalid compute value type'
        raise CompileError(msg, path=path)

    @staticmethod
    def _compile_approval_params(step: dict[str, Any], base: str) -> dict[str, Any]:
        a = step.get('approved_outcome')
        r = step.get('rejected_outcome')
        if not isinstance(a, str) or not a.strip():
            msg = '"approval.approved_outcome" must be a non-empty string'
            raise CompileError(msg, path=f'{base}.approved_outcome')
        if not isinstance(r, str) or not r.strip():
            msg = '"approval.rejected_outcome" must be a non-empty string'
            raise CompileError(msg, path=f'{base}.rejected_outcome')

        timeout_seconds = step.get('timeout_seconds')
        if timeout_seconds is not None and (not isinstance(timeout_seconds, int) or timeout_seconds <= 0):
            msg = '"approval.timeout_seconds" must be a positive int'
            raise CompileError(msg, path=f'{base}.timeout_seconds')

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
    def _parse_flow_item(item: Any, *, index: int, steps_ir: dict[str, Any]) -> tuple[str, str, str | None]:
        if not isinstance(item, dict):
            msg = 'Each flow item must be a mapping'
            raise CompileError(msg, path=f'workflow.flow[{index}]')

        frm = item.get('from')
        to = item.get('to')
        on = item.get('on')

        if not isinstance(frm, str) or frm not in steps_ir:
            msg = '"from" must reference an existing step id'
            raise CompileError(msg, path=f'workflow.flow[{index}].from')

        if not isinstance(to, str) or not to.strip():
            msg = '"to" must be a non-empty string'
            raise CompileError(msg, path=f'workflow.flow[{index}].to')
        to = to.strip()

        if to not in steps_ir and to not in _END_TARGETS:
            msg = '"to" must reference an existing step id or be $end/$reject'
            raise CompileError(msg, path=f'workflow.flow[{index}].to')

        if on is None:
            return frm, to, None

        if not isinstance(on, str) or not on.strip():
            msg = '"on" must be a non-empty string'
            raise CompileError(msg, path=f'workflow.flow[{index}].on')

        return frm, to, on.strip()

    @staticmethod
    def _add_flow_transition(
        transitions: dict[str, Any],
        *,
        frm: str,
        to: str,
        on: str | None,
        index: int,
    ) -> None:
        if on is None:
            if frm in transitions:
                msg = 'Duplicate transition for step'
                raise CompileError(msg, path=f'workflow.flow[{index}].from')
            transitions[frm] = {'kind': 'linear', 'to': to}
            return

        existing = transitions.get(frm)
        if existing is None:
            transitions[frm] = {'kind': 'by_outcome', 'map': {on: to}}
            return

        if existing.get('kind') != 'by_outcome':
            msg = 'Cannot mix linear and outcome transitions for the same step'
            raise CompileError(msg, path=f'workflow.flow[{index}].from')

        target_map = existing['map']
        if on in target_map:
            msg = 'Duplicate (from,on) transition'
            raise CompileError(msg, path=f'workflow.flow[{index}].on')

        target_map[on] = to

    @staticmethod
    def _compile_flow(flow: list[Any], steps_ir: dict[str, Any]) -> dict[str, Any]:
        transitions: dict[str, Any] = {}

        for index, item in enumerate(flow):
            frm, to, on = WorkflowCompiler._parse_flow_item(item, index=index, steps_ir=steps_ir)
            WorkflowCompiler._add_flow_transition(
                transitions,
                frm=frm,
                to=to,
                on=on,
                index=index,
            )

        return transitions

    def _validate_flow_completeness(self, steps_ir: dict[str, Any], transitions: dict[str, Any]) -> None:
        for step_id, s in steps_ir.items():
            produces = bool(s['produces_outcome'])
            outs: list[str] = list(s['outcomes'])

            tr = transitions.get(step_id)

            if produces:
                if tr is None or tr.get('kind') != 'by_outcome':
                    msg = 'Outcome-producing step requires outcome transitions'
                    raise CompileError(msg, path=f'workflow.flow({step_id})')
                mapped = set(tr['map'].keys())
                missing = [o for o in outs if o not in mapped]
                if missing:
                    msg = f'Missing flow mappings for outcomes: {missing}'
                    raise CompileError(msg, path=f'workflow.flow({step_id})')
            else:
                if tr is None:
                    continue
                if tr.get('kind') != 'linear':
                    msg = 'Non-outcome step requires a linear transition (or omit it to end)'
                    raise CompileError(msg, path=f'workflow.flow({step_id})')

    @staticmethod
    def _collect_reachable_steps(start_id: str, steps_ir: dict[str, Any], transitions: dict[str, Any]) -> set[str]:
        reachable: set[str] = set()
        pending = [start_id]

        while pending:
            step_id = pending.pop()
            if step_id in reachable or step_id not in steps_ir:
                continue

            reachable.add(step_id)
            transition = transitions.get(step_id)
            if not isinstance(transition, dict):
                continue

            if transition.get('kind') == 'linear':
                target = transition.get('to')
                if isinstance(target, str) and target in steps_ir:
                    pending.append(target)
                continue

            if transition.get('kind') == 'by_outcome':
                target_map = transition.get('map')
                if not isinstance(target_map, dict):
                    continue

                pending.extend(
                    target
                    for target in target_map.values()
                    if isinstance(target, str) and target in steps_ir
                )

        return reachable

    def _validate_flow_reachability(self, start_id: str, steps_ir: dict[str, Any], transitions: dict[str, Any]) -> None:
        reachable = self._collect_reachable_steps(start_id, steps_ir, transitions)
        unreachable = [step_id for step_id in steps_ir if step_id not in reachable]
        if not unreachable:
            return

        detail = ', '.join(unreachable)
        msg = f'Unreachable steps from workflow.start "{start_id}": {detail}'
        raise CompileError(
            msg,
            path='workflow.steps',
            details={'unreachable_steps': unreachable},
        )

    @staticmethod
    def _extract_set_step_vars(params: dict[str, Any]) -> set[str]:
        produced: set[str] = set()
        vars_map = params.get('vars')
        if not isinstance(vars_map, dict):
            return produced

        for key in vars_map:
            if isinstance(key, str) and key.strip():
                produced.add(key.strip())
        return produced

    @staticmethod
    def _extract_compute_step_vars(params: dict[str, Any]) -> set[str]:
        produced: set[str] = set()
        set_map = params.get('set')
        if not isinstance(set_map, dict):
            return produced

        for target in set_map:
            if not (isinstance(target, str) and target.startswith('vars.')):
                continue
            name = target.split('.', 1)[1].strip()
            if name:
                produced.add(name)
        return produced

    @staticmethod
    def _extract_webhook_step_vars(params: dict[str, Any]) -> set[str]:
        produced: set[str] = set()
        capture = params.get('capture')
        if not isinstance(capture, list):
            return produced

        for rule in capture:
            if not isinstance(rule, dict):
                continue
            target = rule.get('target')
            if (
                isinstance(target, list)
                and len(target) >= VARS_PATH_MIN_PARTS
                and target[0] == 'vars'
                and isinstance(target[1], str)
                and target[1].strip()
            ):
                produced.add(target[1].strip())

        return produced

    @staticmethod
    def _extract_step_produced_vars(step_ir: dict[str, Any]) -> set[str]:
        step_type = step_ir.get('type')
        params = step_ir.get('params') or {}

        if step_type == StepTypes.SET:
            return WorkflowCompiler._extract_set_step_vars(params)

        if step_type == StepTypes.COMPUTE:
            return WorkflowCompiler._extract_compute_step_vars(params)

        if step_type == StepTypes.WEBHOOK:
            return WorkflowCompiler._extract_webhook_step_vars(params)

        return set()

    @staticmethod
    def _build_step_predecessors(
        steps_ir: dict[str, Any],
        transitions: dict[str, Any],
        reachable: set[str],
    ) -> dict[str, set[str]]:
        predecessors: dict[str, set[str]] = {step_id: set() for step_id in steps_ir}

        for from_step, transition in transitions.items():
            if from_step not in reachable or not isinstance(transition, dict):
                continue

            if transition.get('kind') == 'linear':
                target = transition.get('to')
                if isinstance(target, str) and target in reachable:
                    predecessors[target].add(from_step)
                continue

            if transition.get('kind') == 'by_outcome':
                target_map = transition.get('map')
                if not isinstance(target_map, dict):
                    continue
                for target in target_map.values():
                    if isinstance(target, str) and target in reachable:
                        predecessors[target].add(from_step)

        return predecessors

    @staticmethod
    def _build_initial_available_var_maps(
        *,
        start_id: str,
        steps_ir: dict[str, Any],
        reachable: set[str],
        produced_by_step: dict[str, set[str]],
        produced_universe: set[str],
    ) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
        available_before: dict[str, set[str]] = {}
        available_after: dict[str, set[str]] = {}

        for step_id in steps_ir:
            if step_id not in reachable or step_id == start_id:
                available_before[step_id] = set()
            else:
                available_before[step_id] = set(produced_universe)

            available_after[step_id] = set(available_before[step_id]) | produced_by_step.get(step_id, set())

        return available_before, available_after

    @staticmethod
    def _get_step_available_before(
        *,
        step_id: str,
        start_id: str,
        predecessors: dict[str, set[str]],
        available_after: dict[str, set[str]],
    ) -> set[str]:
        if step_id == start_id:
            return set()

        incoming = list(predecessors.get(step_id, set()))
        if not incoming:
            return set()

        next_before = set(available_after[incoming[0]])
        for predecessor_id in incoming[1:]:
            next_before &= available_after[predecessor_id]
        return next_before

    def _compute_available_vars_before_step(
        self,
        start_id: str,
        steps_ir: dict[str, Any],
        transitions: dict[str, Any],
    ) -> tuple[dict[str, set[str]], set[str]]:
        reachable = self._collect_reachable_steps(start_id, steps_ir, transitions)
        predecessors = self._build_step_predecessors(steps_ir, transitions, reachable)
        produced_by_step = {
            step_id: self._extract_step_produced_vars(step_ir)
            for step_id, step_ir in steps_ir.items()
        }

        produced_universe: set[str] = set()
        for step_id in reachable:
            produced_universe.update(produced_by_step.get(step_id, set()))

        available_before, available_after = self._build_initial_available_var_maps(
            start_id=start_id,
            steps_ir=steps_ir,
            reachable=reachable,
            produced_by_step=produced_by_step,
            produced_universe=produced_universe,
        )

        changed = True
        while changed:
            changed = False

            for step_id in steps_ir:
                if step_id not in reachable:
                    continue

                next_before = self._get_step_available_before(
                    step_id=step_id,
                    start_id=start_id,
                    predecessors=predecessors,
                    available_after=available_after,
                )
                next_after = set(next_before) | produced_by_step.get(step_id, set())

                if next_before != available_before[step_id]:
                    available_before[step_id] = next_before
                    changed = True

                if next_after != available_after[step_id]:
                    available_after[step_id] = next_after
                    changed = True

        return available_before, reachable

    def _raise_unavailable_var(self, *, step_id: str, var_name: str, available_vars: set[str], path: str) -> None:
        available_detail = ', '.join(sorted(available_vars))
        if available_detail:
            message = (
                f'Variable "vars.{var_name}" may not be initialized before step "{step_id}". '
                f'Guaranteed vars here: {available_detail}'
            )
        else:
            message = (
                f'Variable "vars.{var_name}" may not be initialized before step "{step_id}". '
                'No workflow vars are guaranteed here yet.'
            )

        raise CompileError(
            message,
            path=path,
            details={
                'step_id': step_id,
                'variable': var_name,
                'available_vars': sorted(available_vars),
            },
        )

    def _validate_expr_ir_refs(
        self,
        expr_ir: Any,
        *,
        available_vars: set[str],
        step_id: str,
        path: str,
    ) -> None:
        if not isinstance(expr_ir, dict):
            return

        kind = expr_ir.get('kind')
        if kind == 'ref':
            ref_path = expr_ir.get('path')
            if not (isinstance(ref_path, list) and ref_path):
                return
            if ref_path[0] != 'vars' or len(ref_path) < VARS_PATH_MIN_PARTS:
                return

            var_name = ref_path[1]
            if isinstance(var_name, str) and var_name not in available_vars:
                self._raise_unavailable_var(
                    step_id=step_id,
                    var_name=var_name,
                    available_vars=available_vars,
                    path=path,
                )
            return

        if kind == 'call':
            for index, arg in enumerate(expr_ir.get('args') or []):
                self._validate_expr_ir_refs(
                    arg,
                    available_vars=available_vars,
                    step_id=step_id,
                    path=f'{path}.args[{index}]',
                )
            return

    def _validate_template_parts_refs(
        self,
        parts: Any,
        *,
        available_vars: set[str],
        step_id: str,
        path: str,
    ) -> None:
        for index, part in enumerate(parts or []):
            if isinstance(part, dict) and part.get('kind') == 'expr':
                self._validate_expr_ir_refs(
                    part.get('expr'),
                    available_vars=available_vars,
                    step_id=step_id,
                    path=f'{path}.parts[{index}]',
                )

    def _validate_nested_mapping_refs(
        self,
        mapping: dict[str, Any],
        *,
        available_vars: set[str],
        step_id: str,
        path: str,
    ) -> None:
        for key, nested in mapping.items():
            self._validate_compiled_value_refs(
                nested,
                available_vars=available_vars,
                step_id=step_id,
                path=f'{path}.{key}',
            )

    def _validate_compiled_value_refs(
        self,
        value: Any,
        *,
        available_vars: set[str],
        step_id: str,
        path: str,
    ) -> None:
        if isinstance(value, list):
            for index, item in enumerate(value):
                self._validate_compiled_value_refs(
                    item,
                    available_vars=available_vars,
                    step_id=step_id,
                    path=f'{path}[{index}]',
                )
            return

        if not isinstance(value, dict):
            return

        kind = value.get('kind')
        if kind == 'template':
            self._validate_template_parts_refs(
                value.get('parts'),
                available_vars=available_vars,
                step_id=step_id,
                path=path,
            )
            return

        if kind in {'ref', 'call'}:
            self._validate_expr_ir_refs(
                value,
                available_vars=available_vars,
                step_id=step_id,
                path=path,
            )
            return

        if kind == 'expr':
            self._validate_expr_ir_refs(
                value.get('expr'),
                available_vars=available_vars,
                step_id=step_id,
                path=path,
            )
            return

        if kind == 'lit':
            return

        self._validate_nested_mapping_refs(
            value,
            available_vars=available_vars,
            step_id=step_id,
            path=path,
        )

    def _validate_condition_refs(
        self,
        condition_ir: Any,
        *,
        available_vars: set[str],
        step_id: str,
        path: str,
    ) -> None:
        if not isinstance(condition_ir, dict):
            return

        op = condition_ir.get('op')
        if op == 'exists':
            self._validate_compiled_value_refs(
                condition_ir.get('arg'),
                available_vars=available_vars,
                step_id=step_id,
                path=f'{path}.exists',
            )
            return

        if op == 'not':
            self._validate_condition_refs(
                condition_ir.get('arg'),
                available_vars=available_vars,
                step_id=step_id,
                path=f'{path}.not',
            )
            return

        if op in {'and', 'or'}:
            for index, item in enumerate(condition_ir.get('args') or []):
                self._validate_condition_refs(
                    item,
                    available_vars=available_vars,
                    step_id=step_id,
                    path=f'{path}.{op}[{index}]',
                )
            return

        if op == 'compare':
            self._validate_compiled_value_refs(
                condition_ir.get('left'),
                available_vars=available_vars,
                step_id=step_id,
                path=f'{path}.compare.left',
            )
            self._validate_compiled_value_refs(
                condition_ir.get('right'),
                available_vars=available_vars,
                step_id=step_id,
                path=f'{path}.compare.right',
            )

    def _validate_email_step_refs(
        self,
        params: dict[str, Any],
        *,
        available_vars: set[str],
        step_id: str,
        base: str,
    ) -> None:
        self._validate_compiled_value_refs(
            params.get('subject'),
            available_vars=available_vars,
            step_id=step_id,
            path=f'{base}.subject',
        )
        self._validate_compiled_value_refs(
            params.get('body'),
            available_vars=available_vars,
            step_id=step_id,
            path=f'{base}.body',
        )

    def _validate_webhook_step_refs(
        self,
        params: dict[str, Any],
        *,
        available_vars: set[str],
        step_id: str,
        base: str,
    ) -> None:
        self._validate_compiled_value_refs(
            params.get('url'),
            available_vars=available_vars,
            step_id=step_id,
            path=f'{base}.url',
        )
        self._validate_compiled_value_refs(
            params.get('headers'),
            available_vars=available_vars,
            step_id=step_id,
            path=f'{base}.headers',
        )
        self._validate_compiled_value_refs(
            params.get('body'),
            available_vars=available_vars,
            step_id=step_id,
            path=f'{base}.body',
        )

    def _validate_logic_step_refs(
        self,
        params: dict[str, Any],
        *,
        available_vars: set[str],
        step_id: str,
        base: str,
    ) -> None:
        for index, item in enumerate(params.get('cases') or []):
            if not isinstance(item, dict):
                continue
            self._validate_condition_refs(
                item.get('when'),
                available_vars=available_vars,
                step_id=step_id,
                path=f'{base}.cases[{index}].when',
            )

    def _validate_set_step_refs(
        self,
        params: dict[str, Any],
        *,
        available_vars: set[str],
        step_id: str,
        base: str,
    ) -> None:
        self._validate_compiled_value_refs(
            params.get('vars'),
            available_vars=available_vars,
            step_id=step_id,
            path=f'{base}.vars',
        )

    def _validate_compute_step_refs(
        self,
        params: dict[str, Any],
        *,
        available_vars: set[str],
        step_id: str,
        base: str,
    ) -> None:
        current_available = set(available_vars)
        set_map = params.get('set') or {}
        if not isinstance(set_map, dict):
            return

        for target, spec in set_map.items():
            self._validate_compiled_value_refs(
                spec.get('expr') if isinstance(spec, dict) else spec,
                available_vars=current_available,
                step_id=step_id,
                path=f'{base}.set.{target}',
            )
            if isinstance(target, str) and target.startswith('vars.'):
                name = target.split('.', 1)[1].strip()
                if name:
                    current_available.add(name)

    def _validate_step_variable_references(
        self,
        start_id: str,
        steps_ir: dict[str, Any],
        transitions: dict[str, Any],
    ) -> None:
        available_before, reachable = self._compute_available_vars_before_step(start_id, steps_ir, transitions)

        for step_id, step_ir in steps_ir.items():
            if step_id not in reachable:
                continue

            step_type = step_ir.get('type')
            params = step_ir.get('params') or {}
            base = f'workflow.steps.{step_id}'
            available_vars = set(available_before.get(step_id, set()))

            if step_type == StepTypes.EMAIL:
                self._validate_email_step_refs(
                    params,
                    available_vars=available_vars,
                    step_id=step_id,
                    base=base,
                )
                continue

            if step_type == StepTypes.WEBHOOK:
                self._validate_webhook_step_refs(
                    params,
                    available_vars=available_vars,
                    step_id=step_id,
                    base=base,
                )
                continue

            if step_type == StepTypes.LOGIC:
                self._validate_logic_step_refs(
                    params,
                    available_vars=available_vars,
                    step_id=step_id,
                    base=base,
                )
                continue

            if step_type == StepTypes.SET:
                self._validate_set_step_refs(
                    params,
                    available_vars=available_vars,
                    step_id=step_id,
                    base=base,
                )
                continue

            if step_type == StepTypes.COMPUTE:
                self._validate_compute_step_refs(
                    params,
                    available_vars=available_vars,
                    step_id=step_id,
                    base=base,
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
    """Convenience wrapper that compiles Workflow 2 YAML into IR."""
    return WorkflowCompiler(compiler_version=compiler_version).compile(yaml_text)
