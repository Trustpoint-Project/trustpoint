"""Lightweight schema linting for Workflow 2 YAML."""

from __future__ import annotations

from dataclasses import dataclass
from difflib import get_close_matches
from typing import Any, ClassVar

from .errors import CompileError


@dataclass(frozen=True)
class _StepSpec:
    allowed_keys: frozenset[str]


class SchemaLinter:
    """Lightweight schema linter.

    Purpose:
      - catch unknown top-level keys early (before deeper compiler errors)
      - catch unknown step keys with suggestions
      - validate step "type" is known (compiler validates semantics)

    This is intentionally NOT a full schema system; it's a guardrail.
    """

    _TOP_LEVEL_KEYS: ClassVar[frozenset[str]] = frozenset({'schema', 'name', 'enabled', 'trigger', 'apply', 'workflow'})
    _WORKFLOW_KEYS: ClassVar[frozenset[str]] = frozenset({'start', 'steps', 'flow'})
    _TRIGGER_KEYS: ClassVar[frozenset[str]] = frozenset({'on', 'sources'})
    _TRIGGER_SOURCES_KEYS: ClassVar[frozenset[str]] = frozenset({'trustpoint', 'ca_ids', 'domain_ids', 'device_ids'})

    _STEP_SPECS: ClassVar[dict[str, _StepSpec]] = {
        'email': _StepSpec(
            allowed_keys={
                'type',
                'title',
                'to',
                'cc',
                'bcc',
                'subject',
                'body',
            }
        ),
        'webhook': _StepSpec(
            allowed_keys={
                'type',
                'title',
                'method',
                'url',
                'headers',
                'body',
                'timeout_seconds',
                'capture',
            }
        ),
        'logic': _StepSpec(
            allowed_keys={
                'type',
                'title',
                'cases',
                'default',
            }
        ),
        'set': _StepSpec(
            allowed_keys={
                'type',
                'title',
                'vars',
            }
        ),
        'compute': _StepSpec(
            allowed_keys={
                'type',
                'title',
                'set',
            }
        ),
        'approval': _StepSpec(
            allowed_keys={
                'type',
                'title',
                'approved_outcome',
                'rejected_outcome',
                'timeout_seconds',
            }
        ),
    }

    def _lint_top_level_keys(self, src: dict[str, Any]) -> None:
        for key in src:
            if key not in self._TOP_LEVEL_KEYS:
                raise CompileError(
                    self._unknown_key_message(str(key), self._TOP_LEVEL_KEYS),
                    path=str(key),
                )

    def _lint_workflow_keys(self, src: dict[str, Any]) -> dict[str, Any] | None:
        wf = src.get('workflow')
        if not isinstance(wf, dict):
            return None

        for key in wf:
            if key not in self._WORKFLOW_KEYS:
                raise CompileError(
                    self._unknown_key_message(str(key), self._WORKFLOW_KEYS),
                    path=f'workflow.{key}',
                )

        return wf

    def _lint_trigger_sources_keys(self, trig: dict[str, Any]) -> None:
        sources = trig.get('sources')
        if not isinstance(sources, dict):
            return

        for key in sources:
            if key not in self._TRIGGER_SOURCES_KEYS:
                raise CompileError(
                    self._unknown_key_message(str(key), self._TRIGGER_SOURCES_KEYS),
                    path=f'trigger.sources.{key}',
                )

    def _lint_trigger_keys(self, src: dict[str, Any]) -> None:
        trig = src.get('trigger')
        if not isinstance(trig, dict):
            return

        for key in trig:
            if key not in self._TRIGGER_KEYS:
                raise CompileError(
                    self._unknown_key_message(str(key), self._TRIGGER_KEYS),
                    path=f'trigger.{key}',
                )

        self._lint_trigger_sources_keys(trig)

    def _lint_steps(self, wf: dict[str, Any] | None) -> None:
        if not isinstance(wf, dict):
            return

        steps = wf.get('steps')
        if not isinstance(steps, dict):
            return

        for step_id, step in steps.items():
            if not isinstance(step, dict):
                continue
            self._lint_step(str(step_id), step)

    def lint(self, src: dict[str, Any]) -> None:
        """Validate the rough workflow shape before deeper compilation."""
        if not isinstance(src, dict):
            msg = 'Top-level YAML must be a mapping'
            raise CompileError(msg, path='')

        self._lint_top_level_keys(src)
        wf = self._lint_workflow_keys(src)
        self._lint_trigger_keys(src)
        self._lint_steps(wf)

    def _lint_step(self, step_id: str, step: dict[str, Any]) -> None:
        base = f'workflow.steps.{step_id}'
        typ = step.get('type')

        if not isinstance(typ, str) or not typ.strip():
            return

        typ = typ.strip()
        spec = self._STEP_SPECS.get(typ)
        if spec is None:
            known = sorted(self._STEP_SPECS.keys())
            msg = f'Unknown step type "{typ}". Allowed: {", ".join(known)}'
            raise CompileError(msg, path=f'{base}.type')

        for k in step:
            if k not in spec.allowed_keys:
                raise CompileError(
                    self._unknown_key_message(str(k), spec.allowed_keys),
                    path=f'{base}.{k}',
                )

    @staticmethod
    def _unknown_key_message(bad_key: str, allowed: set[str] | frozenset[str]) -> str:
        allowed_list = sorted(allowed)
        suggestion = ''
        matches = get_close_matches(bad_key, allowed_list, n=1, cutoff=0.65)
        if matches:
            suggestion = f' Did you mean "{matches[0]}"?'
        return f'Unknown key "{bad_key}". Allowed: {", ".join(allowed_list)}.{suggestion}'
