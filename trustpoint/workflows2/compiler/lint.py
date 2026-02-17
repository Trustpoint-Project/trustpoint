# workflows2/compiler/lint.py
from __future__ import annotations

from dataclasses import dataclass
from difflib import get_close_matches
from typing import Any

from .errors import CompileError


@dataclass(frozen=True)
class _StepSpec:
    allowed_keys: set[str]


class SchemaLinter:
    """
    Lightweight schema linter.

    Purpose:
      - catch unknown top-level keys early (before deeper compiler errors)
      - catch unknown step keys with suggestions
      - validate step "type" is known (compiler validates semantics)

    This is intentionally NOT a full schema system; it's a guardrail.
    """

    # Top-level YAML keys (v2 draft)
    _TOP_LEVEL_KEYS: set[str] = {"schema", "name", "enabled", "trigger", "apply", "workflow"}

    # Workflow-level keys
    _WORKFLOW_KEYS: set[str] = {"start", "steps", "flow"}

    # Trigger keys
    _TRIGGER_KEYS: set[str] = {"on", "sources"}
    _TRIGGER_SOURCES_KEYS: set[str] = {"trustpoint", "ca_ids", "domain_ids", "device_ids"}

    # Step specs by type: allowed keys inside workflow.steps.<id>
    _STEP_SPECS: dict[str, _StepSpec] = {
        # shared keys: type, title are allowed everywhere
        "email": _StepSpec(
            allowed_keys={
                "type",
                "title",
                "to",
                "cc",
                "bcc",
                "subject",
                "body",
            }
        ),
        "webhook": _StepSpec(
            allowed_keys={
                "type",
                "title",
                "method",
                "url",
                "headers",
                "body",
                "timeout_seconds",
                "capture",
            }
        ),
        "logic": _StepSpec(
            allowed_keys={
                "type",
                "title",
                "cases",
                "default",
            }
        ),
        "set": _StepSpec(
            allowed_keys={
                "type",
                "title",
                "vars",
            }
        ),
        "compute": _StepSpec(
            allowed_keys={
                "type",
                "title",
                "set",
            }
        ),
        "approval": _StepSpec(
            allowed_keys={
                "type",
                "title",
                "approved_outcome",
                "rejected_outcome",
                "timeout_seconds",  # <-- NEW: optional
            }
        ),
        "reject": _StepSpec(  # <-- NEW
            allowed_keys={
                "type",
                "title",
                "reason",
            }
        ),
        "stop": _StepSpec(
            allowed_keys={
                "type",
                "title",
                "reason",
            }
        ),
        "succeed": _StepSpec(
            allowed_keys={
                "type",
                "title",
                "message",  # optional
            }
        ),
        "fail": _StepSpec(
            allowed_keys={
                "type",
                "title",
                "reason",  # optional (compiler allows None)
            }
        ),
    }

    def lint(self, src: dict[str, Any]) -> None:
        if not isinstance(src, dict):
            raise CompileError("Top-level YAML must be a mapping", path="")

        # unknown top-level keys
        for k in src.keys():
            if k not in self._TOP_LEVEL_KEYS:
                raise CompileError(
                    self._unknown_key_message(str(k), self._TOP_LEVEL_KEYS),
                    path=str(k),
                )

        # workflow keys sanity
        wf = src.get("workflow")
        if isinstance(wf, dict):
            for k in wf.keys():
                if k not in self._WORKFLOW_KEYS:
                    raise CompileError(
                        self._unknown_key_message(str(k), self._WORKFLOW_KEYS),
                        path=f"workflow.{k}",
                    )

        # trigger keys sanity
        trig = src.get("trigger")
        if isinstance(trig, dict):
            for k in trig.keys():
                if k not in self._TRIGGER_KEYS:
                    raise CompileError(
                        self._unknown_key_message(str(k), self._TRIGGER_KEYS),
                        path=f"trigger.{k}",
                    )
            sources = trig.get("sources")
            if isinstance(sources, dict):
                for k in sources.keys():
                    if k not in self._TRIGGER_SOURCES_KEYS:
                        raise CompileError(
                            self._unknown_key_message(str(k), self._TRIGGER_SOURCES_KEYS),
                            path=f"trigger.sources.{k}",
                        )

        # steps key sanity
        steps = wf.get("steps") if isinstance(wf, dict) else None
        if isinstance(steps, dict):
            for step_id, step in steps.items():
                if not isinstance(step, dict):
                    continue
                self._lint_step(str(step_id), step)

    def _lint_step(self, step_id: str, step: dict[str, Any]) -> None:
        base = f"workflow.steps.{step_id}"
        typ = step.get("type")

        if not isinstance(typ, str) or not typ.strip():
            # compiler will produce clearer errors; still keep here.
            return

        typ = typ.strip()
        spec = self._STEP_SPECS.get(typ)
        if spec is None:
            known = sorted(self._STEP_SPECS.keys())
            msg = f'Unknown step type "{typ}". Allowed: {", ".join(known)}'
            raise CompileError(msg, path=f"{base}.type")

        for k in step.keys():
            if k not in spec.allowed_keys:
                raise CompileError(
                    self._unknown_key_message(str(k), spec.allowed_keys),
                    path=f"{base}.{k}",
                )

    @staticmethod
    def _unknown_key_message(bad_key: str, allowed: set[str]) -> str:
        allowed_list = sorted(allowed)
        suggestion = ""
        matches = get_close_matches(bad_key, allowed_list, n=1, cutoff=0.65)
        if matches:
            suggestion = f' Did you mean "{matches[0]}"?'
        return f'Unknown key "{bad_key}". Allowed: {", ".join(allowed_list)}.{suggestion}'
