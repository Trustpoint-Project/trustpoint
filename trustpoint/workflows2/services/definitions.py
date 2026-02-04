from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.compiler.errors import CompileError
from workflows2.models import Workflow2Definition


@dataclass(frozen=True)
class CompileResult:
    ok: bool
    ir: dict[str, Any] | None
    error: str | None


class WorkflowDefinitionService:
    """
    Compile YAML + persist Workflow2Definition.
    """

    def __init__(self, *, compiler_version: str = "workflows2-ui") -> None:
        self.compiler_version = compiler_version

    def compile_yaml(self, yaml_text: str) -> CompileResult:
        try:
            ir = compile_workflow_yaml(yaml_text, compiler_version=self.compiler_version)
            return CompileResult(ok=True, ir=ir, error=None)
        except CompileError as e:
            return CompileResult(ok=False, ir=None, error=str(e))
        except Exception as e:  # noqa: BLE001
            return CompileResult(ok=False, ir=None, error=f"Unexpected error: {e!s}")

    @staticmethod
    def _extract_trigger_on(ir: dict[str, Any]) -> str:
        trig = ir.get("trigger")
        if isinstance(trig, dict):
            on = trig.get("on")
            if isinstance(on, str):
                return on
        return ""

    @staticmethod
    def _extract_ir_hash(ir: dict[str, Any]) -> str:
        meta = ir.get("meta")
        if isinstance(meta, dict):
            h = meta.get("ir_hash")
            if isinstance(h, str) and h:
                return h
        return "missing-ir-hash"

    def create_definition(
        self,
        *,
        name: str,
        enabled: bool,
        yaml_text: str,
    ) -> tuple[Workflow2Definition | None, CompileResult]:
        res = self.compile_yaml(yaml_text)
        if not res.ok or res.ir is None:
            return None, res

        obj = Workflow2Definition.objects.create(
            name=name.strip(),
            enabled=enabled,
            trigger_on=self._extract_trigger_on(res.ir),
            yaml_text=yaml_text,
            ir_json=res.ir,
            ir_hash=self._extract_ir_hash(res.ir),
        )
        return obj, res

    def update_definition(
        self,
        *,
        definition: Workflow2Definition,
        name: str,
        enabled: bool,
        yaml_text: str,
    ) -> tuple[Workflow2Definition | None, CompileResult]:
        res = self.compile_yaml(yaml_text)
        if not res.ok or res.ir is None:
            return None, res

        definition.name = name.strip()
        definition.enabled = enabled
        definition.trigger_on = self._extract_trigger_on(res.ir)
        definition.yaml_text = yaml_text
        definition.ir_json = res.ir
        definition.ir_hash = self._extract_ir_hash(res.ir)
        definition.save(update_fields=["name", "enabled", "trigger_on", "yaml_text", "ir_json", "ir_hash"])
        return definition, res
