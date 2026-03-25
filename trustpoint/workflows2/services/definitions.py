"""Create, update, and compile stored Workflow 2 definitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.compiler.errors import CompileError
from workflows2.compiler.yaml_format import format_yaml_text
from workflows2.models import Workflow2Definition


@dataclass(frozen=True)
class CompileResult:
    """Return object for definition compilation attempts."""

    ok: bool
    ir: dict[str, Any] | None
    error: str | None
    formatted_yaml: str | None


class WorkflowDefinitionService:
    """Format YAML + compile + persist Workflow2Definition.

    Design:
      - UI YAML is canonicalized before compile and before saving to DB.
      - The DB YAML is the single source of truth (stable formatting).
    """

    def __init__(self, *, compiler_version: str = 'workflows2-ui') -> None:
        """Initialize the service with the compiler version label to record."""
        self.compiler_version = compiler_version

    def compile_yaml(self, yaml_text: str) -> CompileResult:
        """Format and compile YAML without saving a definition."""
        try:
            formatted = format_yaml_text(yaml_text)
        except Exception as e:  # noqa: BLE001
            return CompileResult(ok=False, ir=None, error=f'YAML format failed: {e!s}', formatted_yaml=None)

        try:
            ir = compile_workflow_yaml(formatted, compiler_version=self.compiler_version)
            return CompileResult(ok=True, ir=ir, error=None, formatted_yaml=formatted)
        except CompileError as e:
            return CompileResult(ok=False, ir=None, error=str(e), formatted_yaml=formatted)
        except Exception as e:  # noqa: BLE001
            return CompileResult(ok=False, ir=None, error=f'Unexpected error: {e!s}', formatted_yaml=formatted)

    @staticmethod
    def _extract_trigger_on(ir: dict[str, Any]) -> str:
        trig = ir.get('trigger')
        if isinstance(trig, dict):
            on = trig.get('on')
            if isinstance(on, str):
                return on
        return ''

    @staticmethod
    def _extract_ir_hash(ir: dict[str, Any]) -> str:
        meta = ir.get('meta')
        if isinstance(meta, dict):
            h = meta.get('ir_hash')
            if isinstance(h, str) and h:
                return h
        return 'missing-ir-hash'

    def create_definition(
        self,
        *,
        name: str,
        enabled: bool,
        yaml_text: str,
    ) -> tuple[Workflow2Definition | None, CompileResult]:
        """Create a new definition from validated YAML text."""
        res = self.compile_yaml(yaml_text)
        if not res.ok or res.ir is None or res.formatted_yaml is None:
            return None, res

        obj = Workflow2Definition.objects.create(
            name=name.strip(),
            enabled=enabled,
            trigger_on=self._extract_trigger_on(res.ir),
            yaml_text=res.formatted_yaml,
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
        """Update an existing definition from validated YAML text."""
        res = self.compile_yaml(yaml_text)
        if not res.ok or res.ir is None or res.formatted_yaml is None:
            return None, res

        definition.name = name.strip()
        definition.enabled = enabled
        definition.trigger_on = self._extract_trigger_on(res.ir)
        definition.yaml_text = res.formatted_yaml
        definition.ir_json = res.ir
        definition.ir_hash = self._extract_ir_hash(res.ir)
        definition.save(update_fields=['name', 'enabled', 'trigger_on', 'yaml_text', 'ir_json', 'ir_hash'])
        return definition, res
