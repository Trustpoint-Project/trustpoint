"""Canonical YAML formatting helpers for Workflow 2 definitions."""
from __future__ import annotations

import copy
import re
from typing import TYPE_CHECKING, Any, override

import yaml

from workflows2.compiler.yaml_loader import TrustpointYamlLoader

if TYPE_CHECKING:
    from yaml.nodes import ScalarNode


def _normalize_newlines(text: str) -> str:
    return str(text or '').replace('\r\n', '\n').replace('\r', '\n')


class TrustpointYamlDumper(yaml.SafeDumper):
    """Emit YAML in the canonical Workflow 2 house style.

    - 2-space mapping indent
    - sequences indented under their key
    - booleans emitted as `true`/`false`
    """

    @override
    def increase_indent(self, flow: bool = False, indentless: bool = False) -> Any:
        """Force list indentation under the parent key."""
        return super().increase_indent(flow=flow, indentless=indentless)


# IMPORTANT:
# Like loaders, dumpers also inherit shared resolver dicts.
# Deep-copy so we don't depend on global state.
TrustpointYamlDumper.yaml_implicit_resolvers = copy.deepcopy(yaml.SafeDumper.yaml_implicit_resolvers)

# Make dumper's bool resolution YAML 1.2-ish as well (true/false only).
for ch, resolvers in list(TrustpointYamlDumper.yaml_implicit_resolvers.items()):
    TrustpointYamlDumper.yaml_implicit_resolvers[ch] = [
        (tag, regexp) for (tag, regexp) in resolvers if tag != 'tag:yaml.org,2002:bool'
    ]
_bool_12 = re.compile(r'^(?:true|false)$', re.IGNORECASE)


def _add_bool_resolver(dumper_cls: Any) -> None:
    """Register the strict boolean resolver on a PyYAML dumper class."""
    dumper_cls.add_implicit_resolver('tag:yaml.org,2002:bool', _bool_12, list('tTfF'))


_add_bool_resolver(TrustpointYamlDumper)


def _repr_bool(dumper: TrustpointYamlDumper, value: bool) -> ScalarNode:  # noqa: FBT001
    # Force canonical lowercase. Because our dumper has an implicit bool resolver,
    # this will serialize as plain "true"/"false" (no !!bool tags).
    return dumper.represent_scalar('tag:yaml.org,2002:bool', 'true' if value else 'false')


TrustpointYamlDumper.add_representer(bool, _repr_bool)


def parse_yaml_text(yaml_text: str) -> Any:
    """Parse YAML text using the Trustpoint loader behavior."""
    return yaml.load(_normalize_newlines(yaml_text), Loader=TrustpointYamlLoader)  # noqa: S506


def dump_yaml_text(obj: Any) -> str:
    """Dump Python data as canonical Workflow 2 YAML."""
    out = yaml.dump(
        obj,
        Dumper=TrustpointYamlDumper,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=120,
        indent=2,
    )
    out = _normalize_newlines(out)
    if out and not out.endswith('\n'):
        out += '\n'
    return out


def format_yaml_text(yaml_text: str) -> str:
    """Parse and re-dump YAML text into canonical formatting."""
    text = _normalize_newlines(yaml_text)
    if not text.strip():
        return ''

    obj = parse_yaml_text(text)
    if obj is None:
        return ''
    return dump_yaml_text(obj)
