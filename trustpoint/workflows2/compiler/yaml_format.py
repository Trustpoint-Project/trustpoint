# workflows2/compiler/yaml_format.py
from __future__ import annotations

import copy
import re
from typing import Any

import yaml

from workflows2.compiler.yaml_loader import TrustpointYamlLoader


def _normalize_newlines(text: str) -> str:
    return str(text or "").replace("\r\n", "\n").replace("\r", "\n")


class TrustpointYamlDumper(yaml.SafeDumper):  # type: ignore[misc]
    """
    Canonical dumper:
      - 2-space mapping indent
      - sequences indented under their key (no indentless lists)
      - booleans emitted as "true"/"false" (no !!bool tags)
    """

    def increase_indent(self, flow: bool = False, indentless: bool = False):
        return super().increase_indent(flow=flow, indentless=False)


# IMPORTANT:
# Like loaders, dumpers also inherit shared resolver dicts.
# Deep-copy so we don't depend on global state.
TrustpointYamlDumper.yaml_implicit_resolvers = copy.deepcopy(yaml.SafeDumper.yaml_implicit_resolvers)

# Make dumper's bool resolution YAML 1.2-ish as well (true/false only).
for ch, resolvers in list(TrustpointYamlDumper.yaml_implicit_resolvers.items()):
    TrustpointYamlDumper.yaml_implicit_resolvers[ch] = [
        (tag, regexp) for (tag, regexp) in resolvers if tag != "tag:yaml.org,2002:bool"
    ]
_bool_12 = re.compile(r"^(?:true|false)$", re.IGNORECASE)
TrustpointYamlDumper.add_implicit_resolver("tag:yaml.org,2002:bool", _bool_12, list("tTfF"))


def _repr_bool(dumper: TrustpointYamlDumper, value: bool):  # type: ignore[type-arg]
    # Force canonical lowercase. Because our dumper has an implicit bool resolver,
    # this will serialize as plain "true"/"false" (no !!bool tags).
    return dumper.represent_scalar("tag:yaml.org,2002:bool", "true" if value else "false")


TrustpointYamlDumper.add_representer(bool, _repr_bool)


def parse_yaml_text(yaml_text: str) -> Any:
    return yaml.load(_normalize_newlines(yaml_text), Loader=TrustpointYamlLoader)  # noqa: S506


def dump_yaml_text(obj: Any) -> str:
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
    if out and not out.endswith("\n"):
        out += "\n"
    return out


def format_yaml_text(yaml_text: str) -> str:
    text = _normalize_newlines(yaml_text)
    if not text.strip():
        return ""

    obj = parse_yaml_text(text)
    if obj is None:
        return ""
    return dump_yaml_text(obj)
