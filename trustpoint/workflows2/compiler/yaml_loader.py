"""YAML loading helpers with Trustpoint-specific parsing behavior."""

from __future__ import annotations

import copy
import re
from typing import Any

import yaml

from .errors import CompileError


class TrustpointYamlLoader(yaml.SafeLoader):
    """Workflow YAML parser with YAML 1.2-ish boolean behavior.

    PyYAML defaults to YAML 1.1 bool parsing (on/off/yes/no).
    We want only true/false to be booleans, so "on" stays a string.
    """


# IMPORTANT:
# yaml_implicit_resolvers is a shared class-level structure in PyYAML.
# Never mutate it in place, or you may affect other loaders/dumpers.
TrustpointYamlLoader.yaml_implicit_resolvers = copy.deepcopy(yaml.SafeLoader.yaml_implicit_resolvers)

# Remove YAML 1.1 bool resolver
for ch, resolvers in list(TrustpointYamlLoader.yaml_implicit_resolvers.items()):
    TrustpointYamlLoader.yaml_implicit_resolvers[ch] = [
        (tag, regexp) for (tag, regexp) in resolvers if tag != 'tag:yaml.org,2002:bool'
    ]

# Add strict YAML 1.2-ish bool resolver: true/false only
_bool_12 = re.compile(r'^(?:true|false)$', re.IGNORECASE)


def _add_bool_resolver(loader_cls: Any) -> None:
    """Register the strict boolean resolver on a PyYAML loader class."""
    loader_cls.add_implicit_resolver('tag:yaml.org,2002:bool', _bool_12, list('tTfF'))


_add_bool_resolver(TrustpointYamlLoader)


def load_yaml_any(yaml_text: str) -> Any:
    """Parse YAML text into native Python values."""
    try:
        return yaml.load(yaml_text, Loader=TrustpointYamlLoader)  # noqa: S506
    except yaml.YAMLError as e:
        msg = 'Invalid YAML'
        raise CompileError(msg, details=str(e)) from e


def load_yaml_text(yaml_text: str) -> dict[str, Any]:
    """Parse YAML text and require a mapping at the top level."""
    data = load_yaml_any(yaml_text)
    if not isinstance(data, dict):
        msg = 'Top-level YAML must be a mapping/object.'
        raise CompileError(msg)
    return data
