# workflows2/compiler/yaml_loader.py
from __future__ import annotations

from typing import Any
import re

import yaml

from .errors import CompileError


class TrustpointYamlLoader(yaml.SafeLoader):
    """
    PyYAML defaults to YAML 1.1 bool parsing (on/off/yes/no).
    For workflow specs we want YAML 1.2-like behavior: only true/false.
    """
    pass


# Remove YAML 1.1 bool resolver
for ch, resolvers in list(TrustpointYamlLoader.yaml_implicit_resolvers.items()):
    TrustpointYamlLoader.yaml_implicit_resolvers[ch] = [
        (tag, regexp) for (tag, regexp) in resolvers if tag != "tag:yaml.org,2002:bool"
    ]

# Add strict YAML 1.2-ish bool resolver: true/false only
_bool_12 = re.compile(r"^(?:true|false)$", re.IGNORECASE)
TrustpointYamlLoader.add_implicit_resolver("tag:yaml.org,2002:bool", _bool_12, list("tTfF"))


def load_yaml_text(yaml_text: str) -> dict[str, Any]:
    try:
        data = yaml.load(yaml_text, Loader=TrustpointYamlLoader)  # noqa: S506 (custom SafeLoader)
    except yaml.YAMLError as e:
        raise CompileError("Invalid YAML", details=str(e)) from e

    if not isinstance(data, dict):
        raise CompileError("Top-level YAML must be a mapping/object.")
    return data
