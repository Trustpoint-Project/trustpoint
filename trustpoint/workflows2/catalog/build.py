# workflows2/catalog/build.py
from __future__ import annotations

from typing import Any

from workflows2.catalog.presets import PRESETS
from workflows2.catalog.steps import step_specs
from workflows2.events.registry import get_event_registry


def build_context_catalog() -> dict[str, Any]:
    reg = get_event_registry()

    events: list[dict[str, Any]] = []
    for spec in reg.all_specs():
        events.append(
            {
                "key": spec.key,
                "group": (spec.key.split(".", 1)[0] if "." in spec.key else spec.key),
                "description": spec.description,
                "allowed_step_types": (sorted(list(spec.allowed_step_types)) if spec.allowed_step_types is not None else None),
                "context_vars": [
                    {
                        "path": v.path,
                        "type": v.type,
                        "description": v.description,
                        "example": v.example,
                    }
                    for v in (spec.context_vars or [])
                ],
            }
        )

    steps: list[dict[str, Any]] = []
    for s in step_specs():
        steps.append(
            {
                "type": s.type,
                "title": s.title,
                "description": s.description,
                "category": s.category,
                "block_snippet": s.block_snippet,
                "fields": [
                    {
                        "key": f.key,
                        "title": f.title,
                        "description": f.description,
                        "insert_kind": f.insert_kind,
                        "snippet": f.snippet,
                        # ✅ NEW
                        "required": bool(getattr(f, "required", False)),
                    }
                    for f in s.fields
                ],
            }
        )

    presets: list[dict[str, Any]] = []
    for p in PRESETS:
        presets.append(
            {
                "id": p.id,
                "title": p.title,
                "description": p.description,
                "insert_kind": p.insert_kind,
                "snippet": p.snippet,
                "areas": sorted(list(p.areas)),
                "triggers": sorted(list(p.triggers)) if p.triggers is not None else None,
                "step_types": sorted(list(p.step_types)) if p.step_types is not None else None,
            }
        )

    return {
        "events": sorted(events, key=lambda x: x["key"]),
        "steps": steps,
        "presets": presets,
        "meta": {
            "version": 2,  # bump
        },
    }
