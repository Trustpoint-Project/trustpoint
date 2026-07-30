#!/usr/bin/env python3
# Copyright (c) 2024 Trustpoint Project
# Licensed under the Apache License, Version 2.0
# ruff: noqa: D103, EM101, EM102, TRY003, T201, C901, PLR0912
"""Merge a generated CycloneDX CBOM with a manually maintained CBOM.

The generated CBOM remains authoritative for scanner findings. The manual CBOM
adds protocol-level assets and relationships that source scanners cannot infer.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import uuid
from pathlib import Path
from typing import Any

JsonObject = dict[str, Any]
TRUSTPOINT_PLACEHOLDER_REF = 'trustpoint:application'


def load_json(path: Path) -> JsonObject:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError as exc:
        raise SystemExit(f'Input file does not exist: {path}') from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f'Invalid JSON in {path}: {exc}') from exc

    if not isinstance(data, dict):
        raise SystemExit(f'Expected a JSON object in {path}')
    return data


def component_ref(component: JsonObject) -> str | None:
    ref = component.get('bom-ref')
    return ref if isinstance(ref, str) and ref else None


def is_trustpoint_component(component: JsonObject) -> bool:
    name = component.get('name')
    return isinstance(name, str) and name.casefold() == 'trustpoint'


def find_generated_subject(document: JsonObject) -> JsonObject | None:
    metadata = document.get('metadata')
    if isinstance(metadata, dict):
        subject = metadata.get('component')
        if isinstance(subject, dict) and is_trustpoint_component(subject):
            return subject

    for component in document.get('components', []):
        if isinstance(component, dict) and is_trustpoint_component(component):
            return component
    return None


def merge_missing_component_fields(target: JsonObject, source: JsonObject) -> None:
    for field in ('group', 'name', 'description'):
        if field not in target and field in source:
            target[field] = copy.deepcopy(source[field])

    for field in ('externalReferences', 'properties'):
        source_values = source.get(field, [])
        if not isinstance(source_values, list):
            raise SystemExit(f'Manual component field {field!r} must be an array')
        if not source_values:
            continue
        target_values = target.setdefault(field, [])
        if not isinstance(target_values, list):
            raise SystemExit(f'Generated component field {field!r} must be an array')
        for value in source_values:
            if value not in target_values:
                target_values.append(copy.deepcopy(value))


def rewrite_dependency_ref(dependency: JsonObject, old_ref: str, new_ref: str) -> None:
    if dependency.get('ref') == old_ref:
        dependency['ref'] = new_ref
    for field in ('dependsOn', 'provides'):
        values = dependency.get(field)
        if isinstance(values, list):
            dependency[field] = [new_ref if value == old_ref else value for value in values]


def prepare_manual_document(
    generated: JsonObject,
    manual: JsonObject,
    trustpoint_version: str | None,
) -> JsonObject:
    prepared = copy.deepcopy(manual)
    manual_components = prepared.get('components', [])
    if not isinstance(manual_components, list):
        raise SystemExit('manual components must be an array')

    placeholder = next(
        (
            component
            for component in manual_components
            if isinstance(component, dict)
            and component_ref(component) == TRUSTPOINT_PLACEHOLDER_REF
        ),
        None,
    )
    if placeholder is None:
        raise SystemExit(
            f'Manual CBOM must contain the placeholder component {TRUSTPOINT_PLACEHOLDER_REF!r}'
        )

    generated_subject = find_generated_subject(generated)
    if generated_subject is None:
        if trustpoint_version:
            placeholder['version'] = trustpoint_version
        return prepared

    generated_ref = component_ref(generated_subject)
    if generated_ref is None:
        generated_ref = TRUSTPOINT_PLACEHOLDER_REF
        generated_subject['bom-ref'] = generated_ref

    merge_missing_component_fields(generated_subject, placeholder)
    if trustpoint_version:
        generated_subject['version'] = trustpoint_version

    prepared['components'] = [
        component
        for component in manual_components
        if component_ref(component) != TRUSTPOINT_PLACEHOLDER_REF
    ]

    dependencies = prepared.get('dependencies', [])
    if not isinstance(dependencies, list):
        raise SystemExit('manual dependencies must be an array')
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise SystemExit('manual dependency entries must be objects')
        rewrite_dependency_ref(
            dependency,
            TRUSTPOINT_PLACEHOLDER_REF,
            generated_ref,
        )

    return prepared


def merge_unique_objects(
    generated_items: list[JsonObject],
    manual_items: list[JsonObject],
    *,
    collection_name: str,
) -> list[JsonObject]:
    """Merge referable objects while rejecting conflicting duplicate refs."""
    result = copy.deepcopy(generated_items)
    by_ref: dict[str, JsonObject] = {}

    for item in result:
        ref = component_ref(item)
        if ref:
            if ref in by_ref and by_ref[ref] != item:
                raise SystemExit(
                    f'Conflicting duplicate bom-ref {ref!r} in generated {collection_name}'
                )
            by_ref[ref] = item

    for item in manual_items:
        ref = component_ref(item)
        if not ref:
            if item not in result:
                result.append(copy.deepcopy(item))
            continue

        existing = by_ref.get(ref)
        if existing is None:
            cloned = copy.deepcopy(item)
            result.append(cloned)
            by_ref[ref] = cloned
        elif existing != item:
            raise SystemExit(
                f'Manual {collection_name} conflicts with generated bom-ref {ref!r}. '
                'Choose a different stable bom-ref or reconcile the entries.'
            )

    return result


def merge_dependencies(
    generated_dependencies: list[JsonObject],
    manual_dependencies: list[JsonObject],
) -> list[JsonObject]:
    result: list[JsonObject] = []
    by_ref: dict[str, JsonObject] = {}

    for dependency in [*generated_dependencies, *manual_dependencies]:
        ref = dependency.get('ref')
        if not isinstance(ref, str) or not ref:
            raise SystemExit('Every dependency object must have a non-empty ref')

        target = by_ref.get(ref)
        if target is None:
            target = {'ref': ref}
            by_ref[ref] = target
            result.append(target)

        for field in ('dependsOn', 'provides'):
            values = dependency.get(field, [])
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                raise SystemExit(
                    f'Dependency field {field!r} for {ref!r} must be a string array'
                )
            if values:
                target.setdefault(field, [])
                for value in values:
                    if value not in target[field]:
                        target[field].append(value)
            elif field in dependency and field not in target:
                target[field] = []

    return result


def merge_properties(generated: JsonObject, manual: JsonObject) -> None:
    generated_metadata = generated.setdefault('metadata', {})
    manual_metadata = manual.get('metadata', {})
    if not isinstance(generated_metadata, dict) or not isinstance(manual_metadata, dict):
        raise SystemExit('metadata must be a JSON object')

    generated_properties = generated_metadata.setdefault('properties', [])
    manual_properties = manual_metadata.get('properties', [])
    if not isinstance(generated_properties, list) or not isinstance(manual_properties, list):
        raise SystemExit('metadata.properties must be an array')

    for prop in manual_properties:
        if prop not in generated_properties:
            generated_properties.append(copy.deepcopy(prop))

    enrichment_property = {
        'name': 'trustpoint:cbom:enrichment',
        'value': 'CBOMkit source findings merged with manually maintained Trustpoint protocol assets',
    }
    if enrichment_property not in generated_properties:
        generated_properties.append(enrichment_property)


def validate_references(document: JsonObject) -> None:
    known_refs: set[str] = set()
    duplicate_refs: set[str] = set()

    for collection_name in ('components', 'services'):
        for item in document.get(collection_name, []):
            ref = component_ref(item)
            if ref:
                if ref in known_refs:
                    duplicate_refs.add(ref)
                known_refs.add(ref)

    metadata_component = document.get('metadata', {}).get('component')
    if isinstance(metadata_component, dict):
        ref = component_ref(metadata_component)
        if ref:
            if ref in known_refs:
                duplicate_refs.add(ref)
            known_refs.add(ref)

    if duplicate_refs:
        raise SystemExit(f'Duplicate bom-ref values in final CBOM: {sorted(duplicate_refs)}')

    missing: set[str] = set()
    for dependency in document.get('dependencies', []):
        ref = dependency['ref']
        if ref not in known_refs:
            missing.add(ref)
        for field in ('dependsOn', 'provides'):
            for target in dependency.get(field, []):
                if target not in known_refs:
                    missing.add(target)

    if missing:
        raise SystemExit(
            f'Dependency graph references unknown bom-ref values: {sorted(missing)}'
        )


def merge_cboms(generated: JsonObject, manual: JsonObject, version: str | None) -> JsonObject:
    for label, document in (('generated', generated), ('manual', manual)):
        if document.get('bomFormat') != 'CycloneDX':
            raise SystemExit(f'{label} input is not a CycloneDX BOM')

    generated_spec = generated.get('specVersion')
    manual_spec = manual.get('specVersion')
    if generated_spec != manual_spec:
        raise SystemExit(
            f'CycloneDX version mismatch: generated={generated_spec!r}, manual={manual_spec!r}'
        )

    merged = copy.deepcopy(generated)
    prepared_manual = prepare_manual_document(merged, manual, version)

    merged['components'] = merge_unique_objects(
        merged.get('components', []),
        prepared_manual.get('components', []),
        collection_name='components',
    )

    generated_services = merged.get('services', [])
    manual_services = prepared_manual.get('services', [])
    if generated_services or manual_services:
        merged['services'] = merge_unique_objects(
            generated_services,
            manual_services,
            collection_name='services',
        )
    else:
        merged.pop('services', None)

    merged['dependencies'] = merge_dependencies(
        merged.get('dependencies', []),
        prepared_manual.get('dependencies', []),
    )
    merge_properties(merged, prepared_manual)

    if 'serialNumber' in generated:
        merged['serialNumber'] = generated['serialNumber']
        merged['version'] = int(generated.get('version', 1)) + 1
    else:
        merged['serialNumber'] = f'urn:uuid:{uuid.uuid4()}'
        merged['version'] = 1

    validate_references(merged)
    return merged


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument('--generated', required=True, type=Path)
    parser.add_argument('--manual', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--trustpoint-version')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    generated = load_json(args.generated)
    manual = load_json(args.manual)
    merged = merge_cboms(generated, manual, args.trustpoint_version)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(merged, indent=2) + '\n', encoding='utf-8')
    print(
        f"Wrote {args.output} with {len(merged.get('components', []))} components "
        f"and {len(merged.get('dependencies', []))} dependency entries."
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
