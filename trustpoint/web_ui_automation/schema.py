# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""JSON schema and validation helpers for Web UI automation profiles."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urlsplit

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from jsonschema import Draft202012Validator

PROFILE_SCHEMA_ID = 'trustpoint.web-automation.v1'
SUPPORTED_OPERATIONS = frozenset({'onboard', 'renew', 'inventory'})
SUPPORTED_ACTIONS = frozenset(
    {
        'assert_attribute',
        'assert_enabled',
        'assert_hidden',
        'assert_text',
        'assert_url',
        'assert_visible',
        'check',
        'click',
        'click_if_visible',
        'commit_configuration',
        'compare_fingerprint',
        'download',
        'extract_attribute',
        'extract_text',
        'fill',
        'focus',
        'go_back',
        'goto',
        'hover',
        'press',
        'reboot_device',
        'reload',
        'restart_service',
        'select',
        'uncheck',
        'upload',
        'verify_tls_certificate',
        'wait_for',
        'wait_for_download',
        'wait_for_navigation',
        'wait_for_network_idle',
    }
)
ALLOWED_SECRET_PLACEHOLDERS = frozenset(
    {
        '{{ device_password }}',
        '{{ device_username }}',
        '{{ private_key_password }}',
    }
)

STEP_SCHEMA: dict[str, Any] = {
    'type': 'object',
    'required': ['id', 'action'],
    'properties': {
        'id': {'type': 'string', 'minLength': 1, 'maxLength': 120},
        'action': {'type': 'string', 'enum': sorted(SUPPORTED_ACTIONS)},
        'path_ref': {'type': 'string', 'minLength': 1, 'maxLength': 120},
        'selector': {'type': 'string', 'minLength': 1, 'maxLength': 2000},
        'target': {'type': 'object'},
        'value': {'type': ['string', 'number', 'boolean']},
        'artifact': {'type': 'string'},
        'key': {'type': 'string', 'minLength': 1, 'maxLength': 80},
        'output': {'type': 'string', 'minLength': 1, 'maxLength': 120},
        'timeout_ms': {'type': 'integer', 'minimum': 1, 'maximum': 300000},
        'sensitive': {'type': 'boolean'},
        'expected_fingerprint': {'type': 'string'},
        'expected': {'type': ['string', 'number', 'boolean']},
        'attribute': {'type': 'string'},
        'state': {'type': 'string'},
        'force': {'type': 'boolean'},
        'description': {'type': 'string'},
    },
    'additionalProperties': False,
}

OPERATION_SCHEMA: dict[str, Any] = {
    'type': 'object',
    'required': ['steps'],
    'properties': {
        'steps': {'type': 'array', 'items': STEP_SCHEMA, 'minItems': 1},
        'postconditions': {'type': 'array', 'items': STEP_SCHEMA},
    },
    'additionalProperties': False,
}

PROFILE_SCHEMA: dict[str, Any] = {
    '$schema': 'https://json-schema.org/draft/2020-12/schema',
    'type': 'object',
    'required': [
        'schema',
        'name',
        'version',
        'metadata',
        'certificate_profile',
        'key_generation',
        'encoding',
        'paths',
        'operations',
    ],
    'properties': {
        'schema': {'const': PROFILE_SCHEMA_ID},
        'name': {'type': 'string', 'minLength': 1, 'maxLength': 200},
        'version': {'type': 'string', 'minLength': 1, 'maxLength': 40},
        'metadata': {
            'type': 'object',
            'required': ['vendor', 'device_family'],
            'properties': {
                'vendor': {'type': 'string', 'minLength': 1, 'maxLength': 200},
                'device_family': {'type': 'string', 'minLength': 1, 'maxLength': 200},
                'firmware_hint': {'type': 'string', 'maxLength': 200},
                'description': {'type': 'string', 'maxLength': 2000},
            },
            'additionalProperties': False,
        },
        'certificate_profile': {'type': 'string', 'minLength': 1, 'maxLength': 255},
        'key_generation': {'const': 'trustpoint'},
        'encoding': {'enum': ['PEM', 'PKCS12']},
        'paths': {
            'type': 'object',
            'minProperties': 1,
            'additionalProperties': {'type': 'string', 'minLength': 1, 'maxLength': 2000},
        },
        'inputs': {'type': 'object'},
        'operations': {
            'type': 'object',
            'required': ['onboard'],
            'properties': {
                'onboard': OPERATION_SCHEMA,
                'renew': OPERATION_SCHEMA,
                'inventory': OPERATION_SCHEMA,
            },
            'additionalProperties': False,
        },
    },
    'additionalProperties': False,
}

_VALIDATOR = Draft202012Validator(PROFILE_SCHEMA)


def canonical_profile_json(profile: dict[str, Any]) -> str:
    """Return a deterministic JSON representation of a profile."""
    return json.dumps(profile, ensure_ascii=True, separators=(',', ':'), sort_keys=True)


def calculate_profile_checksum(profile: dict[str, Any]) -> str:
    """Calculate a SHA-256 checksum for a profile."""
    return hashlib.sha256(canonical_profile_json(profile).encode()).hexdigest()


def get_certificate_profile_slug(profile: dict[str, Any]) -> str:
    """Return the certificate-profile slug declared by a profile."""
    value = profile.get('certificate_profile')
    return value if isinstance(value, str) else ''


def profile_supports_operation(profile: dict[str, Any], operation: str) -> bool:
    """Return whether the profile declares an operation."""
    operations = profile.get('operations')
    return isinstance(operations, dict) and operation in operations


def validate_profile_schema(profile: dict[str, Any]) -> None:
    """Validate schema and Trustpoint-specific profile invariants.

    Raises:
        ValidationError: If the profile is malformed or unsafe.
    """
    errors = sorted(_VALIDATOR.iter_errors(profile), key=lambda error: list(error.absolute_path))
    if errors:
        messages = []
        for error in errors:
            path = '.'.join(str(part) for part in error.absolute_path) or '<root>'
            messages.append(f'{path}: {error.message}')
        raise ValidationError({'profile': messages})

    paths = profile['paths']
    for name, path in paths.items():
        _validate_relative_path(name, path)

    operations = profile['operations']
    for operation_name, operation in operations.items():
        _validate_operation(operation_name, operation, paths)


def _validate_relative_path(name: str, path: str) -> None:
    """Validate that a named path is relative to the configured device base URL."""
    split = urlsplit(path)
    if split.scheme or split.netloc:
        raise ValidationError({'profile': [_('Path %(name)s must be relative.') % {'name': name}]})
    if not path.startswith('/'):
        raise ValidationError({'profile': [_('Path %(name)s must start with /.') % {'name': name}]})
    if split.fragment:
        raise ValidationError({'profile': [_('Path %(name)s must not contain a fragment.') % {'name': name}]})


def _validate_operation(operation_name: str, operation: dict[str, Any], paths: dict[str, str]) -> None:
    """Validate operation-level references and secret handling."""
    seen_step_ids: set[str] = set()
    all_steps = [*operation['steps'], *operation.get('postconditions', [])]
    for step in all_steps:
        step_id = step['id']
        if step_id in seen_step_ids:
            raise ValidationError(
                {'profile': [_('Duplicate step ID %(step_id)s in %(operation)s.') % {
                    'step_id': step_id,
                    'operation': operation_name,
                }]}
            )
        seen_step_ids.add(step_id)

        if step['action'] == 'goto':
            path_ref = step.get('path_ref')
            if not path_ref or path_ref not in paths:
                raise ValidationError(
                    {'profile': [_('Step %(step_id)s references an unknown path.') % {'step_id': step_id}]}
                )

        if step.get('sensitive') is True:
            value = step.get('value')
            if isinstance(value, str) and value not in ALLOWED_SECRET_PLACEHOLDERS:
                raise ValidationError(
                    {'profile': [_('Sensitive step %(step_id)s must use a secret placeholder.') % {
                        'step_id': step_id,
                    }]}
                )
