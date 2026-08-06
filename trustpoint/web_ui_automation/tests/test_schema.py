# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for Web UI automation profile validation."""

from __future__ import annotations

import copy

import pytest
from django.core.exceptions import ValidationError

from web_ui_automation.schema import calculate_profile_checksum, validate_profile_schema


@pytest.fixture
def valid_profile() -> dict[str, object]:
    """Return a minimal valid Phase 1 profile."""
    return {
        'schema': 'trustpoint.web-automation.v1',
        'name': 'Test profile',
        'version': '1.0.0',
        'metadata': {'vendor': 'Vendor', 'device_family': 'Firewall'},
        'certificate_profile': 'firewall-management-tls',
        'key_generation': 'trustpoint',
        'encoding': 'PEM',
        'paths': {'login': '/login'},
        'operations': {
            'onboard': {
                'steps': [{'id': 'open-login', 'action': 'goto', 'path_ref': 'login'}]
            }
        },
    }


def test_valid_profile_is_accepted(valid_profile: dict[str, object]) -> None:
    """Accept a minimal valid profile."""
    validate_profile_schema(valid_profile)


def test_absolute_path_is_rejected(valid_profile: dict[str, object]) -> None:
    """Reject profile paths that can escape the configured device origin."""
    profile = copy.deepcopy(valid_profile)
    profile['paths'] = {'login': 'https://example.com/login'}
    with pytest.raises(ValidationError):
        validate_profile_schema(profile)


def test_sensitive_literal_is_rejected(valid_profile: dict[str, object]) -> None:
    """Reject literal values in steps marked as sensitive."""
    profile = copy.deepcopy(valid_profile)
    profile['operations']['onboard']['steps'].append(
        {
            'id': 'password',
            'action': 'fill',
            'selector': '#password',
            'value': 'plaintext-password',
            'sensitive': True,
        }
    )
    with pytest.raises(ValidationError):
        validate_profile_schema(profile)


def test_checksum_is_stable_across_key_order(valid_profile: dict[str, object]) -> None:
    """Produce the same checksum for semantically identical JSON key order."""
    reordered = dict(reversed(list(valid_profile.items())))
    assert calculate_profile_checksum(valid_profile) == calculate_profile_checksum(reordered)
