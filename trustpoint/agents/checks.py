# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Deployment checks for the agents application."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.core.checks import Warning as CheckWarning
from django.core.checks import register
from django.core.exceptions import ValidationError
from django.db import DatabaseError

from agents.models import AgentProfileDefinition, is_literal_password_step

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from django.apps import AppConfig
    from django.core.checks import CheckMessage


@register()
def literal_password_steps(
    *,
    app_configs: Sequence[AppConfig] | None = None,
    databases: Sequence[str] | None = None,
    **kwargs: Any,
) -> Iterable[CheckMessage]:
    """Warn when a profile still has a literal password value."""
    del app_configs, databases, kwargs
    try:
        profiles = AgentProfileDefinition.objects.defer('secrets')
        unsafe = 0
        for profile in profiles:
            if not isinstance(profile.profile, dict):
                continue
            steps = profile.profile.get('steps')
            if not isinstance(steps, list):
                continue
            if any(isinstance(step, dict) and is_literal_password_step(step) for step in steps):
                unsafe += 1
    except (DatabaseError, ValidationError):
        # During migrations the table may not exist yet; skip the check.
        return []

    if unsafe:
        return [
            CheckWarning(
                f'{unsafe} agent profile(s) still contain literal password values. '
                'Run "python manage.py encrypt_agent_profile_secrets".',
                id='agents.W001',
            )
        ]
    return []
