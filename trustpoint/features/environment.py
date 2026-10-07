# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Environment hooks for Trustpoint Behave tests."""

from __future__ import annotations

from behave import runner
from django.conf import settings


def before_all(_context: runner.Context) -> None:
    """Use the same local crypto-test configuration as the existing pytest helpers."""
    settings.DEVELOPMENT_ENV = True
    settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True
    settings.TRUSTPOINT_IS_OPERATIONAL = True
    settings.DOCKER_CONTAINER = False


def before_scenario(context: runner.Context, _scenario: object) -> None:
    """Ensure state from a previous scenario cannot leak into the next one."""
    for name in (
        'response',
        'authenticated_client',
        'api_client',
        'api_token',
        'domain',
        'device',
        'issuing_ca',
        'service_account',
        'service_credential',
        'service_secret',
    ):
        if hasattr(context, name):
            delattr(context, name)
