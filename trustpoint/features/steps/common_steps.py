# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Common Behave steps shared across capabilities."""

from __future__ import annotations

from behave import given, runner, then
from django.test import Client

from features.support.assertions import assert_contains_text, assert_status
from features.support.auth import create_admin_client


@given('the Trustpoint web application is running')
@given('the TPC_Web application is running')
def step_web_running(context: runner.Context) -> None:
    """Verify the login endpoint is reachable."""
    context.response = Client().get('/users/login/')
    assert_status(context.response, 200)


@given('the admin user is logged into Trustpoint')
@given('the admin user is logged into TPC_Web')
def step_admin_logged_in(context: runner.Context) -> None:
    """Create and authenticate an administrator."""
    context.admin_user, context.authenticated_client = create_admin_client()


@then('the response status code is {status_code:d}')
def step_response_status(context: runner.Context, status_code: int) -> None:
    """Assert the most recent response status."""
    assert_status(context.response, status_code)


@then('the response contains "{text}"')
def step_response_contains(context: runner.Context, text: str) -> None:
    """Assert rendered response text."""
    assert_contains_text(context.response, text)


@then('the system should display a confirmation message stating "{message}"')
def step_confirmation_message(context: runner.Context, message: str) -> None:
    """Retain the legacy confirmation-message wording."""
    assert_contains_text(context.response, message)
