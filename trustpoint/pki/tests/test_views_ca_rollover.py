# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for CA rollover view orchestration."""

from __future__ import annotations

from http import HTTPStatus
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from django.http import HttpResponse
from django.test import RequestFactory

from pki.models.ca_rollover import CaRolloverStrategyType
from pki.services.ca_rollover import CaRolloverError
from pki.views.ca_rollover import (
    CancelRolloverView,
    CompleteRolloverView,
    PlanRolloverView,
    StartRolloverView,
    TransitionRolloverView,
)


def request(method: str = 'post', **data: str) -> object:
    """Build a request with an authenticated operator."""
    factory = RequestFactory()
    test_request = getattr(factory, method)('/ca/rollover/', data=data)
    test_request.user = SimpleNamespace(is_authenticated=True)
    return test_request


@pytest.mark.parametrize('value', ['bad', ''])
def test_plan_rejects_invalid_strategy(value: str) -> None:
    """Planning rejects strategy values outside the registered enum."""
    view = PlanRolloverView()
    with (
        patch('pki.views.ca_rollover.get_object_or_404', return_value=Mock()),
        patch('pki.views.ca_rollover.redirect', return_value=HttpResponse(status=302)) as redirect,
        patch('pki.views.ca_rollover.messages.error') as error,
    ):
        response = view.post(request(strategy_type=value), pk=4)

    assert response.status_code == HTTPStatus.FOUND
    error.assert_called_once()
    redirect.assert_called_once_with('pki:issuing_cas-config', pk=4)


def test_plan_rejects_unavailable_strategy() -> None:
    """Planning reports a registered enum whose implementation is unavailable."""
    with (
        patch('pki.views.ca_rollover.get_object_or_404', return_value=Mock()),
        patch('pki.views.ca_rollover.rollover_registry.get', side_effect=KeyError),
        patch('pki.views.ca_rollover.messages.error') as error,
        patch('pki.views.ca_rollover.redirect', return_value=HttpResponse(status=302)),
    ):
        response = PlanRolloverView().post(request(strategy_type=CaRolloverStrategyType.IMPORT_CA), pk=4)

    assert response.status_code == HTTPStatus.FOUND
    error.assert_called_once()


def test_plan_rejects_invalid_form() -> None:
    """Planning reports every form validation error and does not call the service."""
    strategy = Mock()
    strategy.get_plan_form.return_value = Mock(is_valid=Mock(return_value=False), errors={'new_ca': ['invalid']})
    with (
        patch('pki.views.ca_rollover.get_object_or_404', return_value=Mock()),
        patch('pki.views.ca_rollover.rollover_registry.get', return_value=strategy),
        patch('pki.views.ca_rollover.messages.error') as error,
        patch('pki.views.ca_rollover.redirect', return_value=HttpResponse(status=302)),
        patch('pki.views.ca_rollover.CaRolloverService.plan_rollover') as plan,
    ):
        response = PlanRolloverView().post(request(strategy_type=CaRolloverStrategyType.IMPORT_CA), pk=4)

    assert response.status_code == HTTPStatus.FOUND
    assert error.call_args.args[1] == 'invalid'
    plan.assert_not_called()


def test_plan_success_records_rollover() -> None:
    """A valid plan delegates to the service and emits success feedback."""
    strategy = Mock()
    form = Mock(is_valid=Mock(return_value=True))
    strategy.get_plan_form.return_value = form
    rollover = Mock(new_issuing_ca='new-ca')
    with (
        patch('pki.views.ca_rollover.get_object_or_404', return_value=Mock(unique_name='old-ca')),
        patch('pki.views.ca_rollover.rollover_registry.get', return_value=strategy),
        patch('pki.views.ca_rollover.CaRolloverService.plan_rollover', return_value=rollover) as plan,
        patch('pki.views.ca_rollover.AuditLog.create_entry') as audit,
        patch('pki.views.ca_rollover.messages.success') as success,
        patch('pki.views.ca_rollover.redirect', return_value=HttpResponse(status=302)),
    ):
        response = PlanRolloverView().post(request(strategy_type=CaRolloverStrategyType.IMPORT_CA), pk=4)

    assert response.status_code == HTTPStatus.FOUND
    plan.assert_called_once()
    success.assert_called_once()
    audit.assert_called_once()


@pytest.mark.parametrize(
    ('view_class', 'service_method', 'success_text'),
    [
        (StartRolloverView, 'execute_rollover', 'started'),
        (CompleteRolloverView, 'finalize_rollover', 'completed'),
        (CancelRolloverView, 'cancel_rollover', 'cancelled'),
    ],
)
def test_rollover_actions_success(view_class: type, service_method: str, success_text: str) -> None:
    """Start, complete, and cancel delegate and redirect on success."""
    rollover = Mock()
    service = patch(f'pki.views.ca_rollover.CaRolloverService.{service_method}')
    with (
        patch('pki.views.ca_rollover.get_object_or_404', return_value=rollover),
        service as operation,
        patch('pki.views.ca_rollover.messages.success') as success,
        patch('pki.views.ca_rollover.AuditLog.create_entry'),
        patch('pki.views.ca_rollover.redirect', return_value=HttpResponse(status=302)),
    ):
        response = view_class().post(request(), pk=4, rollover_pk=8)

    assert response.status_code == HTTPStatus.FOUND
    operation.assert_called_once_with(rollover)
    assert success.call_count == 1
    assert success_text in str(success.call_args.args[1]).lower()


@pytest.mark.parametrize(
    ('view_class', 'service_method'),
    [
        (StartRolloverView, 'execute_rollover'),
        (CompleteRolloverView, 'finalize_rollover'),
        (CancelRolloverView, 'cancel_rollover'),
    ],
)
def test_rollover_actions_report_service_error(view_class: type, service_method: str) -> None:
    """Lifecycle service errors become user feedback and preserve the redirect."""
    with (
        patch('pki.views.ca_rollover.get_object_or_404', return_value=Mock()),
        patch(f'pki.views.ca_rollover.CaRolloverService.{service_method}', side_effect=CaRolloverError('blocked')),
        patch('pki.views.ca_rollover.messages.error') as error,
        patch('pki.views.ca_rollover.redirect', return_value=HttpResponse(status=302)),
    ):
        response = view_class().post(request(), pk=4, rollover_pk=8)

    assert response.status_code == HTTPStatus.FOUND
    assert error.call_args.args[1] == 'blocked'


def test_transition_reports_invalid_state() -> None:
    """Transition catches invalid state errors from the rollover model."""
    rollover = Mock()
    rollover.transition_to_transition.side_effect = ValueError('wrong state')
    with (
        patch('pki.views.ca_rollover.get_object_or_404', return_value=rollover),
        patch('pki.views.ca_rollover.messages.error') as error,
        patch('pki.views.ca_rollover.redirect', return_value=HttpResponse(status=302)),
    ):
        response = TransitionRolloverView().post(request(), pk=4, rollover_pk=8)

    assert response.status_code == HTTPStatus.FOUND

    assert error.call_args.args[1] == 'wrong state'
