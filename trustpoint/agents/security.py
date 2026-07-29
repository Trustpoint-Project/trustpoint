# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Security utilities for the agents application."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.contrib import messages
from django.http import HttpResponseRedirect
from django.urls import reverse_lazy

from onboarding.enums import OnboardingProtocol
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse


class AgentSecurity(LoggerMixin):
    """Helper class for checking agent-related security policies."""

    @staticmethod
    def is_agent_protocol_permitted() -> bool:
        """Check if the AGENT onboarding protocol is permitted by the active security configuration.

        Returns:
            True if AGENT protocol is permitted, False otherwise.
        """
        from management.models import SecurityConfig  # noqa: PLC0415

        try:
            cfg: SecurityConfig = SecurityConfig.objects.get()
        except SecurityConfig.DoesNotExist:
            return True
        except SecurityConfig.MultipleObjectsReturned:
            cfg = SecurityConfig.objects.first()  # type: ignore[assignment]

        permitted: list[int] = cfg.permitted_onboarding_protocols or []
        return OnboardingProtocol.AGENT.value in permitted


class AgentSecurityMixin(LoggerMixin):
    """Mixin for views that require the AGENT protocol to be permitted."""

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Check if AGENT protocol is permitted before dispatching the view."""
        if not AgentSecurity.is_agent_protocol_permitted():
            self.logger.warning(
                'Access denied to agent functionality: AGENT protocol not permitted by security configuration.'
            )
            messages.error(
                request,
                'Agent functionality is disabled by the current security configuration.',
            )
            return HttpResponseRedirect(reverse_lazy('devices:list'))
        return super().dispatch(request, *args, **kwargs)  # type: ignore[misc]
