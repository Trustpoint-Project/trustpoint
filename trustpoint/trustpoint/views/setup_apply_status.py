# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Complete the setup progress protocol in the operational runtime."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.http import JsonResponse
from django.views import View

if TYPE_CHECKING:
    from django.http import HttpRequest


class CompletedSetupApplyStatusView(View):
    """Report success at the same URL polled during bootstrap setup."""

    http_method_names = ('get',)

    def get(self, _request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        """Return the terminal setup state expected by the bootstrap progress page."""
        del args, kwargs
        response = JsonResponse(
            {
                'state': 'complete',
                'stage': 'complete',
                'detail': 'Trustpoint setup completed successfully.',
                'progress': 100,
                'history': [],
                'activity': [],
            }
        )
        response['Cache-Control'] = 'no-store'
        return response
