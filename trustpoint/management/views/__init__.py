# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Package that contains all Django Views of the management App."""

from __future__ import annotations

from django.views.generic.base import RedirectView

from management.views import audit_log, service_accounts

__all__ = ['audit_log', 'service_accounts']


class IndexView(RedirectView):
    """Index view."""

    permanent = True
    pattern_name = 'management:settings'
