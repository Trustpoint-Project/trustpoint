# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Custom DRF permission classes for the management API."""

from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.views import APIView


class IsSuperUser(BasePermission):
    """Allows access only to authenticated superusers.

    DRF analogue of :class:`trustpoint.views.base.SuperuserRequiredMixin`.
    """

    def has_permission(self, request: Request, _view: APIView) -> bool:
        """Return True if the requesting user is an authenticated superuser."""
        return bool(request.user and request.user.is_authenticated and request.user.is_superuser)
