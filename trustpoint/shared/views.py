# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""This module contains all view-related functionality used throughout the project."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import ProtectedError
from django.http import HttpResponse, HttpResponseRedirect

from management.security_change_audit import audit_security_change, snapshot_security_state
from trustpoint.views.base import BulkDeleteView

if TYPE_CHECKING:
    from django.forms import Form
    from django_stubs_ext import StrPromise


class AuditedBulkDeleteView(BulkDeleteView):
    """Delete security objects atomically with permission checks and audit entries."""

    delete_permission: str
    protected_error_message: str | StrPromise
    delete_success_message: str | StrPromise

    def form_valid(self, form: Form) -> HttpResponse:
        """Lock and snapshot selected objects, then delete and audit them together."""
        if not self.request.user.has_perm(self.delete_permission):
            raise PermissionDenied
        queryset = self.get_queryset()
        deleted_count = queryset.count()

        try:
            with transaction.atomic():
                targets = list(queryset.select_for_update())
                snapshots = [(target, snapshot_security_state(target)) for target in targets]
                response = super().form_valid(form)
                for target, before in snapshots:
                    audit_security_change(target=target, actor=self.request.user, before=before, action='deleted')
        except ProtectedError:
            messages.error(self.request, self.protected_error_message)
            return HttpResponseRedirect(self.get_success_url())
        except ValidationError as exc:
            messages.error(self.request, exc.message)
            return HttpResponseRedirect(self.get_success_url())

        messages.success(self.request, str(self.delete_success_message).format(count=deleted_count))
        return response
