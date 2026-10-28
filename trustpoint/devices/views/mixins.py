# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared device selection for bulk actions."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.contrib import messages
from django.utils.translation import gettext_lazy

from devices.models import DeviceModel
from trustpoint.logger import LoggerMixin
from util.mult_obj_views import get_primary_keys_from_str_as_list_of_ints

if TYPE_CHECKING:
    from django.db.models import QuerySet
    from django.http import HttpRequest
    from django_stubs_ext import StrPromise


class DeviceBulkSelectionMixin(LoggerMixin):
    """Load selected devices and report invalid or missing primary keys."""

    pks: str
    missing: str
    kwargs: dict[str, Any]
    queryset: QuerySet[DeviceModel] | None
    selection_required_message: str | StrPromise

    def get_queryset(self) -> QuerySet[DeviceModel]:
        """Load the requested devices and remember any missing primary keys."""
        if not self.pks:
            self.pks = self.kwargs.get('pks', '')
        requested_pks = get_primary_keys_from_str_as_list_of_ints(pks=self.pks)
        queryset = DeviceModel.objects.filter(pk__in=requested_pks)
        missing = set(requested_pks) - set(queryset.values_list('pk', flat=True))
        self.missing = ', '.join(str(pk) for pk in missing)
        return queryset

    def _set_queryset(self, request: HttpRequest) -> str | None:
        """Return the redirect route when selection cannot be used for the action."""
        try:
            self.queryset = self.get_queryset()
        except ValueError:
            messages.error(request, self.selection_required_message)
            return 'devices:devices'
        except Exception:
            error = gettext_lazy(
                f'Failed to retrieve the queryset for primary keys: {self.pks}.See logs for more details.'
            )
            self.logger.exception(error)
            messages.error(request, error)
            return 'devices:devices'

        if self.missing:
            error = gettext_lazy(f'Devices for the following primary keys were not found: {self.pks}.')
            messages.error(request, error.format(pks=self.missing))
            return 'devices:devices'
        return None
