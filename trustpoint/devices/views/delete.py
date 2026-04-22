"""Views for device and certificate deletion."""

from typing import Any

from django.contrib import messages
from django.db.models import QuerySet
from django.http import HttpResponse
from django.http.request import HttpRequest
from django.shortcuts import redirect
from django.utils.translation import gettext_lazy
from django.views.generic.list import ListView

from devices.forms import (
    DeleteDevicesForm,
)

# noinspection PyUnresolvedReferences
from devices.models import (
    DeviceModel,
)
from management.models.audit_log import AuditLog
from trustpoint.logger import LoggerMixin
from trustpoint.page_context import (
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    DEVICES_PAGE_OPC_UA_SUBCATEGORY,
    PageContextMixin,
)
from util.mult_obj_views import get_primary_keys_from_str_as_list_of_ints

DeviceWithoutDomainErrorMsg = gettext_lazy('Device does not have an associated domain.')
NamedCurveMissingForEccErrorMsg = gettext_lazy('Failed to retrieve named curve for ECC algorithm.')
ActiveTrustpointTlsServerCredentialModelMissingErrorMsg = gettext_lazy(
    'No active trustpoint TLS server credential found.'
)

# This only occurs if no domain is configured
PublicKeyInfoMissingErrorMsg = DeviceWithoutDomainErrorMsg

class AbstractBulkDeleteView(LoggerMixin, PageContextMixin, ListView[DeviceModel]):
    """View to confirm the deletion of multiple Devices."""

    model = DeviceModel
    template_name = 'devices/confirm_delete.html'
    context_object_name = 'devices'

    missing: str = ''
    pks: str = ''
    queryset: QuerySet[DeviceModel]
    form_class = DeleteDevicesForm

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the primary keys to the context.

        Args:
            kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data.
        """
        context = super().get_context_data(**kwargs)
        context['pks'] = self.pks
        context['delete_form'] = self.form_class(initial={'pks': self.pks})
        context['device_delete_url'] = f'{self.page_category}:{self.page_name}_device_delete'
        return context

    def get_queryset(self) -> QuerySet[DeviceModel]:
        """Gets the queryset of DeviceModel objects that are requested to be deleted.

        Returns:
            The queryset of DeviceModel objects that are requested to be deleted.
        """
        if not self.pks:
            self.pks = self.kwargs.get('pks', '')
        pks_list = get_primary_keys_from_str_as_list_of_ints(pks=self.pks)
        qs = DeviceModel.objects.filter(pk__in=pks_list)

        found_pks = set(qs.values_list('pk', flat=True))
        missing = set(pks_list) - found_pks

        self.missing = ', '.join(str(pk) for pk in missing)

        return qs

    def _set_queryset(self, request: HttpRequest) -> str | None:
        try:
            self.queryset = self.get_queryset()
        except ValueError:
            err_msg_template = gettext_lazy('Please select the devices you would like to delete.')
            err_msg = err_msg_template.format(pks=self.pks)
            messages.error(request, err_msg)
            return 'devices:devices'
        except Exception:
            err_msg_template = gettext_lazy(
                f'Failed to retrieve the queryset for primary keys: {self.pks}.See logs for more details.'
            )
            err_msg = err_msg_template.format(pks=self.pks)
            self.logger.exception(err_msg)
            messages.error(request, err_msg)
            return 'devices:devices'

        if self.missing:
            err_msg_template = gettext_lazy(f'Devices for the following primary keys were not found: {self.pks}.')
            err_msg = err_msg_template.format(pks=self.missing)
            messages.error(request, err_msg)
            return 'devices:devices'

        return None

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """HTTP GET processing.

        Args:
            request: The Django request object.
            *args: Positional arguments passed to super().get().
            **kwargs: Keyword arguments passed to super().get().

        Returns:
            The device deletion view or a redirect to the devices view if one or more pks were not found.
        """
        redirect_name = self._set_queryset(request)
        if redirect_name:
            return redirect(redirect_name)
        messages.warning(
            request, gettext_lazy('This operation will revoke ALL certificates associated with the selected devices.')
        )
        return super().get(request, *args, **kwargs)

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """HTTP POST processing which will try to delete all requested DeviceModel records.

        Args:
            request: The Django request object.
            *_args: Positional arguments are discarded.
            **_kwargs: Keyword arguments are discarded.

        Returns:
            Redirect to the devices summary.
        """
        delete_form = self.form_class(self.request.POST)
        if delete_form.is_valid():
            self.pks = delete_form.cleaned_data['pks']
            redirect_name = self._set_queryset(request)
            if redirect_name:
                return redirect(redirect_name)

        try:
            devices_to_delete = list(self.queryset)
            count, _ = self.queryset.delete()
            actor = request.user if request.user.is_authenticated else None
            for device in devices_to_delete:
                AuditLog.create_entry(
                    operation_type=AuditLog.OperationType.DEVICE_DELETED,
                    target=device,
                    target_display=f'Device: {device.common_name}',
                    actor=actor,
                )
            success_msg_template = gettext_lazy(
                'Successfully deleted {count} devices. All corresponding certificates have been revoked.'
            )
            success_msg = success_msg_template.format(count=count)
            messages.success(request, success_msg)
        except Exception:
            err_msg = 'Failed to delete DeviceModel records.'
            self.logger.exception(err_msg)
            messages.error(
                request, gettext_lazy('Failed to delete DeviceModel records. See logs for more information.')
            )

        return redirect('devices:devices')


class DeviceBulkDeleteView(AbstractBulkDeleteView):
    """abc."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsBulkDeleteView(AbstractBulkDeleteView):
    """abc."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY

class OpcUaGdsPushBulkDeleteView(AbstractBulkDeleteView):
    """abc."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
