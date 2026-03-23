"""Views for creating and registering new devices."""

from typing import Any

from django import forms
from django.contrib import messages
from django.http import HttpResponse, HttpResponseBase
from django.http.request import HttpRequest
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy
from django.views.generic.base import RedirectView, TemplateView
from django.views.generic.edit import FormView

from devices.forms import (
    NoOnboardingCreateForm,
    OnboardingCreateForm,
    OpcUaGdsPushCreateForm,
)

# noinspection PyUnresolvedReferences
from devices.models import (
    DeviceModel,
)
from management.models import KeyStorageConfig
from management.models.audit_log import AuditLog
from trustpoint.page_context import (
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    DEVICES_PAGE_OPC_UA_SUBCATEGORY,
    PageContextMixin,
)

DeviceWithoutDomainErrorMsg = gettext_lazy('Device does not have an associated domain.')
NamedCurveMissingForEccErrorMsg = gettext_lazy('Failed to retrieve named curve for ECC algorithm.')
ActiveTrustpointTlsServerCredentialModelMissingErrorMsg = gettext_lazy(
    'No active trustpoint TLS server credential found.'
)

# This only occurs if no domain is configured
PublicKeyInfoMissingErrorMsg = DeviceWithoutDomainErrorMsg

class AbstractCreateChooseOnboaringView(PageContextMixin, TemplateView):
    """Abstract view for choosing if the new device shall be onboarded or not."""

    http_method_names = ('get',)
    template_name = 'devices/create_choose_onboarding.html'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the cancel url href according to the subcategory.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to use for rendering the devices page.
        """
        context = super().get_context_data(**kwargs)
        context['cancel_create_url'] = f'devices:{self.page_name}'
        context['use_onboarding_url'] = f'{self.page_category}:{self.page_name}_create_onboarding'
        context['use_no_onboarding_url'] = f'{self.page_category}:{self.page_name}_create_no_onboarding'
        context['use_opc_ua_gds_push_url'] = f'{self.page_category}:{self.page_name}_create_opc_ua_gds_push'
        context['show_opc_ua_gds_push_option'] = False  # Default: don't show GDS Push option
        return context


class DeviceCreateChooseOnboardingView(AbstractCreateChooseOnboaringView):
    """View for choosing if the new device shall be onboarded or not."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the cancel url href according to the subcategory.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to use for rendering the devices page.
        """
        context = super().get_context_data(**kwargs)
        # Enable OPC UA GDS Push option for standard devices
        context['show_opc_ua_gds_push_option'] = True
        return context


class OpcUaGdsCreateChooseOnboardingView(AbstractCreateChooseOnboaringView):
    """View for choosing if the new OPC UA GDS shall be onboarded or not."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the cancel url href according to the subcategory.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to use for rendering the devices page.
        """
        context = super().get_context_data(**kwargs)
        # Remove no-onboarding and OPC UA GDS Push options for OPC UA GDS
        context.pop('use_no_onboarding_url', None)
        context['show_opc_ua_gds_push_option'] = False
        return context

class OpcUaGdsPushCreateChooseOnboardingView(RedirectView):
    """Deprecated: Redirects to standard devices create page."""

    permanent = True
    pattern_name = 'devices:devices_create'


class AbstractCreateAddOnboardingTypeView(PageContextMixin, TemplateView):
    """Abstract view for choosing how new device shall be added."""

    http_method_names = ('get',)
    template_name = 'devices/add_onboarding_type.html'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the cancel url href according to the subcategory.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to use for rendering the devices page.
        """
        context = super().get_context_data(**kwargs)
        context['cancel_create_url'] = f'devices:{self.page_name}'
        context['use_onboarding_url_name'] = 'pki:devid_registration-method_select'
        context['use_no_onboarding_url'] = f'{self.page_category}:{self.page_name}_create_no_onboarding'
        return context


class DeviceCreateAddOnboardingTypeView(AbstractCreateAddOnboardingTypeView):
    """View for choosing how new device shall be added."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY




class AbstractCreateNoOnboardingView(PageContextMixin, FormView[NoOnboardingCreateForm]):
    """asdfds."""

    http_method_names = ('get', 'post')

    form_class = NoOnboardingCreateForm
    template_name = 'devices/create.html'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the cancel url href according to the subcategory.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to use for rendering the devices page.
        """
        context = super().get_context_data(**kwargs)
        context['cancel_create_url'] = f'{self.page_category}:{self.page_name}'
        return context

    def form_valid(self, form: NoOnboardingCreateForm) -> HttpResponse:
        """Saves the form / creates the device model object.

        Args:
            form: The valid form.

        Returns:
            The HTTP Response to be returned.
        """
        if self.page_name == DEVICES_PAGE_DEVICES_SUBCATEGORY:
            self.object = form.save(device_type=DeviceModel.DeviceType.GENERIC_DEVICE)
        else:
            self.object = form.save(device_type=DeviceModel.DeviceType.OPC_UA_GDS)

        actor = self.request.user if self.request.user.is_authenticated else None
        AuditLog.create_entry(
            operation_type=AuditLog.OperationType.DEVICE_ADDED,
            target=self.object,
            target_display=f'Device: {self.object.common_name}',
            actor=actor,
        )

        return super().form_valid(form)

    def get_success_url(self) -> str:
        """Gets the success url to redirect to after successful processing of the POST data following a form submit.

        Returns:
            The success url to redirect to after successful processing of the POST data following a form submit.
        """
        return str(
            reverse_lazy(
                f'{self.page_category}:{self.page_name}_certificate_lifecycle_management', kwargs={'pk': self.object.id}
            )
        )


class DeviceCreateNoOnboardingView(AbstractCreateNoOnboardingView):
    """Create form view for the devices section."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsCreateNoOnboardingView(AbstractCreateNoOnboardingView):
    """Create form view for the devices section."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class AbstractCreateOnboardingView(PageContextMixin, FormView[forms.Form]):
    """asdfds."""

    http_method_names = ('get', 'post')

    form_class: type[forms.Form] = OnboardingCreateForm
    template_name = 'devices/create.html'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the cancel url href according to the subcategory.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to use for rendering the devices page.
        """
        context = super().get_context_data(**kwargs)
        context['cancel_create_url'] = f'{self.page_category}:{self.page_name}'
        return context

    def form_valid(self, form: forms.Form) -> HttpResponse:
        """Saves the form / creates the device model object.

        Args:
            form: The valid form.

        Returns:
            The HTTP Response to be returned.
        """
        if self.page_name == DEVICES_PAGE_DEVICES_SUBCATEGORY:
            self.object = form.save(device_type=DeviceModel.DeviceType.GENERIC_DEVICE)  # type: ignore[attr-defined]
        elif self.page_name == DEVICES_PAGE_OPC_UA_SUBCATEGORY:
            self.object = form.save(device_type=DeviceModel.DeviceType.OPC_UA_GDS)  # type: ignore[attr-defined]
        else:  # DEVICES_PAGE_DEVICES_SUBCATEGORY
            self.object = form.save(device_type=DeviceModel.DeviceType.OPC_UA_GDS_PUSH)  # type: ignore[attr-defined]

        actor = self.request.user if self.request.user.is_authenticated else None
        AuditLog.create_entry(
            operation_type=AuditLog.OperationType.DEVICE_ADDED,
            target=self.object,
            target_display=f'Device: {self.object.common_name}',
            actor=actor,
        )

        return super().form_valid(form)

    def get_success_url(self) -> str:
        """Gets the success url to redirect to after successful processing of the POST data following a form submit.

        Returns:
            The success url to redirect to after successful processing of the POST data following a form submit.
        """
        return str(
            reverse_lazy(
                f'{self.page_category}:{self.page_name}_certificate_lifecycle_management', kwargs={'pk': self.object.id}
            )
        )


class DeviceCreateOnboardingView(AbstractCreateOnboardingView):
    """Create form view for the devices section."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class DeviceCreateOpcUaGdsPushView(AbstractCreateOnboardingView):
    """Create form view for OPC UA GDS Push devices in the devices section."""

    form_class = OpcUaGdsPushCreateForm
    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Check if SOFTWARE storage is configured before allowing GDS Push creation.

        Args:
            request: The HTTP request object.
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            HttpResponseBase: The response object.
        """
        try:
            config = KeyStorageConfig.get_config()
            if config.storage_type != KeyStorageConfig.StorageType.SOFTWARE:
                messages.error(
                    request,
                    f'OPC UA GDS Push is only available with SOFTWARE key storage. '
                    f'Current storage type: {config.get_storage_type_display()}'
                )
                return redirect('devices:devices')
        except KeyStorageConfig.DoesNotExist:
            messages.error(
                request,
                'Key storage configuration not found. Please configure key storage first.'
            )
            return redirect('devices:devices')

        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form: forms.Form) -> HttpResponse:
        """Saves the form / creates the device model object as OPC UA GDS Push type.

        Args:
            form: The valid form.

        Returns:
            The HTTP Response to be returned.
        """
        self.object = form.save(device_type=DeviceModel.DeviceType.OPC_UA_GDS_PUSH)  # type: ignore[attr-defined]

        actor = self.request.user if self.request.user.is_authenticated else None
        AuditLog.create_entry(
            operation_type=AuditLog.OperationType.DEVICE_ADDED,
            target=self.object,
            target_display=f'Device: {self.object.common_name}',
            actor=actor,
        )

        return FormView.form_valid(self, form)


class OpcUaGdsCreateOnboardingView(AbstractCreateOnboardingView):
    """Create form view for the devices section."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class OpcUaGdsPushCreateOnboardingView(RedirectView):
    """Deprecated: Redirects to standard devices OPC UA GDS Push create page."""

    permanent = True
    pattern_name = 'devices:devices_create_opc_ua_gds_push'
