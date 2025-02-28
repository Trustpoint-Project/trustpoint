from __future__ import annotations

import enum
from typing import Any, cast

from django.contrib import messages
from django.db.models import ProtectedError
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic import DeleteView
from django.views.generic.edit import CreateView, FormView, UpdateView
from django.views.generic.list import ListView

from pki.forms import DevIdAddMethodSelectForm, DevIdRegistrationForm
from pki.models import DevIdRegistration, DomainModel, IssuingCaModel
from pki.models.truststore import TruststoreModel
from trustpoint.settings import UIConfig
from trustpoint.views.base import (
    BulkDeleteView,
    ContextDataMixin,
    ListInDetailView,
    SortableTableMixin,
    no_login,
)


class PkiProtocol(enum.Enum):

    EST = 'est'
    CMP = 'cmp'
    REST = 'rest'
    SCEP = 'scep'
    ACME = 'acme'


class DomainContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'domains'


class DomainTableView(DomainContextMixin, SortableTableMixin, ListView):
    """Domain Table View."""

    model = DomainModel
    template_name = 'pki/domains/domain.html'  # Template file
    context_object_name = 'domain-new'
    paginate_by = UIConfig.paginate_by
    default_sort_param = 'unique_name'


class DomainCreateView(DomainContextMixin, CreateView):
    """View to create a new domain."""

    model = DomainModel
    fields = '__all__'
    template_name = 'pki/domains/add.html'
    success_url = reverse_lazy('pki:domains')
    ignore_url = reverse_lazy('pki:domains')

    def get_form(self, form_class: Any = None) -> Any:
        """Override get_form to filter out autogen root CAs."""
        form = super().get_form(form_class)
        # Filter out autogen root CAs
        form.fields['issuing_ca'].queryset = IssuingCaModel.objects.exclude(
            issuing_ca_type=IssuingCaModel.IssuingCaTypeChoice.AUTOGEN_ROOT
        ).filter(is_active=True)
        form.fields['issuing_ca'].empty_label = None # Remove empty "---------" choice
        del form.fields['is_active']
        return form


class DomainUpdateView(DomainContextMixin, UpdateView):
    """View to edit a domain."""

    # TODO(Air): This view is currently UNUSED.
    # If used, a mixin implementing the get_form method from the DomainCreateView should be added.

    model = DomainModel
    fields = '__all__'
    template_name = 'pki/domains/add.html'
    success_url = reverse_lazy('pki:domains')
    ignore_url = reverse_lazy('pki:domains')


class DomainDevIdRegistrationTableMixin(SortableTableMixin, ListInDetailView):

    model = DevIdRegistration
    paginate_by = UIConfig.paginate_by
    context_object_name = 'devid_registrations'
    default_sort_param = 'unique_name'

    def get_queryset(self):
        self.queryset = DevIdRegistration.objects.filter(domain=self.get_object())
        return super().get_queryset()


class DomainConfigView(DomainContextMixin, DomainDevIdRegistrationTableMixin, ListInDetailView):
    detail_model = DomainModel
    template_name = 'pki/domains/config.html'
    detail_context_object_name = 'domain'
    success_url = reverse_lazy('pki:domains')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        domain = self.get_object()

        context['protocols'] = {
            'cmp': domain.cmp_protocol if hasattr(domain, 'cmp_protocol') else None,
            'est': domain.est_protocol if hasattr(domain, 'est_protocol') else None,
            'acme': domain.acme_protocol if hasattr(domain, 'acme_protocol') else None,
            'scep': domain.scep_protocol if hasattr(domain, 'scep_protocol') else None,
            'rest': domain.rest_protocol if hasattr(domain, 'rest_protocol') else None
        }

        return context

    def post(self, request, *args, **kwargs):
        domain = self.get_object()

        active_protocols = request.POST.getlist('protocols')

        for protocol in PkiProtocol:
            protocol_name = protocol.value
            protocol_object = domain.get_protocol_object(protocol_name)
            if protocol_object is not None:
                protocol_object.status = protocol_name in active_protocols
                protocol_object.save()

        messages.success(request, _("Settings updated successfully."))
        return HttpResponseRedirect(self.success_url)


class DomainDetailView(DomainContextMixin, DomainDevIdRegistrationTableMixin, ListInDetailView):

    detail_model = DomainModel
    template_name = 'pki/domains/details.html'
    detail_context_object_name = 'domain'


class DomainCaBulkDeleteConfirmView(DomainContextMixin, BulkDeleteView):
    """View to confirm the deletion of multiple Domains."""

    model = DomainModel
    success_url = reverse_lazy('pki:domains')
    ignore_url = reverse_lazy('pki:domains')
    template_name = 'pki/domains/confirm_delete.html'
    context_object_name = 'domains'

    def form_valid(self, form) -> HttpResponse:
        """Attempt to delete domains if the form is valid."""
        queryset = self.get_queryset()
        deleted_count = queryset.count()

        try:
            response = super().form_valid(form)
        except ProtectedError:
            messages.error(
                self.request,
                _(
                    'Cannot delete the selected Domains(s) because they are referenced by other objects.'
                )
            )
            return HttpResponseRedirect(self.success_url)

        messages.success(
            self.request,
            _('Successfully deleted {count} Domains.').format(count=deleted_count)
        )

        return response


class DevIdRegistrationCreateView(DomainContextMixin, FormView):
    """View to create a new DevID Registration."""

    http_method_names = ('get', 'post')

    template_name = 'pki/devid_registration/add.html'
    form_class = DevIdRegistrationForm

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context data."""
        context = super().get_context_data(**kwargs)
        context['domain'] = self.get_domain()
        truststore_id = self.kwargs.get('truststore_id')
        if truststore_id:
            context['truststore'] = self.get_truststore(truststore_id)
        else:
            context['truststore'] = None

        return context

    def get_initial(self) -> dict[str, Any]:
        """Initialize the form with default values."""
        initial = super().get_initial()
        domain = self.get_domain()
        initial['domain'] = domain
        truststore_id = self.kwargs.get('truststore_id')
        if truststore_id:
            initial['truststore'] = self.get_truststore(truststore_id)
        else:
            initial['truststore'] = None
        return initial

    def get_form_kwargs(self) -> dict[str, Any]:
        """Provide additional arguments to the form."""
        form_kwargs = super().get_form_kwargs()
        form_kwargs['initial'] = self.get_initial()
        return form_kwargs

    def get_domain(self) -> DomainModel:
        """Fetch the domain based on the primary key passed in the URL."""
        try:
            pk = self.kwargs.get('pk')
            return DomainModel.objects.get(pk=pk)
        except DomainModel.DoesNotExist:
            raise Http404('Domain does not exist.')

    def get_truststore(self, truststore_id) -> TruststoreModel:
        """Fetch the domain based on the primary key passed in the URL."""
        try:
            return TruststoreModel.objects.get(pk=truststore_id)
        except TruststoreModel.DoesNotExist:
            raise Http404('Truststore does not exist.')

    def form_valid(self, form: DevIdRegistrationForm) -> HttpResponse:
        """Handle the case where the form is valid."""
        dev_id_registration = form.save()
        messages.success(
            self.request,
            f'Successfully created DevID Registration: {dev_id_registration.unique_name}',
        )
        return super().form_valid(form)

    def get_success_url(self) -> str:
        """Return the URL to redirect to upon successful form submission."""
        domain = self.get_domain()
        return cast('str', reverse_lazy('pki:domains-config', kwargs={'pk': domain.id}))

class DevIdRegistrationDeleteView(DomainContextMixin, DeleteView):
    """View to delete a DevID Registration."""
    model = DevIdRegistration
    template_name = 'pki/devid_registration/confirm_delete.html'
    success_url = reverse_lazy('pki:domains')

    def delete(self, request, *args, **kwargs):
        """Override delete method to add a success message."""
        response = super().delete(request, *args, **kwargs)
        messages.success(request, _('DevID Registration Pattern deleted successfully.'))
        return response

class DevIdMethodSelectView(DomainContextMixin, FormView):
    template_name = 'pki/devid_registration/method_select.html'
    form_class = DevIdAddMethodSelectForm

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["domain"] = get_object_or_404(DomainModel, id=self.kwargs.get("pk"))
        return context

    def form_valid(self, form) -> HttpResponseRedirect:
        method_select = form.cleaned_data.get('method_select')
        domain_pk = self.kwargs.get("pk")  # Get domain ID

        if not method_select:
            return HttpResponseRedirect(reverse('pki:devid_registration-method_select', kwargs={'pk': domain_pk}))

        if method_select == 'import_truststore':
            if domain_pk:
                return HttpResponseRedirect(
                    reverse('pki:truststores-add-with-pk', kwargs={'pk': domain_pk}))
            return HttpResponseRedirect(reverse('pki:truststores-add'))

        if method_select == 'configure_pattern':
            return HttpResponseRedirect(reverse('pki:devid_registration_create', kwargs={'pk': domain_pk}))

        return HttpResponseRedirect(reverse('pki:devid_registration-method_select', kwargs={'pk': domain_pk}))
