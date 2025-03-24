"""Views for managing Domains."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from django.contrib import messages
from django.db.models import ProtectedError
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic import DeleteView
from django.views.generic.edit import CreateView, FormView, UpdateView
from django.views.generic.list import ListView
from psycopg.types import enum

from devices.models import IssuedCredentialModel
from pki.forms import DevIdAddMethodSelectForm, DevIdRegistrationForm
from pki.models import DevIdRegistration, DomainModel, IssuingCaModel, CertificateModel
from pki.models.truststore import TruststoreModel
from trustpoint.settings import UIConfig
from trustpoint.views.base import (
    BulkDeleteView,
    ContextDataMixin,
    ListInDetailView,
    SortableTableMixin,
)


class PkiProtocol(enum.Enum):
    EST = 'est'
    CMP = 'cmp'
    REST = 'rest'
    SCEP = 'scep'
    ACME = 'acme'


if TYPE_CHECKING:
    from django.db.models import QuerySet
    from django.forms import Form
    from django.http import HttpRequest


class DomainContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'domains'


class DomainTableView(DomainContextMixin, SortableTableMixin, ListView[DomainModel]):
    """Domain Table View."""

    model = DomainModel
    template_name = 'pki/domains/domain.html'  # Template file
    context_object_name = 'domain-new'
    paginate_by = UIConfig.paginate_by
    default_sort_param = 'unique_name'


class DomainCreateView(DomainContextMixin, CreateView[DomainModel]):
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
        form.fields['issuing_ca'].empty_label = None  # Remove empty "---------" choice
        del form.fields['is_active']
        return form


class DomainUpdateView(DomainContextMixin, UpdateView[DomainModel]):
    """View to edit a domain."""

    # TODO(Air): This view is currently UNUSED.
    # If used, a mixin implementing the get_form method from the DomainCreateView should be added.

    model = DomainModel
    fields = '__all__'
    template_name = 'pki/domains/add.html'
    success_url = reverse_lazy('pki:domains')
    ignore_url = reverse_lazy('pki:domains')


class DomainDevIdRegistrationTableMixin(SortableTableMixin, ListInDetailView):
    """Mixin to add a table of DevID Registrations to the domain config view."""

    model = DevIdRegistration
    paginate_by = UIConfig.paginate_by
    context_object_name = 'devid_registrations'
    default_sort_param = 'unique_name'

    def get_queryset(self) -> QuerySet[DevIdRegistration]:
        """Gets the queryset for the DevID Registration table."""
        self.queryset = DevIdRegistration.objects.filter(domain=self.get_object())
        return super().get_queryset()


class DomainConfigView(DomainContextMixin, DomainDevIdRegistrationTableMixin, ListInDetailView):
    """View to configure a domain, allows adding DevID registration patterns."""

    detail_model = DomainModel
    template_name = 'pki/domains/config.html'
    detail_context_object_name = 'domain'
    success_url = reverse_lazy('pki:domains')

    def get_context_data(self, **kwargs):
        """Adds (no) additional context data."""
        context = super().get_context_data(**kwargs)
        domain = self.get_object()

        issued_credentials = domain.issued_credentials.all()

        certificates = CertificateModel.objects.filter(
            credential__in=[issued_credential.credential for issued_credential in issued_credentials]
        )

        context['certificates'] = certificates
        context['protocols'] = {
            'cmp': domain.cmp_protocol if hasattr(domain, 'cmp_protocol') else None,
            'est': domain.est_protocol if hasattr(domain, 'est_protocol') else None,
            'acme': domain.acme_protocol if hasattr(domain, 'acme_protocol') else None,
            'scep': domain.scep_protocol if hasattr(domain, 'scep_protocol') else None,
            'rest': domain.rest_protocol if hasattr(domain, 'rest_protocol') else None,
        }
        context['domain_options'] = {
            'auto_create_new_device': domain.auto_create_new_device,
            'allow_username_password_registration': domain.allow_username_password_registration,
            'allow_idevid_registration': domain.allow_idevid_registration,
            'domain_credential_auth': domain.domain_credential_auth,
            'username_password_auth': domain.username_password_auth,
            'allow_app_certs_without_domain': domain.allow_app_certs_without_domain,
        }

        context['domain_help_texts'] = {
            'auto_create_new_device': domain._meta.get_field('auto_create_new_device').help_text,
            'allow_username_password_registration': domain._meta.get_field(
                'allow_username_password_registration'
            ).help_text,
            'allow_idevid_registration': domain._meta.get_field('allow_idevid_registration').help_text,
            'domain_credential_auth': domain._meta.get_field('domain_credential_auth').help_text,
            'username_password_auth': domain._meta.get_field('username_password_auth').help_text,
            'allow_app_certs_without_domain': domain._meta.get_field('allow_app_certs_without_domain').help_text,
        }

        context['domain_verbose_name'] = {
            'auto_create_new_device': domain._meta.get_field('auto_create_new_device').verbose_name,
            'allow_username_password_registration': domain._meta.get_field(
                'allow_username_password_registration'
            ).verbose_name,
            'allow_idevid_registration': domain._meta.get_field('allow_idevid_registration').verbose_name,
            'domain_credential_auth': domain._meta.get_field('domain_credential_auth').verbose_name,
            'username_password_auth': domain._meta.get_field('username_password_auth').verbose_name,
            'allow_app_certs_without_domain': domain._meta.get_field('allow_app_certs_without_domain').verbose_name,
        }

        return context  # noqa: RET504

    def post(self, request, *args, **kwargs):
        """Handle config form submission."""
        domain = self.get_object()

        domain.auto_create_new_device = 'auto_create_new_device' in request.POST
        domain.allow_username_password_registration = 'allow_username_password_registration' in request.POST
        domain.allow_idevid_registration = 'allow_idevid_registration' in request.POST
        domain.domain_credential_auth = 'domain_credential_auth' in request.POST
        domain.username_password_auth = 'username_password_auth' in request.POST
        domain.allow_app_certs_without_domain = 'allow_app_certs_without_domain' in request.POST

        domain.save()

        messages.success(request, _('Settings updated successfully.'))
        return HttpResponseRedirect(self.success_url)


class DomainDetailView(DomainContextMixin, DomainDevIdRegistrationTableMixin, ListInDetailView):
    """View to display domain details."""

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

    def form_valid(self, form: Form) -> HttpResponse:
        """Attempt to delete domains if the form is valid."""
        queryset = self.get_queryset()
        deleted_count = queryset.count()

        try:
            response = super().form_valid(form)
        except ProtectedError:
            messages.error(
                self.request, _('Cannot delete the selected Domains(s) because they are referenced by other objects.')
            )
            return HttpResponseRedirect(self.success_url)

        messages.success(self.request, _('Successfully deleted {count} Domains.').format(count=deleted_count))

        return response


class DevIdRegistrationCreateView(DomainContextMixin, FormView[DevIdRegistrationForm]):
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
        except DomainModel.DoesNotExist as e:
            exc_msg = 'This Domain does not exist.'
            raise Http404(exc_msg) from e

    def get_truststore(self, truststore_id: int) -> TruststoreModel:
        """Fetch the domain based on the primary key passed in the URL."""
        try:
            return TruststoreModel.objects.get(pk=truststore_id)
        except TruststoreModel.DoesNotExist as e:
            exc_msg = 'This Domain does not exist.'
            raise Http404(exc_msg) from e

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

    def delete(self, request: HttpRequest, *args: tuple[Any], **kwargs: dict[str, Any]) -> HttpResponse:
        """Override delete method to add a success message."""
        response = super().delete(request, *args, **kwargs)
        messages.success(request, _('DevID Registration Pattern deleted successfully.'))
        return response


class DevIdMethodSelectView(DomainContextMixin, FormView):
    """View to select the method to add a DevID Registration pattern."""

    template_name = 'pki/devid_registration/method_select.html'
    form_class = DevIdAddMethodSelectForm

    def get_context_data(self, **kwargs: dict[str, Any]) -> dict[str, Any]:
        """Add additional context data."""
        context = super().get_context_data(**kwargs)
        context['domain'] = get_object_or_404(DomainModel, id=self.kwargs.get('pk'))
        return context

    def form_valid(self, form: DevIdAddMethodSelectForm) -> HttpResponseRedirect:
        """Redirect to the view for the selected method."""
        method_select = form.cleaned_data.get('method_select')
        domain_pk = self.kwargs.get('pk')  # Get domain ID

        if method_select == 'import_truststore':
            if domain_pk:
                return HttpResponseRedirect(reverse('pki:truststores-add-with-pk', kwargs={'pk': domain_pk}))
            return HttpResponseRedirect(reverse('pki:truststores-add'))

        if method_select == 'configure_pattern':
            return HttpResponseRedirect(reverse('pki:devid_registration_create', kwargs={'pk': domain_pk}))

        # Try again if none or invalid method was selected
        return HttpResponseRedirect(reverse('pki:devid_registration-method_select', kwargs={'pk': domain_pk}))


class IssuedCertificatesView(ListView):
    """View to list certificates issued by a specific Issuing CA for a Domain."""

    model = CertificateModel
    template_name = 'pki/domains/issued_certificates.html'
    context_object_name = 'certificates'

    def get_queryset(self):
        """Return only certificates associated with the domain's issued credentials."""
        domain = self.get_domain()  # Get the domain
        issued_credentials = IssuedCredentialModel.objects.filter(domain=domain)
        certificates = CertificateModel.objects.filter(
            credential__in=[issued_credential.credential for issued_credential in issued_credentials]
        )
        return certificates

    def get_domain(self):
        """Get the domain object based on the URL parameter."""
        domain_id = self.kwargs.get('pk')
        return DomainModel.objects.get(pk=domain_id)

    def get_context_data(self, **kwargs):
        """Pass additional context data to the template."""
        context = super().get_context_data(**kwargs)
        domain = self.get_domain()
        context['domain'] = domain
        return context
