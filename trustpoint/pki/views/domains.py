"""Views for managing Domains."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import ProtectedError
from django.forms import BaseModelForm
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic import DeleteView
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, FormView
from django.views.generic.list import ListView

from pki.forms import DevIdAddMethodSelectForm, DevIdRegistrationForm
from pki.models import (
    CertificateModel,
    CertificateProfileModel,
    DevIdRegistration,
    DomainModel,
    IssuingCaModel,
)
from pki.models.truststore import TruststoreModel
from trustpoint.settings import UIConfig
from trustpoint.views.base import (
    BulkDeleteView,
    ContextDataMixin,
    ListInDetailView,
    SortableTableMixin,
)

if TYPE_CHECKING:
    from django.db.models import QuerySet
    from django.forms import Form
    from django.http import HttpRequest


class DomainContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'domains'


class DomainTableView(DomainContextMixin, SortableTableMixin[DomainModel], ListView[DomainModel]):
    """Domain Table View."""

    model = DomainModel
    template_name = 'pki/domains/domain.html'  # Template file
    context_object_name = 'domain-new'
    paginate_by = UIConfig.paginate_by
    default_sort_param = 'unique_name'


class DomainCreateView(DomainContextMixin, CreateView[DomainModel, BaseModelForm[DomainModel]]):
    """View to create a new domain."""

    model = DomainModel
    model = DomainModel
    fields = '__all__'
    template_name = 'pki/domains/add.html'
    success_url = reverse_lazy('pki:domains')
    ignore_url = reverse_lazy('pki:domains')

    def get_form(self, _form_class: Any = None) -> Any:
        """Override get_form to filter out autogen root CAs."""
        form = super().get_form()
        # Filter out autogen root CAs
        form.fields['issuing_ca'].queryset = IssuingCaModel.objects.exclude(  # type: ignore[attr-defined]
            issuing_ca_type=IssuingCaModel.IssuingCaTypeChoice.AUTOGEN_ROOT
        ).filter(is_active=True)
        # Remove empty "---------" choice
        form.fields['issuing_ca'].empty_label = None  # type: ignore[attr-defined]
        del form.fields['is_active']
        return form

    def form_valid(self, form: BaseModelForm[DomainModel]) -> HttpResponse:
        """Handle the case where the form is valid."""
        domain = form.save()
        messages.success(
            self.request,
            _('Successfully created domain {name}.').format(name=domain.unique_name),
        )
        return super().form_valid(form)


class DomainDevIdRegistrationTableMixin(SortableTableMixin[DevIdRegistration], ListInDetailView):
    """Mixin to add a table of DevID Registrations to the domain config view."""

    model = DevIdRegistration
    paginate_by = UIConfig.paginate_by
    context_object_name = 'devid_registrations'
    default_sort_param = 'unique_name'

    def get_queryset(self) -> QuerySet[DevIdRegistration]:
        """Gets the queryset for the DevID Registration table."""
        domain: DomainModel = cast('DomainModel', self.get_object())
        self.queryset = DevIdRegistration.objects.filter(domain=domain)
        return super().get_queryset()


class DomainConfigView(DomainContextMixin, DomainDevIdRegistrationTableMixin, ListInDetailView):
    """View to configure a domain, allows adding DevID registration patterns."""

    detail_model = DomainModel
    template_name = 'pki/domains/config.html'
    detail_context_object_name = 'domain'
    success_url = reverse_lazy('pki:domains')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds additional context data."""
        context = super().get_context_data(**kwargs)
        domain: DomainModel = cast('DomainModel', self.get_object())

        issued_credentials = domain.issued_credentials.all()

        certificates = CertificateModel.objects.filter(
            credential__in=[issued_credential.credential for issued_credential in issued_credentials]
        )

        context['profile_data'] = {
            profile.id: {
                'unique_name': profile.unique_name,
                'alias': '',
                'is_allowed': False
            }
            for profile in CertificateProfileModel.objects.all()
        }

        for allowed_profile in domain.certificate_profiles.all():
            profile_id = allowed_profile.certificate_profile.id
            context['profile_data'][profile_id]['alias'] = allowed_profile.alias
            context['profile_data'][profile_id]['is_allowed'] = True

        context['certificates'] = certificates
        context['domain_options'] = {}
        context['domain_help_texts'] = {}
        context['domain_verbose_name'] = {}

        return context

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle config form submission."""
        del args
        del kwargs

        domain: DomainModel = cast('DomainModel', self.get_object())

        # Handle assignments of  allowed certificate profiles in domain
        # get fields from request POST
        allowed_profile_data = {}
        for key in request.POST:
            if key.startswith('cert_p_allowed_'):
                profile_id = key.removeprefix('cert_p_allowed_')
                alias = request.POST.get(f'cert_p_alias_{profile_id}', '').strip()
                allowed_profile_data[profile_id] = alias

        rejected_aliases = domain.set_allowed_cert_profiles(allowed_profile_data)
        for alias_value, profile in rejected_aliases:
            messages.warning(
                request,
                _('Alias "{alias}" not applied for profile {profile} as it is already in use. '
                'Please use an unique domain alias for each Certificate Profile.').format(
                    alias=alias_value,
                    profile=profile
                )
            )

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
                self.request, _('Cannot delete the selected Domain(s) because they are referenced by other objects.')
            )
            return HttpResponseRedirect(self.success_url)
        except ValidationError as exc:
            messages.error(self.request, exc.message)
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
        domain = self.get_domain()
        context['domain'] =domain
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
        if domain:
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

    def get_domain(self) -> DomainModel | None:
        """Get domain from URL pk (GET) or form data (POST)."""
        pk = self.kwargs.get('pk')
        if pk:
            try:
                return DomainModel.objects.get(pk=pk)
            except DomainModel.DoesNotExist:
                raise Http404('Domain does not exist.')

        if self.request.method == 'POST':
            domain_id = self.request.POST.get('domain')
            if domain_id:
                try:
                    return DomainModel.objects.get(pk=domain_id)
                except (DomainModel.DoesNotExist, ValueError):
                    raise Http404('Domain does not exist.')

        return None



    def get_truststore(self, truststore_id: int) -> TruststoreModel:
        """Fetch the truststore based on the primary key passed in the URL."""
        try:
            return TruststoreModel.objects.get(pk=truststore_id)
        except TruststoreModel.DoesNotExist as e:
            exc_msg = 'This Truststore does not exist.'
            raise Http404(exc_msg) from e

    def form_valid(self, form: DevIdRegistrationForm) -> HttpResponse:
        """Handle the case where the form is valid."""
        dev_id_registration = form.save()
        self.object = dev_id_registration
        messages.success(
            self.request,
            _('Successfully created DevID registration pattern {name}.').format(name=dev_id_registration.unique_name),
        )
        return super().form_valid(form)

    def get_success_url(self) -> str:
        """Return the URL to redirect to upon successful form submission."""
        if self.kwargs.get('pk'):
            domain = self.object.domain
            return reverse_lazy('pki:domains-config', kwargs={'pk': domain.id})
        return reverse_lazy('devices:devices')


class DevIdRegistrationDeleteView(DomainContextMixin, DeleteView[DevIdRegistration, Any]):
    """View to delete a DevID Registration."""

    model = DevIdRegistration
    template_name = 'pki/devid_registration/confirm_delete.html'
    success_url = reverse_lazy('pki:domains')

    def delete(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Override delete method to add a success message."""
        response = super().delete(request, *args, **kwargs)
        messages.success(request, _('DevID Registration Pattern deleted successfully.'))
        return response


class DevIdMethodSelectView(DomainContextMixin, FormView[DevIdAddMethodSelectForm]):
    """View to select the method to add a DevID Registration pattern."""

    template_name = 'pki/devid_registration/method_select.html'
    form_class = DevIdAddMethodSelectForm

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context data."""
        context = super().get_context_data(**kwargs)
        pk = self.kwargs.get('pk')

        if pk:
            context['domain'] = DomainModel.objects.get(pk=pk)
        else:
            context['domain'] = None
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


class IssuedCertificatesView(ContextDataMixin, ListView[CertificateModel]):
    """View to list certificates issued by a specific Issuing CA for a Domain."""

    model = CertificateModel
    template_name = 'pki/domains/issued_certificates.html'
    context_object_name = 'issued_certificates'

    def get_queryset(self) -> QuerySet[CertificateModel]:
        """Return only certificates associated with the domain's issued credentials."""
        domain: DomainModel = self.get_domain()
        if domain.issuing_ca is None:
            msg = 'Domain has no issuing CA configured.'
            raise Http404(msg)
        # PyCharm TypeChecker issue - this passes mypy
        # noinspection PyTypeChecker
        # TODO(AlexHx8472): This must be limited to the actual domain.  # noqa: FIX002
        return CertificateModel.objects.filter(
            issuer_public_bytes=domain.issuing_ca.credential.certificate.subject_public_bytes
        )

    def get_domain(self) -> DomainModel:
        """Get the domain object based on the URL parameter."""
        domain_id = self.kwargs.get('pk')
        return DomainModel.objects.get(pk=domain_id)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Pass additional context data to the template."""
        context = super().get_context_data(**kwargs)
        domain = self.get_domain()
        context['domain'] = domain
        return context

class OnboardingMethodSelectIdevidHelpView(DomainContextMixin, DetailView[DevIdRegistration]):
    """View to select the protocol for IDevID enrollment."""

    template_name = 'pki/domains/idevid_method_select.html'
    context_object_name = 'devid_registration'
    model = DevIdRegistration

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the required context for the template."""
        context = super().get_context_data(**kwargs)
        context['pk'] = self.object.pk

        return context

