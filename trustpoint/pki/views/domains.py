"""Views for managing Domains."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from cryptography.hazmat.primitives import serialization
from devices.views import ActiveTrustpointTlsServerCredentialModelMissingErrorMsg, NamedCurveMissingForEccErrorMsg
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
from django.views.generic.edit import CreateView, FormView, UpdateView
from django.views.generic.list import ListView
from management.models import TlsSettings
from trustpoint.views.base import (
    BulkDeleteView,
    ContextDataMixin,
    ListInDetailView,
    SortableTableMixin,
)
from trustpoint_core import oid

from pki.forms import DevIdAddMethodSelectForm, DevIdRegistrationForm
from pki.models import CertificateModel, DevIdRegistration, DomainModel, IssuingCaModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel, TruststoreModel
from trustpoint.settings import UIConfig

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


class DomainCreateView(DomainContextMixin, CreateView[DomainModel, BaseModelForm[DomainModel]]):
    """View to create a new domain."""

    model = DomainModel
    fields = '__all__'
    template_name = 'pki/domains/add.html'
    success_url = reverse_lazy('pki:domains')
    ignore_url = reverse_lazy('pki:domains')

    def get_form(self, _form_class: Any = None) -> Any:
        """Override get_form to filter out autogen root CAs."""
        form = super().get_form()
        # Filter out autogen root CAs
        form.fields['issuing_ca'].queryset = IssuingCaModel.objects.exclude(
            issuing_ca_type=IssuingCaModel.IssuingCaTypeChoice.AUTOGEN_ROOT
        ).filter(is_active=True)
        form.fields['issuing_ca'].empty_label = None  # Remove empty "---------" choice
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


class DomainUpdateView(DomainContextMixin, UpdateView[DomainModel]):
    """View to edit a domain."""

    # TODO(Air): This view is currently UNUSED. # noqa: FIX002
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

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds (no) additional context data."""
        context = super().get_context_data(**kwargs)
        domain: DomainModel = cast(DomainModel, self.get_object())

        issued_credentials = domain.issued_credentials.all()

        certificates = CertificateModel.objects.filter(
            credential__in=[issued_credential.credential for issued_credential in issued_credentials]
        )

        context['certificates'] = certificates
        context['domain_options'] = {}
        context['domain_help_texts'] = {}
        context['domain_verbose_name'] = {}

        return context

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle config form submission."""
        del args
        del kwargs

        domain = self.get_object()

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
            _('Successfully created DevID registration pattern {name}.').format(name=dev_id_registration.unique_name),
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

    def delete(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Override delete method to add a success message."""
        response = super().delete(request, *args, **kwargs)
        messages.success(request, _('DevID Registration Pattern deleted successfully.'))
        return response


class DevIdMethodSelectView(DomainContextMixin, FormView):
    """View to select the method to add a DevID Registration pattern."""

    template_name = 'pki/devid_registration/method_select.html'
    form_class = DevIdAddMethodSelectForm

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
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
        # TODO(AlexHx8472): This must be limited to the actual domain.
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

    template_name = 'help/idevid_method_select.html'
    context_object_name = 'devid_registration'
    model = DevIdRegistration

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the required context for the template."""
        context = super().get_context_data(**kwargs)
        context['pk'] = self.object.pk

        return context


class OnboardingIdevidRegistrationHelpView(DomainContextMixin, DetailView[DevIdRegistration]):
    """Help view for the IDevID Registration, which displays the required OpenSSL commands."""

    http_method_names = ('get',)

    model = DevIdRegistration
    context_object_name = 'devid_registration'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the required OpenSSL commands to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        context['pk'] = self.kwargs.get('pk')
        devid_registration: DevIdRegistration = self.object

        if devid_registration.domain.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            domain_credential_key_gen_command = (
                f'openssl genrsa -out domain_credential_key.pem {devid_registration.domain.public_key_info.key_size}'
            )
            key_gen_command = f'openssl genrsa -out key.pem {devid_registration.domain.public_key_info.key_size}'
        elif devid_registration.domain.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            if not devid_registration.domain.public_key_info.named_curve:
                raise Http404(NamedCurveMissingForEccErrorMsg)
            domain_credential_key_gen_command = (
                f'openssl ecparam -name {devid_registration.domain.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out domain_credential_key.pem'
            )
            key_gen_command = (
                f'openssl ecparam -name {devid_registration.domain.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out key.pem'
            )
        else:
            err_msg = 'Unsupported public key algorithm'
            raise ValueError(err_msg)

        ipv4_address = TlsSettings.get_first_ipv4_address()

        context['host'] = f'{ipv4_address}:{self.request.META.get("SERVER_PORT", "443")}'
        context['domain_credential_key_gen_command'] = domain_credential_key_gen_command
        context['key_gen_command'] = key_gen_command
        context['issuing_ca_pem'] = (
            devid_registration.domain.get_issuing_ca_or_value_error().credential.get_certificate()
            .public_bytes(encoding=serialization.Encoding.PEM)
            .decode()
        )
        tls_cert = ActiveTrustpointTlsServerCredentialModel.objects.first()
        if not tls_cert or not tls_cert.credential:
            raise Http404(ActiveTrustpointTlsServerCredentialModelMissingErrorMsg)
        context['trustpoint_server_certificate'] = (
            tls_cert.credential.certificate.get_certificate_serializer().as_pem().decode('utf-8')
        )
        context['public_key_info'] = devid_registration.domain.public_key_info
        context['domain'] = devid_registration.domain
        return context


class OnboardingCmpIdevidRegistrationHelpView(OnboardingIdevidRegistrationHelpView):
    """Help view for the CMP IDevID Registration, which displays the required OpenSSL commands."""

    template_name = 'help/cmp_idevid.html'


class OnboardingEstIdevidRegistrationHelpView(OnboardingIdevidRegistrationHelpView):
    """Help view for the EST IDevID Registration, which displays the required OpenSSL commands."""

    template_name = 'help/est_idevid.html'
