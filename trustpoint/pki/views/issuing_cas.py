"""Views for Issuing CA management."""

from __future__ import annotations

import binascii
import json
from base64 import b64decode
from typing import TYPE_CHECKING, Any, ClassVar, cast

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import ProtectedError
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse, reverse_lazy
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext as _
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView
from django.views.generic.list import ListView
from django_filters.rest_framework import DjangoFilterBackend
from drf_yasg import openapi  # type: ignore[import-untyped]
from drf_yasg.utils import swagger_auto_schema  # type: ignore[import-untyped]
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from pki.forms import (
    CertificateIssuanceForm,
    IssuingCaAddFileImportPkcs12Form,
    IssuingCaAddFileImportSeparateFilesForm,
    IssuingCaAddMethodSelectForm,
    IssuingCaAddRequestCmpForm,
    IssuingCaAddRequestEstForm,
    IssuingCaTruststoreAssociationForm,
    TruststoreAddForm,
)
from pki.models import CaModel, CertificateModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.truststore import TruststoreModel
from pki.serializer import IssuingCaSerializer
from trustpoint.logger import LoggerMixin
from trustpoint.settings import UIConfig
from trustpoint.views.base import (
    BulkDeleteView,
    ContextDataMixin,
    SortableTableMixin,
)

if TYPE_CHECKING:
    from django.db.models import QuerySet
    from django.forms import Form
    from django.http import HttpRequest

    from pki.models.credential import CredentialModel


class IssuingCaContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'cas'


class KeylessCaContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Keyless CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'cas'


class IssuingCaTableView(IssuingCaContextMixin, SortableTableMixin[CaModel], ListView[CaModel]):
    """Issuing CA Table View."""

    model = CaModel
    template_name = 'pki/issuing_cas/issuing_cas.html'  # Template file
    context_object_name = 'issuing_ca'
    paginate_by = UIConfig.paginate_by  # Number of items per page
    default_sort_param = 'created_at'

    def get_queryset(self) -> QuerySet[CaModel, CaModel]:
        """Return only issuing CAs."""
        queryset = self.model.objects.all().exclude(
            ca_type__in=[CaModel.CaTypeChoice.KEYLESS, CaModel.CaTypeChoice.AUTOGEN_ROOT]
        )

        sort_param = self.request.GET.get('sort', self.default_sort_param)
        if sort_param == 'common_name':
            sort_param = 'credential__certificate__common_name'
        elif sort_param == '-common_name':
            sort_param = '-credential__certificate__common_name'

        if hasattr(self.model, 'is_active'):
            return queryset.order_by('-is_active', sort_param)
        return queryset.order_by(sort_param)

    def get_context_data(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Add sorting information to the context."""
        context = super().get_context_data(*args, **kwargs)

        sort_param = self.request.GET.get('sort', self.default_sort_param)
        context['current_sort'] = sort_param

        return context


class IssuingCaAddMethodSelectView(IssuingCaContextMixin, FormView[IssuingCaAddMethodSelectForm]):
    """View to select the method to add an Issuing CA."""

    template_name = 'pki/issuing_cas/add/method_select.html'
    form_class = IssuingCaAddMethodSelectForm

    def form_valid(self, form: IssuingCaAddMethodSelectForm) -> HttpResponseRedirect:
        """Redirect to the next step based on the selected method."""
        method_select = form.cleaned_data.get('method_select')
        if not method_select:
            return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-method_select'))

        if method_select and method_select == 'local_file_import':
            return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-file_import-file_type_select'))

        return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-method_select'))


class IssuingCaAddFileImportPkcs12View(IssuingCaContextMixin, FormView[IssuingCaAddFileImportPkcs12Form]):
    """View to import an Issuing CA from a PKCS12 file."""

    template_name = 'pki/issuing_cas/add/file_import.html'
    form_class = IssuingCaAddFileImportPkcs12Form
    success_url = reverse_lazy('pki:issuing_cas')

    def form_valid(self, form: IssuingCaAddFileImportPkcs12Form) -> HttpResponse:
        """Handle the case where the form is valid."""
        messages.success(
            self.request,
            _('Successfully added Issuing CA {name}.').format(name=form.cleaned_data['unique_name']),
        )
        return super().form_valid(form)


class IssuingCaAddFileImportSeparateFilesView(IssuingCaContextMixin, FormView[IssuingCaAddFileImportSeparateFilesForm]):
    """View to import an Issuing CA from separate PEM files."""

    template_name = 'pki/issuing_cas/add/file_import.html'
    form_class = IssuingCaAddFileImportSeparateFilesForm
    success_url = reverse_lazy('pki:issuing_cas')

    def form_valid(self, form: IssuingCaAddFileImportSeparateFilesForm) -> HttpResponse:
        """Handle the case where the form is valid."""
        messages.success(
            self.request,
            _('Successfully added Issuing CA {name}.').format(name=form.cleaned_data['unique_name']),
        )
        return super().form_valid(form)


class IssuingCaAddRequestEstView(IssuingCaContextMixin, FormView[IssuingCaAddRequestEstForm]):
    """View to request an Issuing CA certificate using EST."""

    form_class = IssuingCaAddRequestEstForm
    template_name = 'pki/issuing_cas/add/request_est.html'

    def form_valid(self, form: IssuingCaAddRequestEstForm) -> HttpResponse:
        """Handle successful form submission."""
        ca = form.save()
        messages.success(
            self.request,
            _('Successfully created Issuing CA {name}. Please associate a trust store.').format(
                name=ca.unique_name
            ),
        )
        return redirect('pki:issuing_cas-truststore-association', pk=ca.pk)


class IssuingCaTruststoreAssociationView(IssuingCaContextMixin, FormView[IssuingCaTruststoreAssociationForm]):
    """View for associating a truststore with an Issuing CA."""

    form_class = IssuingCaTruststoreAssociationForm
    template_name = 'pki/issuing_cas/truststore_association.html'

    def get_ca(self) -> CaModel:
        """Get the CA from the URL parameters."""
        pk = self.kwargs.get('pk')
        return get_object_or_404(
            CaModel.objects.exclude(ca_type__in=[CaModel.CaTypeChoice.KEYLESS, CaModel.CaTypeChoice.AUTOGEN_ROOT]),
            pk=pk
        )

    def get_form_kwargs(self) -> dict[str, Any]:
        """Add the CA instance to the form kwargs."""
        kwargs = super().get_form_kwargs()
        kwargs['instance'] = self.get_ca()
        truststore_id = self.request.GET.get('truststore_id')
        if truststore_id:
            try:
                truststore = TruststoreModel.objects.get(pk=truststore_id)
                kwargs['initial'] = kwargs.get('initial', {})
                kwargs['initial']['trust_store'] = truststore
            except TruststoreModel.DoesNotExist:
                pass
        return kwargs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the CA and import form to the context."""
        context = super().get_context_data(**kwargs)
        context['ca'] = self.get_ca()
        context['import_form'] = TruststoreAddForm()
        return context

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle both association and import form submissions."""
        if 'trust_store_file' in request.FILES:
            return self._handle_import(request)
        return super().post(request, *args, **kwargs)

    def _handle_import(self, request: HttpRequest) -> HttpResponse:
        """Handle truststore import from modal."""
        import_form = TruststoreAddForm(request.POST, request.FILES)

        if import_form.is_valid():
            truststore = import_form.cleaned_data['truststore']
            messages.success(
                request,
                _('Successfully imported truststore {name}.').format(name=truststore.unique_name),
            )
            return HttpResponseRedirect(
                reverse('pki:issuing_cas-truststore-association', kwargs={'pk': self.get_ca().pk}) +
                f'?truststore_id={truststore.id}'
            )

        context = self.get_context_data()
        context['import_form'] = import_form
        return self.render_to_response(context)

    def form_valid(self, form: IssuingCaTruststoreAssociationForm) -> HttpResponse:
        """Handle successful form submission."""
        form.save()
        ca = self.get_ca()
        messages.success(
            self.request,
            _('Successfully associated truststore with Issuing CA {name}.').format(name=ca.unique_name)
        )
        if ca.ca_type == CaModel.CaTypeChoice.REMOTE_ISSUING_EST:
            return redirect('pki:issuing_cas-define-cert-content-est', pk=ca.pk)
        return redirect('pki:issuing_cas-define-cert-content-cmp', pk=ca.pk)


class IssuingCaDefineCertContentMixin(LoggerMixin, IssuingCaContextMixin):
    """Mixin for defining certificate content using the issuing_ca profile."""

    ca_type_filter: CaModel.CaTypeChoice
    redirect_url_name: str

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Dispatch the request, ensuring the CA and profile exist."""
        self.ca = get_object_or_404(
            CaModel.objects.filter(ca_type=self.ca_type_filter),
            pk=kwargs['pk']
        )
        try:
            self.cert_profile = CertificateProfileModel.objects.get(unique_name='issuing_ca')
        except CertificateProfileModel.DoesNotExist:
            messages.error(
                request,
                _('Certificate profile "issuing_ca" not found. Please create it or contact your administrator.')
            )
            return redirect('pki:issuing_cas')
        return cast('HttpResponse', super().dispatch(request, *args, **kwargs))  # type: ignore[misc]

    def get_form_kwargs(self) -> dict[str, Any]:
        """Get form kwargs, including the profile."""
        kwargs = super().get_form_kwargs()  # type: ignore[misc]
        raw_profile = json.loads(self.cert_profile.profile_json)
        kwargs['profile'] = raw_profile
        return kwargs  # type: ignore[no-any-return]

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context data."""
        context = super().get_context_data(**kwargs)
        context['issuing_ca'] = self.ca
        context['cert_profile'] = self.cert_profile
        context['profile_dict'] = self.get_form_kwargs()['profile']
        return context

    def form_invalid(self, form: CertificateIssuanceForm) -> HttpResponse:
        """Handle the case where the form is invalid."""
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(self.request, f'{field}: {error}')  # type: ignore[attr-defined]
        return super().form_invalid(form)  # type: ignore[misc,no-any-return]

    def form_valid(self, form: CertificateIssuanceForm) -> HttpResponse:
        """Handle the case where the form is valid."""
        # Store the form data in session for use in the request-cert view
        self.request.session[f'cert_content_data_{self.ca.pk}'] = form.cleaned_data # type: ignore[attr-defined]
        messages.success(
            self.request, # type: ignore[attr-defined]
            self.get_success_message()
        )
        return redirect(self.redirect_url_name, pk=self.ca.pk)

    def get_success_message(self) -> str:
        """Get the success message for the form submission."""
        msg = 'Subclasses must implement get_success_message()'
        raise NotImplementedError(msg)


class IssuingCaDefineCertContentEstView(IssuingCaDefineCertContentMixin, FormView[CertificateIssuanceForm]):
    """View to define certificate content using the issuing_ca profile before requesting via EST."""

    form_class = CertificateIssuanceForm
    template_name = 'pki/issuing_cas/define_cert_content_est.html'
    ca_type_filter = CaModel.CaTypeChoice.REMOTE_ISSUING_EST
    redirect_url_name = 'pki:issuing_cas-request-cert-est'

    def get_success_message(self) -> str:
        """Get the success message for the form submission."""
        return _('Certificate content defined. Please proceed to request the certificate via EST.')


class IssuingCaAddRequestCmpView(IssuingCaContextMixin, FormView[IssuingCaAddRequestCmpForm]):
    """View to request an Issuing CA certificate using CMP."""

    form_class = IssuingCaAddRequestCmpForm
    template_name = 'pki/issuing_cas/add/request_cmp.html'

    def form_valid(self, form: IssuingCaAddRequestCmpForm) -> HttpResponse:
        """Handle successful form submission."""
        ca = form.save()
        messages.success(
            self.request,
            _('Successfully created Issuing CA {name}. Please associate a trust store.').format(
                name=ca.unique_name
            ),
        )
        return redirect('pki:issuing_cas-truststore-association', pk=ca.pk)


class IssuingCaDefineCertContentCmpView(IssuingCaDefineCertContentMixin, FormView[CertificateIssuanceForm]):
    """View to define certificate content using the issuing_ca profile before requesting via CMP."""

    form_class = CertificateIssuanceForm
    template_name = 'pki/issuing_cas/define_cert_content_cmp.html'
    ca_type_filter = CaModel.CaTypeChoice.REMOTE_ISSUING_CMP
    redirect_url_name = 'pki:issuing_cas-request-cert-cmp'

    def get_success_message(self) -> str:
        """Get the success message for the form submission."""
        return _('Certificate content defined. Please proceed to request the certificate via CMP.')


class IssuingCaConfigView(LoggerMixin, IssuingCaContextMixin, DetailView[CaModel]):
    """View to display the details of an Issuing CA."""

    model = CaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    template_name = 'pki/issuing_cas/config.html'
    context_object_name = 'issuing_ca'

    def get_queryset(self) -> QuerySet[CaModel, CaModel]:
        """Return only issuing CAs."""
        return super().get_queryset().exclude(
            ca_type__in=[CaModel.CaTypeChoice.KEYLESS, CaModel.CaTypeChoice.AUTOGEN_ROOT]
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the issued certificates to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data()

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        issuing_ca = self.get_object()
        if issuing_ca.credential and issuing_ca.credential.certificate:
            credential = issuing_ca.credential
            issuer_public_bytes = credential.certificate_or_error.subject_public_bytes
            issued_certificates = CertificateModel.objects.filter(issuer_public_bytes=issuer_public_bytes)
        else:
            issued_certificates = CertificateModel.objects.none()
        context['issued_certificates'] = issued_certificates
        context['active_crl'] = issuing_ca.get_active_crl()
        return context


class IssuingCaRequestCertMixin(LoggerMixin, IssuingCaContextMixin):
    """Mixin for certificate request views for EST and CMP protocols."""

    context_object_name = 'issuing_ca'
    ca_type_filter: CaModel.CaTypeChoice
    redirect_url_name: str

    def get_queryset(self) -> QuerySet[CaModel, CaModel]:
        """Return only CAs matching the protocol-specific type filter."""
        return CaModel.objects.filter(ca_type=self.ca_type_filter)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the issuing_ca certificate profile and cert content summary to the context."""
        context = super().get_context_data(**kwargs)

        # Get certificate profile
        try:
            cert_profile = CertificateProfileModel.objects.get(unique_name='issuing_ca')
            context['cert_profile'] = cert_profile
            context['profile_json'] = cert_profile.profile_json
        except CertificateProfileModel.DoesNotExist:
            self.logger.warning('issuing_ca certificate profile not found')
            context['cert_profile'] = None
            context['profile_json'] = None

        # Get certificate content data from session
        ca = self.get_object()  # type: ignore[attr-defined]
        cert_content_key = f'cert_content_data_{ca.pk}'
        cert_content_data = self.request.session.get(cert_content_key)  # type: ignore[attr-defined]

        if cert_content_data:
            context['cert_content_data'] = cert_content_data
            context['has_cert_content'] = True

            # Build a summary of the certificate content
            summary = self._build_cert_content_summary(cert_content_data)
            context['cert_content_summary'] = summary
        else:
            context['has_cert_content'] = False
            context['cert_content_data'] = None
            context['cert_content_summary'] = None

        return context

    def _build_cert_content_summary(self, cert_data: dict[str, Any]) -> dict[str, Any]:
        """Build a human-readable summary of the certificate content."""
        summary: dict[str, Any] = {
            'subject': {},
            'san': {},
            'validity': {}
        }

        # Subject fields
        subject_fields = [
            ('common_name', 'Common Name (CN)'),
            ('organization_name', 'Organization (O)'),
            ('organizational_unit_name', 'Organizational Unit (OU)'),
            ('country_name', 'Country (C)'),
            ('state_or_province_name', 'State/Province (ST)'),
            ('locality_name', 'Locality (L)'),
            ('email_address', 'Email Address'),
        ]

        for field_name, label in subject_fields:
            value = cert_data.get(field_name)
            if value:
                summary['subject'][label] = value

        # SAN fields
        san_fields = [
            ('dns_names', 'DNS Names'),
            ('ip_addresses', 'IP Addresses'),
            ('rfc822_names', 'Email Addresses'),
            ('uris', 'URIs'),
        ]

        for field_name, label in san_fields:
            value = cert_data.get(field_name)
            if value:
                summary['san'][label] = value

        # Validity
        validity_parts = []
        if cert_data.get('days'):
            validity_parts.append(f"{cert_data['days']} days")
        if cert_data.get('hours'):
            validity_parts.append(f"{cert_data['hours']} hours")
        if cert_data.get('minutes'):
            validity_parts.append(f"{cert_data['minutes']} minutes")
        if cert_data.get('seconds'):
            validity_parts.append(f"{cert_data['seconds']} seconds")

        summary['validity'] = ', '.join(validity_parts) if validity_parts else 'Not specified'

        return summary

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Handle POST request to request certificate."""
        ca = self.get_object()  # type: ignore[attr-defined]

        # TODO(FlorianHandke): Implement certificate request client  # noqa: FIX002
        messages.warning(request, self.get_not_implemented_message())
        return redirect(self.redirect_url_name, pk=ca.pk)

    def get_not_implemented_message(self) -> str:
        """Get the not implemented message for the specific protocol."""
        msg = 'Subclasses must implement get_not_implemented_message()'
        raise NotImplementedError(msg)


class IssuingCaRequestCertEstView(IssuingCaRequestCertMixin, DetailView[CaModel]):  # type: ignore[misc]
    """View to display the EST certificate request page."""

    template_name = 'pki/issuing_cas/request_cert_est.html'
    ca_type_filter = CaModel.CaTypeChoice.REMOTE_ISSUING_EST
    redirect_url_name = 'pki:issuing_cas-request-cert-est'

    def get_not_implemented_message(self) -> str:
        """Get the not implemented message for EST."""
        return _('EST certificate request not yet implemented.')


class IssuingCaRequestCertCmpView(IssuingCaRequestCertMixin, DetailView[CaModel]):   # type: ignore[misc]
    """View to display the CMP certificate request page."""

    template_name = 'pki/issuing_cas/request_cert_cmp.html'
    ca_type_filter = CaModel.CaTypeChoice.REMOTE_ISSUING_CMP
    redirect_url_name = 'pki:issuing_cas-request-cert-cmp'

    def get_not_implemented_message(self) -> str:
        """Get the not implemented message for CMP."""
        return _('CMP certificate request not yet implemented.')


class KeylessCaConfigView(LoggerMixin, KeylessCaContextMixin, DetailView[CaModel]):
    """View to display the details of a Keyless CA."""

    http_method_names = ('get',)

    model = CaModel
    success_url = reverse_lazy('pki:cas')
    ignore_url = reverse_lazy('pki:cas')
    template_name = 'pki/keyless_cas/config.html'
    context_object_name = 'keyless_ca'

    def get_queryset(self) -> QuerySet[CaModel, CaModel]:
        """Return only keyless CAs."""
        return super().get_queryset().filter(ca_type=CaModel.CaTypeChoice.KEYLESS)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add active CRL information to the context."""
        context = super().get_context_data(**kwargs)
        ca = context['keyless_ca']
        context['active_crl'] = ca.get_active_crl()
        return context


class IssuedCertificatesListView(IssuingCaContextMixin, ListView[CertificateModel]):
    """View to display all certificates issued by a specific Issuing CA."""

    model = CertificateModel
    template_name = 'pki/issuing_cas/issued_certificates.html'
    context_object_name = 'issued_certificates'

    def get_queryset(self) -> QuerySet[CertificateModel, CertificateModel]:
        """Gets the required and filtered QuerySet.

        Returns:
            The filtered QuerySet.
        """
        issuing_ca = get_object_or_404(CaModel.objects.exclude(
            ca_type__in=[CaModel.CaTypeChoice.KEYLESS, CaModel.CaTypeChoice.AUTOGEN_ROOT]
        ), pk=self.kwargs['pk'])

        # PyCharm TypeChecker issue - this passes mypy
        # noinspection PyTypeChecker
        # TODO(AlexHx8472): This is not a good query. Use issued credentials to get the certificates.  # noqa: FIX002
        return CertificateModel.objects.filter(
            issuer_public_bytes=issuing_ca.subject_public_bytes
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the issuing ca model object to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data()

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        context['issuing_ca'] = get_object_or_404(
            CaModel.objects.exclude(
                ca_type__in=[CaModel.CaTypeChoice.KEYLESS, CaModel.CaTypeChoice.AUTOGEN_ROOT]
            ), pk=self.kwargs['pk']
        )
        return context


class IssuingCaDetailView(IssuingCaContextMixin, DetailView[CaModel]):
    """Detail view for an Issuing CA."""

    model = CaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    template_name = 'pki/issuing_cas/details.html'
    context_object_name = 'issuing_ca'

    def get_queryset(self) -> QuerySet[CaModel, CaModel]:
        """Return only issuing CAs."""
        return super().get_queryset().exclude(
            ca_type__in=[CaModel.CaTypeChoice.KEYLESS, CaModel.CaTypeChoice.AUTOGEN_ROOT]
        )


class IssuingCaBulkDeleteConfirmView(IssuingCaContextMixin, BulkDeleteView):
    """View to confirm the deletion of multiple Issuing CAs."""

    model = CaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    template_name = 'pki/issuing_cas/confirm_delete.html'
    context_object_name = 'issuing_cas'

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests."""
        queryset = self.get_queryset()
        if not queryset.exists():
            messages.error(request, _('No Issuing CAs selected for deletion.'))
            return HttpResponseRedirect(self.success_url)
        return super().get(request, *args, **kwargs)

    def get_queryset(self) -> QuerySet[CaModel, CaModel]:
        """Return only issuing CAs."""
        return super().get_queryset().exclude(
            ca_type__in=[CaModel.CaTypeChoice.KEYLESS, CaModel.CaTypeChoice.AUTOGEN_ROOT]
        )

    def form_valid(self, form: Form) -> HttpResponse:
        """Delete the selected Issuing CAs on valid form."""
        queryset = self.get_queryset()
        deleted_count = queryset.count() if queryset else 0

        try:
            response = super().form_valid(form)
        except ProtectedError:
            messages.error(
                self.request,
                _('Cannot delete the selected Issuing CA(s) because they are referenced by other objects.'),
            )
            return HttpResponseRedirect(self.success_url)
        except ValidationError as exc:
            messages.error(self.request, exc.message)
            return HttpResponseRedirect(self.success_url)

        messages.success(self.request, _('Successfully deleted {count} Issuing CA(s).').format(count=deleted_count))

        return response


class IssuingCaCrlGenerationView(IssuingCaContextMixin, DetailView[CaModel]):
    """View to manually generate a CRL for an Issuing CA."""

    model = CaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    context_object_name = 'issuing_ca'

    http_method_names = ('get',)

    def get_queryset(self) -> QuerySet[CaModel, CaModel]:
        """Return only issuing CAs."""
        return super().get_queryset().exclude(
            ca_type__in=[CaModel.CaTypeChoice.KEYLESS, CaModel.CaTypeChoice.AUTOGEN_ROOT]
        )

    # TODO(Air): This view should use a POST request as it is an action.    # noqa: FIX002
    # However, this is not trivial in the config view as that already contains a form.
    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Generate a CRL for the Issuing CA (should be POST!)."""
        del args
        del kwargs

        issuing_ca = self.get_object()
        if issuing_ca.issue_crl():
            messages.success(request, _('CRL for Issuing CA %s has been generated.') % issuing_ca.unique_name)
        else:
            messages.error(request, _('Failed to generate CRL for Issuing CA %s.') % issuing_ca.unique_name)
        next_url = request.GET.get('next')
        if next_url and url_has_allowed_host_and_scheme(next_url, allowed_hosts=[request.get_host()]):
            return redirect(next_url)
        return redirect('pki:issuing_cas-config', pk=issuing_ca.pk)


class CrlDownloadView(IssuingCaContextMixin, DetailView[CaModel]):
    """Unauthenticated view to download the certificate revocation list of any CA."""

    http_method_names = ('get',)

    model = CaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    context_object_name = 'ca'

    def get_queryset(self) -> QuerySet[CaModel, CaModel]:
        """Return all CAs."""
        return super().get_queryset().all()

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Download the CRL of the CA."""
        del args
        del kwargs

        ca = self.get_object()
        crl_pem = ca.crl_pem
        if not crl_pem:
            messages.warning(request, _('No CRL available for CA %s.') % ca.unique_name)
            return redirect('pki:issuing_cas')
        encoding = request.GET.get('encoding', '').lower()
        if encoding == 'der':
            pem_lines = [line.strip() for line in crl_pem.splitlines() if line and not line.startswith('-----')]
            b64data = ''.join(pem_lines)
            try:
                crl_der = b64decode(b64data)
            except (binascii.Error, ValueError) as exc:
                messages.error(
                    request,
                    _(
                        'Failed to convert CRL to DER for CA %s: %s'
                    ) % (ca.unique_name, str(exc)),
                )
                return redirect('pki:issuing_cas')

            response = HttpResponse(crl_der, content_type='application/pkix-crl')
            response['Content-Disposition'] = f'attachment; filename="{ca.unique_name}.crl.der"'
        else:
            response = HttpResponse(crl_pem, content_type='application/x-pem-file')
            response['Content-Disposition'] = f'attachment; filename="{ca.unique_name}.crl"'
        return response


class IssuingCaViewSet(LoggerMixin, viewsets.ReadOnlyModelViewSet[CaModel]):
    """ViewSet for managing Issuing CA instances via REST API."""

    queryset = CaModel.objects.exclude(
        ca_type__in=[CaModel.CaTypeChoice.KEYLESS, CaModel.CaTypeChoice.AUTOGEN_ROOT]
    ).order_by('-created_at')
    serializer_class = IssuingCaSerializer
    permission_classes = (IsAuthenticated,)
    filter_backends = (
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    )
    filterset_fields: ClassVar = ['unique_name', 'is_active']
    search_fields: ClassVar = ['unique_name', 'credential__certificate__common_name']
    ordering_fields: ClassVar = ['unique_name', 'created_at', 'updated_at']

    # ignoring untyped decorator (drf-yasg not typed)
    @swagger_auto_schema(
        operation_summary='List Issuing CAs',
        operation_description='Retrieve all Issuing CAs from the database.',
        tags=['issuing-cas'],
    )  # type: ignore[misc]
    def list(self, _request: HttpRequest, *_args: Any, **_kwargs: Any) -> Response:
        """API endpoint to get all Issuing CAs."""
        queryset = self.get_queryset()

        for backend in list(self.filter_backends):
            if hasattr(backend, 'filter_queryset'):
                queryset = backend().filter_queryset(self.request, queryset, self)  # type: ignore[attr-defined]

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        operation_summary='Retrieve Issuing CA',
        operation_description='Retrieve details of a specific Issuing CA by ID.',
        tags=['issuing-cas'],
    )  # type: ignore[misc]
    def retrieve(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        """API endpoint to get a single Issuing CA by ID."""
        return super().retrieve(request, *args, **kwargs)  # type: ignore[arg-type]

    @action(
        detail=True,
        methods=['post'],
        permission_classes=[IsAuthenticated],
        url_path='generate-crl',
    )
    @swagger_auto_schema(
        operation_summary='Generate CRL',
        operation_description=(
            'Manually generate a new Certificate Revocation List (CRL) for this Issuing CA. '
            'No request body is required.'
        ),
        tags=['issuing-cas'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            title='Empty',
            properties={},
        ),
        responses={
            200: openapi.Response(
                description='CRL generated successfully',
                examples={
                    'application/json': {
                        'message': 'CRL generated successfully for Issuing CA "MyCA".',
                        'last_crl_issued_at': '2025-12-02T16:30:00Z',
                    }
                },
            ),
            500: 'Failed to generate CRL',
        },
    )  # type: ignore[misc]
    def generate_crl(self, _request: HttpRequest, **_kwargs: Any) -> Response:
        """Generate a new CRL for this Issuing CA."""
        ca = self.get_object()

        if ca.issue_crl():
            return Response(
                {
                    'message': f'CRL generated successfully for Issuing CA "{ca.unique_name}".',
                    'last_crl_issued_at': ca.last_crl_issued_at,
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            {'error': f'Failed to generate CRL for Issuing CA "{ca.unique_name}".'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    @action(
        detail=True,
        methods=['get'],
        permission_classes=[IsAuthenticated],
        url_path='crl',
    )
    @swagger_auto_schema(
        operation_summary='Download CRL',
        operation_description=(
            'Download the Certificate Revocation List (CRL) for this Issuing CA. '
            'Requires authentication. '
            'Supports both PEM (default) and DER formats via the format query parameter. '
            'If no CRL is available, use the POST /api/issuing-cas/<pk>/generate-crl/ endpoint to generate one first.'
        ),
        tags=['issuing-cas'],
        manual_parameters=[
            openapi.Parameter(
                'encoding',
                openapi.IN_QUERY,
                description='CRL encoding: "pem" (default) or "der"',
                type=openapi.TYPE_STRING,
                enum=['pem', 'der'],
                default='pem',
            ),
        ],
        responses={
            200: 'CRL file downloaded successfully',
            400: 'Invalid format parameter',
            404: openapi.Response(
                description='CRL not available for this Issuing CA',
                examples={
                    'application/json': {
                        'error': 'No CRL available for Issuing CA "MyCA".',
                        'hint': 'Generate a CRL first using POST /api/issuing-cas/1/generate-crl/',
                    }
                },
            ),
        },
    )  # type: ignore[misc]
    def crl(self, request: HttpRequest, **_kwargs: Any) -> HttpResponse:
        """Download the CRL for this Issuing CA."""
        ca = self.get_object()
        crl_pem = ca.crl_pem

        if not crl_pem:
            return Response(
                {
                    'error': f'No CRL available for Issuing CA "{ca.unique_name}".',
                    'hint': f'Generate a CRL first using POST /api/issuing-cas/{ca.pk}/generate-crl/',
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        crl_format = request.GET.get('encoding', 'pem').lower()

        if crl_format not in ('pem', 'der'):
            return Response(
                {'error': 'Invalid format parameter. Must be "pem" or "der".'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if crl_format == 'pem':
            response = HttpResponse(crl_pem, content_type='application/x-pem-file')
            response['Content-Disposition'] = f'attachment; filename="{ca.unique_name}.crl"'
        else:  # der
            try:
                crl_obj = x509.load_pem_x509_crl(crl_pem.encode(), default_backend())
                crl_der = crl_obj.public_bytes(encoding=serialization.Encoding.DER)
                response = HttpResponse(crl_der, content_type='application/pkix-crl')
                response['Content-Disposition'] = f'attachment; filename="{ca.unique_name}.crl"'
            except (ValueError, TypeError):
                self.logger.exception('Failed to convert CRL to DER format')
                return Response(
                    {'error': 'Failed to convert CRL to DER format'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        return response
