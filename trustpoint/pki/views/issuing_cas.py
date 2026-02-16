"""Views for Issuing CA management."""

from __future__ import annotations

import binascii
from base64 import b64decode
from typing import TYPE_CHECKING, Any, ClassVar, NamedTuple, cast

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: TC002
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
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiExample,
    OpenApiParameter,
    extend_schema,
    inline_serializer,
)
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
from pki.models import CaModel, CertificateModel, CredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.credential import CertificateChainOrderModel, PrimaryCredentialCertificate
from pki.models.truststore import TruststoreModel
from pki.serializer.issuing_ca import IssuingCaSerializer
from pki.util.cert_profile import ProfileValidationError
from request.clients import EstClient, EstClientError
from request.clients.cmp_client import CmpClient, CmpClientError
from request.message_builder.cmp import CmpMessageBuilder
from request.operation_processor.csr_build import ProfileAwareCsrBuilder
from request.operation_processor.csr_sign import EstDeviceCsrSignProcessor
from request.request_context import CmpCertificateRequestContext, EstCertificateRequestContext
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
    from rest_framework.request import Request


class CmpContextParams(NamedTuple):
    """Parameters for creating a CMP certificate request context."""
    subject: x509.Name
    public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    recipient_name: str
    extensions: list[x509.Extension[x509.ExtensionType]] | None
    sender_kid: int | None


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
                messages.warning(
                    self.request,
                    'Truststore with id %s does not exist. Ignoring truststore_id parameter.',
                    truststore_id
                )
        return kwargs

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle both association and import form submissions."""
        if 'trust_store_file' in request.FILES:
            return self._handle_import(request)
        return super().post(request, *args, **kwargs)

    def _handle_import(self, request: HttpRequest) -> HttpResponse:
        """Handle truststore import from modal."""
        import_form = TruststoreAddForm(request.POST, request.FILES)
        ca = self.get_ca()

        if import_form.is_valid():
            truststore = import_form.cleaned_data['truststore']

            expected_usage = self._get_expected_truststore_usage(ca)
            if truststore.intended_usage != expected_usage:
                usage_name = TruststoreModel.IntendedUsage(expected_usage).label
                import_form.add_error(
                    'intended_usage',
                    _('For this CA configuration, only "{usage}" truststores are allowed.').format(
                        usage=usage_name
                    )
                )
                context = self.get_context_data()
                context['import_form'] = import_form
                return self.render_to_response(context)

            messages.success(
                request,
                _('Successfully imported truststore {name}.').format(name=truststore.unique_name),
            )
            return HttpResponseRedirect(
                reverse('pki:issuing_cas-truststore-association', kwargs={'pk': ca.pk}) +
                f'?truststore_id={truststore.id}'
            )

        context = self.get_context_data()
        context['import_form'] = import_form
        return self.render_to_response(context)

    def _get_expected_truststore_usage(self, ca: CaModel) -> int:
        """Get the expected truststore intended_usage for the given CA type and state.

        Args:
            ca: The CA model instance

        Returns:
            The expected IntendedUsage value
        """
        if ca.ca_type in [CaModel.CaTypeChoice.REMOTE_ISSUING_CMP, CaModel.CaTypeChoice.REMOTE_CMP_RA]:
            return TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN

        if ca.ca_type == CaModel.CaTypeChoice.REMOTE_EST_RA:
            # Step 1: CA chain, Step 2: TLS cert
            if not ca.certificate:
                return TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN
            return TruststoreModel.IntendedUsage.TLS

        # Default for other EST CAs
        return TruststoreModel.IntendedUsage.TLS

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the CA and import form to the context."""
        context = super().get_context_data(**kwargs)
        ca = self.get_ca()
        context['ca'] = ca
        import_form = TruststoreAddForm()
        intended_usage_field = cast('ChoiceField', import_form.fields['intended_usage'])

        # Filter choices based on CA type
        if ca.ca_type in [CaModel.CaTypeChoice.REMOTE_ISSUING_CMP, CaModel.CaTypeChoice.REMOTE_CMP_RA]:
            # Only allow ISSUING_CA_CHAIN for CMP RAs
            intended_usage_field.choices = [
                choice for choice in intended_usage_field.choices  # type: ignore[union-attr]
                if isinstance(choice, tuple) and choice[0] == TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN
            ]
        elif ca.ca_type == CaModel.CaTypeChoice.REMOTE_EST_RA:
            if not ca.certificate:
                # Step 1: CA chain
                intended_usage_field.choices = [
                    choice for choice in intended_usage_field.choices  # type: ignore[union-attr]
                    if isinstance(choice, tuple) and choice[0] == TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN
                ]
            else:
                # Step 2: TLS cert
                intended_usage_field.choices = [
                    choice for choice in intended_usage_field.choices  # type: ignore[union-attr]
                    if isinstance(choice, tuple) and choice[0] == TruststoreModel.IntendedUsage.TLS
                ]

        context['import_form'] = import_form
        # Add flag to differentiate between EST and CMP/RA for helpful hints
        context['is_cmp'] = ca.ca_type in [
            CaModel.CaTypeChoice.REMOTE_ISSUING_CMP,
            CaModel.CaTypeChoice.REMOTE_CMP_RA
        ]
        context['is_est_ra'] = ca.ca_type == CaModel.CaTypeChoice.REMOTE_EST_RA
        context['est_ra_step'] = 1 if (context['is_est_ra'] and not ca.certificate) else 2
        return context

    def _handle_ra_certificate_extraction(self, ca: CaModel) -> bool:
        """Extract RA certificate and parent from CA chain truststore.

        Args:
            ca: The CA model instance (must be an RA type)

        Returns:
            True if this was a CA chain association (requiring TLS cert next for EST RA), False otherwise
        """
        if not (ca.no_onboarding_config and ca.no_onboarding_config.trust_store):
            return False

        truststore = ca.no_onboarding_config.trust_store

        if truststore.intended_usage != TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN:
            return False

        if not truststore.truststoreordermodel_set.exists():
            return False

        first_cert_order = truststore.truststoreordermodel_set.order_by('order').first()
        if not first_cert_order:
            return False

        ca.certificate = first_cert_order.certificate

        cert_orders = list(truststore.truststoreordermodel_set.order_by('order'))
        if len(cert_orders) >= 2:  # noqa: PLR2004
            issuer_cert = cert_orders[1].certificate
            issuer_ca = CaModel.objects.filter(certificate=issuer_cert).first()
            if issuer_ca:
                ca.parent_ca = issuer_ca

        ca.chain_truststore = truststore

        ca.save(update_fields=['certificate', 'parent_ca', 'chain_truststore'])
        return True

    def form_valid(self, form: IssuingCaTruststoreAssociationForm) -> HttpResponse:
        """Handle successful form submission."""
        form.save()
        ca = self.get_ca()

        if ca.ca_type in [CaModel.CaTypeChoice.REMOTE_EST_RA, CaModel.CaTypeChoice.REMOTE_CMP_RA]:
            is_ca_chain = self._handle_ra_certificate_extraction(ca)

            if ca.ca_type == CaModel.CaTypeChoice.REMOTE_EST_RA and is_ca_chain:
                messages.success(
                    self.request,
                    _('Successfully associated CA chain. Now please associate the TLS server certificate.')
                )
                return redirect('pki:issuing_cas-truststore-association', pk=ca.pk)

        messages.success(
            self.request,
            _('Successfully associated truststore with Issuing CA {name}.').format(name=ca.unique_name)
        )
        if ca.ca_type == CaModel.CaTypeChoice.REMOTE_ISSUING_EST:
            return redirect('pki:issuing_cas-define-cert-content-est', pk=ca.pk)
        if ca.ca_type == CaModel.CaTypeChoice.REMOTE_EST_RA:
            return redirect('pki:issuing_cas-config', pk=ca.pk)
        if ca.ca_type == CaModel.CaTypeChoice.REMOTE_CMP_RA:
            return redirect('pki:issuing_cas-config', pk=ca.pk)
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
        raw_profile = self.cert_profile.profile
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
        self.logger.info('Form cleaned_data: %s', form.cleaned_data)
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



class RemoteRaAddRequestCmpMixin(IssuingCaContextMixin):
    """Mixin for CMP RA configuration views."""

    def form_valid(self, form: IssuingCaAddRequestCmpForm) -> HttpResponse:
        """Handle successful CMP RA configuration submission."""
        ca = form.save(is_ra_mode=True)
        messages.success(
            self.request,  # type: ignore[attr-defined]
            _('Successfully configured CMP RA {name}. Please associate a trust store.').format(name=ca.unique_name)
        )
        return redirect('pki:issuing_cas-truststore-association', pk=ca.pk)



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


class RemoteRaAddRequestCmpView(RemoteRaAddRequestCmpMixin, FormView[IssuingCaAddRequestCmpForm]):
    """View to configure a remote CMP RA (Registration Authority)."""

    form_class = IssuingCaAddRequestCmpForm
    template_name = 'pki/issuing_cas/add/cmp_ra.html'


class RemoteRaAddRequestEstMixin(IssuingCaContextMixin):
    """Mixin for EST RA configuration views."""

    def form_valid(self, form: IssuingCaAddRequestEstForm) -> HttpResponse:
        """Handle successful EST RA configuration submission."""
        ca = form.save(is_ra_mode=True)
        messages.success(
            self.request,  # type: ignore[attr-defined]
            _('Successfully configured EST RA {name}. Please associate the CA chain trust store.').format(
                name=ca.unique_name
            )
        )
        return redirect('pki:issuing_cas-truststore-association', pk=ca.pk)



class RemoteRaAddRequestEstView(RemoteRaAddRequestEstMixin, FormView[IssuingCaAddRequestEstForm]):
    """View to configure a remote EST RA (Registration Authority)."""

    form_class = IssuingCaAddRequestEstForm
    template_name = 'pki/issuing_cas/add/est_ra.html'


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

        ca_cert = issuing_ca.ca_certificate_model
        if ca_cert:
            issuer_public_bytes = ca_cert.subject_public_bytes
            issued_certificates = CertificateModel.objects.filter(issuer_public_bytes=issuer_public_bytes)
        else:
            issued_certificates = CertificateModel.objects.none()

        context['issued_certificates'] = issued_certificates
        context['active_crl'] = issuing_ca.get_active_crl()

        if issuing_ca.is_issuing_ca and issuing_ca.credential:
            context['certificate_chain'] = issuing_ca.credential.ordered_certificate_chain_queryset
        elif issuing_ca.chain_truststore:
            if issuing_ca.ca_type in [CaModel.CaTypeChoice.REMOTE_EST_RA, CaModel.CaTypeChoice.REMOTE_CMP_RA]:
                context['certificate_chain'] = issuing_ca.chain_truststore.truststoreordermodel_set.filter(
                    order__gt=0
                ).order_by('order')
            else:
                context['certificate_chain'] = issuing_ca.chain_truststore.truststoreordermodel_set.order_by('order')
        else:
            context['certificate_chain'] = []

        return context

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests."""
        return super().get(request, *args, **kwargs)


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

    def _perform_est_enrollment(self, ca: CaModel, cert_content_data: dict[str, Any], request: HttpRequest) -> None:
        """Perform the EST enrollment process."""
        cert_profile = CertificateProfileModel.objects.get(unique_name='issuing_ca')

        request_data = self._build_request_data_from_form(cert_content_data)
        self.logger.info('Built request data: %s', request_data)

        context = EstCertificateRequestContext(
            operation='simpleenroll',
            protocol='est',
            domain=None,
            cert_profile_str='issuing_ca',
            certificate_profile_model=cert_profile,
            allow_ca_certificate_request=True,  # Allow CA cert requests for Issuing CA enrollment
            est_server_host=ca.remote_host,
            est_server_port=ca.remote_port,
            est_server_path=ca.remote_path,
            est_username=ca.est_username,
            est_password=(
                ca.no_onboarding_config.est_password
                if ca.no_onboarding_config else None
            ),
            est_server_truststore=(
                ca.no_onboarding_config.trust_store
                if ca.no_onboarding_config else None
            ),
        )

        context.request_data = request_data
        context.owner_credential = ca.credential

        csr_builder = ProfileAwareCsrBuilder()
        csr_builder.process_operation(context)
        csr = csr_builder.get_csr()

        context.cert_requested = csr

        # Use EstDeviceCsrSignProcessor to re-sign the CSR with the proper signature algorithm
        csr_signer = EstDeviceCsrSignProcessor()
        csr_signer.process_operation(context)
        signed_csr = csr_signer.get_signed_csr()

        # Send the re-signed CSR to the remote EST server
        est_client = EstClient(context)
        issued_cert = est_client.simple_enroll(signed_csr)

        cert_pem = issued_cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode())
        cert_model = CertificateModel.save_certificate(cert_obj)

        if ca.credential:
            ca.credential.certificate = cert_model
            ca.credential.save()
        else:
            credential = CredentialModel(
                credential_type=CredentialModel.CredentialTypeChoice.ISSUING_CA,
                certificate=cert_model,
                private_key=ca.credential.private_key if ca.credential else '',
            )
            credential.save()
            credential.certificates.add(cert_model)
            PrimaryCredentialCertificate.objects.create(
                credential=credential,
                certificate=cert_model,
                is_primary=True
            )
            ca.credential = credential
            ca.save()

        del request.session[f'cert_content_data_{ca.pk}']

    def _build_request_data_from_form(self, cert_content_data: dict[str, Any]) -> dict[str, Any]:
        """Build request data structure from form data.

        Args:
            cert_content_data: Form data containing certificate fields.

        Returns:
            Request data in the format expected by the profile verifier.
        """
        self.logger.info('Building request data from: %s', cert_content_data)
        request_data: dict[str, Any] = {
            'subj': {},
            'ext': {
                'subject_alternative_name': {}
            },
            'validity': {}
        }

        # Subject fields
        required_subject_fields = ['common_name', 'organization_name', 'country_name', 'state_or_province_name']
        for field_name in required_subject_fields:
            value = cert_content_data.get(field_name)
            if value:
                request_data['subj'][field_name] = value

        # SAN fields
        san_fields = {
            'dns_names': 'dns_names',
            'ip_addresses': 'ip_addresses',
            'rfc822_names': 'rfc822_names',
            'uris': 'uris'
        }

        for profile_key, form_key in san_fields.items():
            value = cert_content_data.get(form_key)
            if value is not None:
                request_data['ext']['subject_alternative_name'][profile_key] = value

        # Validity fields
        validity_fields = ['days', 'hours', 'minutes', 'seconds']
        for field in validity_fields:
            value = cert_content_data.get(field)
            if value is not None:
                request_data['validity'][field] = int(value)

        return request_data

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Handle POST request to request certificate via EST."""
        ca = self.get_object()

        cert_content_key = f'cert_content_data_{ca.pk}'
        cert_content_data = request.session.get(cert_content_key)

        self.logger.info('Cert content data for CA %s: %s', ca.pk, cert_content_data)

        if not cert_content_data:
            messages.error(
                request,
                _(
                    'Certificate content data not found. '
                    'Please define the certificate content first.'
                )
            )
            return redirect('pki:issuing_cas-define-cert-content-est', pk=ca.pk)

        try:
            self._perform_est_enrollment(ca, cert_content_data, request)
            messages.success(
                request,
                _('Successfully enrolled certificate for Issuing CA {name} via EST.').format(name=ca.unique_name)
            )
            return redirect('pki:issuing_cas-config', pk=ca.pk)
        except (ValueError, KeyError, ProfileValidationError) as exc:
            messages.error(request, _('Failed to build certificate request: {error}').format(error=str(exc)))
            return redirect('pki:issuing_cas-define-cert-content-est', pk=ca.pk)
        except CertificateProfileModel.DoesNotExist:
            messages.error(request, _('Certificate profile "issuing_ca" not found.'))
            return redirect('pki:issuing_cas-define-cert-content-est', pk=ca.pk)
        except EstClientError as exc:
            self.logger.exception('EST client error during certificate enrollment')
            messages.error(
                request,
                _('Failed to enroll certificate via EST: {error}').format(error=str(exc))
            )
            return redirect(self.redirect_url_name, pk=ca.pk)
        except Exception as exc:
            self.logger.exception('Unexpected error during EST certificate enrollment')
            messages.error(
                request,
                _('Unexpected error during certificate enrollment: {error}').format(error=str(exc))
            )
            return redirect(self.redirect_url_name, pk=ca.pk)


class IssuingCaRequestCertCmpView(IssuingCaRequestCertMixin, DetailView[CaModel]):   # type: ignore[misc]
    """View to display the CMP certificate request page."""

    template_name = 'pki/issuing_cas/request_cert_cmp.html'
    ca_type_filter = CaModel.CaTypeChoice.REMOTE_ISSUING_CMP
    redirect_url_name = 'pki:issuing_cas-request-cert-cmp'

    def get_not_implemented_message(self) -> str:
        """Get the not implemented message for CMP."""
        return _('CMP certificate request not yet implemented.')

    def _perform_cmp_enrollment(
        self,
        ca: CaModel,
        cert_content_data: dict[str, Any],
        request: HttpRequest,
        *,
        sender_kid: int | None = None,
    ) -> None:
        """Perform the CMP enrollment process."""
        cert_profile = CertificateProfileModel.objects.get(unique_name='issuing_ca')

        request_data = self._build_request_data_from_form(cert_content_data)
        self.logger.info('Built request data: %s', request_data)

        context = CmpCertificateRequestContext(
            operation='certification',
            protocol='cmp',
            domain=None,
            cert_profile_str='issuing_ca',
            certificate_profile_model=cert_profile,
            allow_ca_certificate_request=True,
            cmp_server_host=ca.remote_host,
            cmp_server_port=ca.remote_port,
            cmp_server_path=ca.remote_path,
            cmp_shared_secret=(
                ca.no_onboarding_config.cmp_shared_secret
                if ca.no_onboarding_config else None
            ),
            cmp_server_truststore=(
                ca.no_onboarding_config.trust_store
                if ca.no_onboarding_config else None
            ),
        )

        context.request_data = request_data
        context.owner_credential = ca.credential

        csr_builder = ProfileAwareCsrBuilder()
        csr_builder.process_operation(context)
        csr = csr_builder.get_csr()

        if not csr.subject or len(csr.subject) == 0:
            msg = 'CSR does not have a subject - cannot build CMP request'
            raise ValueError(msg)

        self.logger.info('CSR subject: %s', csr.subject.rfc4514_string())

        csr_subject = csr.subject
        csr_public_key = csr.public_key()
        csr_extensions = list(csr.extensions) if csr.extensions else None

        self.logger.info('CSR has %d extensions', len(csr.extensions) if csr.extensions else 0)

        recipient_name = self._get_recipient_name_from_truststore(ca)

        private_key = self._load_private_key(ca)

        cmp_params = CmpContextParams(
            subject=csr_subject,
            public_key=cast('rsa.RSAPublicKey | ec.EllipticCurvePublicKey', csr_public_key),
            private_key=private_key,
            recipient_name=recipient_name,
            extensions=csr_extensions,
            sender_kid=sender_kid,
        )

        cmp_context = self._create_cmp_context(ca, cmp_params)

        cmp_builder = CmpMessageBuilder()
        cmp_builder.build(cmp_context)

        pki_message = cmp_context.parsed_message

        cmp_client = CmpClient(cmp_context)
        issued_cert, chain_certs = cmp_client.send_and_extract_certificate(
            pki_message,
            add_shared_secret_protection=True,
        )

        self._save_cmp_certificates(ca, issued_cert, chain_certs)

        del request.session[f'cert_content_data_{ca.pk}']

    def _build_request_data_from_form(self, cert_content_data: dict[str, Any]) -> dict[str, Any]:
        """Build request data structure from form data.

        Args:
            cert_content_data: Form data containing certificate fields.

        Returns:
            Request data in the format expected by the profile verifier.
        """
        self.logger.info('Building request data from: %s', cert_content_data)
        request_data: dict[str, Any] = {
            'subj': {},
            'ext': {
                'subject_alternative_name': {}
            },
            'validity': {}
        }

        # Subject fields
        required_subject_fields = ['common_name', 'organization_name', 'country_name', 'state_or_province_name']
        for field_name in required_subject_fields:
            value = cert_content_data.get(field_name)
            if value:
                request_data['subj'][field_name] = value

        # SAN fields
        san_fields = {
            'dns_names': 'dns_names',
            'ip_addresses': 'ip_addresses',
            'rfc822_names': 'rfc822_names',
            'uris': 'uris'
        }

        for profile_key, form_key in san_fields.items():
            value = cert_content_data.get(form_key)
            if value is not None:
                request_data['ext']['subject_alternative_name'][profile_key] = value

        # Validity fields
        validity_fields = ['days', 'hours', 'minutes', 'seconds']
        for field in validity_fields:
            value = cert_content_data.get(field)
            if value is not None:
                request_data['validity'][field] = int(value)

        return request_data

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Handle POST request to request certificate via CMP."""
        ca = self.get_object()

        cert_content_key = f'cert_content_data_{ca.pk}'
        cert_content_data = request.session.get(cert_content_key)

        self.logger.info('Cert content data for CA %s: %s', ca.pk, cert_content_data)

        if not cert_content_data:
            messages.error(
                request,
                _(
                    'Certificate content data not found. '
                    'Please define the certificate content first.'
                )
            )
            return redirect('pki:issuing_cas-define-cert-content-cmp', pk=ca.pk)

        # Extract optional sender_kid from the form
        sender_kid_raw = request.POST.get('sender_kid', '').strip()
        sender_kid: int | None = int(sender_kid_raw) if sender_kid_raw else None

        try:
            self._perform_cmp_enrollment(ca, cert_content_data, request, sender_kid=sender_kid)
            messages.success(
                request,
                _('Successfully enrolled certificate for Issuing CA {name} via CMP.').format(name=ca.unique_name)
            )
            return redirect('pki:issuing_cas-config', pk=ca.pk)
        except (ValueError, KeyError, ProfileValidationError) as exc:
            messages.error(request, _('Failed to build certificate request: {error}').format(error=str(exc)))
            return redirect('pki:issuing_cas-define-cert-content-cmp', pk=ca.pk)
        except CertificateProfileModel.DoesNotExist:
            messages.error(request, _('Certificate profile "issuing_ca" not found.'))
            return redirect('pki:issuing_cas-define-cert-content-cmp', pk=ca.pk)
        except CmpClientError as exc:
            self.logger.exception('CMP client error during certificate enrollment')
            messages.error(
                request,
                _('Failed to enroll certificate via CMP: {error}').format(error=str(exc))
            )
            return redirect(self.redirect_url_name, pk=ca.pk)
        except Exception as exc:
            self.logger.exception('Unexpected error during CMP certificate enrollment')
            messages.error(
                request,
                _('Unexpected error during certificate enrollment: {error}').format(error=str(exc))
            )
            return redirect(self.redirect_url_name, pk=ca.pk)

    def _get_recipient_name_from_truststore(self, ca: CaModel) -> str:
        """Extract recipient name from the CA's truststore."""
        if not ca.no_onboarding_config or not ca.no_onboarding_config.trust_store:
            msg = 'No truststore configured for CMP CA - recipient name cannot be determined'
            raise ValueError(msg)

        try:
            truststore_certs = ca.no_onboarding_config.trust_store.truststoreordermodel_set.order_by('order')
            if not truststore_certs.exists():
                msg = 'Truststore contains no certificates - cannot determine recipient name'
                raise ValueError(msg)

            first_cert_model = truststore_certs.first().certificate  # type: ignore[union-attr]
            ca_cert = first_cert_model.get_certificate_serializer().as_crypto()
            recipient_name = ca_cert.subject.rfc4514_string()
            self.logger.info('Using recipient name from truststore: %s', recipient_name)
        except (AttributeError, IndexError) as e:
            msg = f'Failed to extract recipient name from truststore: {e}'
            raise ValueError(msg) from e
        else:
            return recipient_name

    def _load_private_key(self, ca: CaModel) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
        """Load the private key from the CA's credential."""
        if not ca.credential or not ca.credential.private_key:
            msg = 'No private key available for CA credential'
            raise ValueError(msg)

        return cast(
            'rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey',
            serialization.load_pem_private_key(
                ca.credential.private_key.encode(),
                password=None,
            ),
        )

    def _create_cmp_context(
        self,
        ca: CaModel,
        params: CmpContextParams,
    ) -> CmpCertificateRequestContext:
        """Create the CMP certificate request context."""
        return CmpCertificateRequestContext(
            protocol='cmp',
            operation='certification',
            cmp_server_host=ca.remote_host,
            cmp_server_port=ca.remote_port,
            cmp_server_path=ca.remote_path,
            cmp_shared_secret=(
                ca.no_onboarding_config.cmp_shared_secret
                if ca.no_onboarding_config else None
            ),
            cmp_server_truststore=(
                ca.no_onboarding_config.trust_store
                if ca.no_onboarding_config else None
            ),
            request_data={
                'subject': params.subject,
                'public_key': params.public_key,
                'private_key': params.private_key,
                'recipient_name': params.recipient_name,
                'extensions': params.extensions,
                'use_initialization_request': False,
                'add_pop': True,
                'prepare_shared_secret_protection': True,
                'sender_kid': params.sender_kid,
            },
        )

    def _save_cmp_certificates(
        self,
        ca: CaModel,
        issued_cert: x509.Certificate,
        chain_certs: list[x509.Certificate],
    ) -> None:
        """Save the issued certificate and chain certificates."""
        cert_model = CertificateModel.save_certificate(issued_cert)

        chain_ca_models = []
        for chain_cert in chain_certs:
            existing_ca = self._find_existing_ca_for_certificate(chain_cert)
            if existing_ca:
                chain_ca_models.append(existing_ca)
            else:
                cn_attrs = chain_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                cn = cn_attrs[0].value if cn_attrs else 'unknown'
                keyless_ca = CaModel.create_keyless_ca(
                    unique_name=str(cn),
                    certificate_obj=chain_cert,
                    parent_ca=None,
                )
                chain_ca_models.append(keyless_ca)
                self.logger.info('Created keyless CA %s for chain certificate', keyless_ca.unique_name)

        self._build_ca_hierarchy(chain_ca_models)

        issuer_ca = self._find_issuer_ca(issued_cert, chain_ca_models)
        if issuer_ca:
            ca.parent_ca = issuer_ca
            ca.save()
            self.logger.info('Set parent CA %s for issuing CA %s', issuer_ca.unique_name, ca.unique_name)

        if ca.credential:
            ca.credential.certificate = cert_model
            ca.credential.save()
            self._build_certificate_chain_for_credential(ca.credential, ca.parent_ca)
        else:
            credential = CredentialModel(
                credential_type=CredentialModel.CredentialTypeChoice.ISSUING_CA,
                certificate=cert_model,
                private_key=ca.credential.private_key if ca.credential else '',
            )
            credential.save()
            credential.certificates.add(cert_model)
            PrimaryCredentialCertificate.objects.create(
                credential=credential,
                certificate=cert_model,
                is_primary=True
            )
            ca.credential = credential
            ca.save()
            self._build_certificate_chain_for_credential(credential, ca.parent_ca)

    def _build_ca_hierarchy(
        self,
        chain_ca_models: list[CaModel],
    ) -> None:
        """Build the CA hierarchy by setting parent-child relationships."""
        ca_by_subject = {}
        for ca in chain_ca_models:
            cert = ca.get_certificate()
            if cert:
                ca_by_subject[cert.subject.public_bytes().hex()] = ca

        for ca in chain_ca_models:
            cert = ca.get_certificate()
            if not cert:
                continue
            issuer_subject_bytes = cert.issuer.public_bytes().hex()
            if issuer_subject_bytes in ca_by_subject:
                parent_ca = ca_by_subject[issuer_subject_bytes]
                if parent_ca not in (ca, ca.parent_ca):
                    ca.parent_ca = parent_ca
                    ca.save()
                    self.logger.info('Set parent CA %s for CA %s', parent_ca.unique_name, ca.unique_name)

    def _find_issuer_ca(
        self,
        issued_cert: x509.Certificate,
        chain_ca_models: list[CaModel],
    ) -> CaModel | None:
        """Find the CA that issued the certificate."""
        issuer_subject_bytes = issued_cert.issuer.public_bytes().hex()
        for ca in chain_ca_models:
            ca_cert = ca.get_certificate()
            if ca_cert and ca_cert.subject.public_bytes().hex() == issuer_subject_bytes:
                return ca
        return None

    def _build_certificate_chain_for_credential(self, credential: CredentialModel, parent_ca: CaModel | None) -> None:
        """Build the certificate chain for the credential."""
        if not parent_ca or not credential.certificate:
            return
        chain = []
        current: CaModel | None = parent_ca
        while current:
            if current.certificate:
                chain.append(current.certificate)
            current = current.parent_ca
        credential.certificatechainordermodel_set.all().delete()
        primary_cert = credential.certificate
        for i, cert in enumerate(chain):
            CertificateChainOrderModel.objects.create(
                credential=credential, certificate=cert, order=i, primary_certificate=primary_cert
            )

    def _find_existing_ca_for_certificate(self, cert: x509.Certificate) -> CaModel | None:
        """Find an existing CA that has the given certificate."""
        # TODO(FHK): comparing the subject public bytes is not sufficient  # noqa: FIX002
        for existing_ca in CaModel.objects.filter(certificate__isnull=False):
            try:
                ca_cert = existing_ca.get_certificate()
                if ca_cert and (ca_cert.subject.public_bytes() == cert.subject.public_bytes() and
                    ca_cert.issuer.public_bytes() == cert.issuer.public_bytes()):
                    return existing_ca
            except (AttributeError, ValueError) as e:
                self.logger.debug('Error checking existing keyless CA certificate: %s', e)
                continue

        for existing_ca in CaModel.objects.filter(credential__isnull=False):
            try:
                ca_cert = existing_ca.get_certificate()
                if ca_cert and (ca_cert.subject.public_bytes() == cert.subject.public_bytes() and
                    ca_cert.issuer.public_bytes() == cert.issuer.public_bytes()):
                    return existing_ca
            except (AttributeError, ValueError) as e:
                self.logger.debug('Error checking existing issuing CA certificate: %s', e)
                continue

        return None


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
        """Return only issuing CAs (excluding RAs and keyless CAs)."""
        return super().get_queryset().exclude(
            ca_type__in=[
                CaModel.CaTypeChoice.KEYLESS,
                CaModel.CaTypeChoice.AUTOGEN_ROOT,
                CaModel.CaTypeChoice.REMOTE_EST_RA,
                CaModel.CaTypeChoice.REMOTE_CMP_RA,
            ]
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

@extend_schema(tags=['Issuing-CA'])
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

    @extend_schema(
        summary='List Issuing CAs',
        description='Retrieve all Issuing CAs from the database.',
    )
    def list(self, _request: Request) -> Response:
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

    @extend_schema(
        summary='Retrieve Issuing CA',
        description='Retrieve details of a specific Issuing CA by ID.',
    )
    def retrieve(self, request: Request) -> Response:
        """API endpoint to get a single Issuing CA by ID."""
        return super().retrieve(request)

    @extend_schema(
        summary='Generate CRL',
        description=(
            'Manually generate a new Certificate Revocation List (CRL) for this Issuing CA. '
            'No request body is required.'
        ),
        request=inline_serializer(name='Empty', fields={}),
        responses={
            200: OpenApiTypes.OBJECT,
            500: OpenApiTypes.OBJECT,
        },
        examples=[
            OpenApiExample(
                name='CRL Generated',
                value={
                    'message': 'CRL generated successfully for Issuing CA "MyCA".',
                    'last_crl_issued_at': '2025-12-02T16:30:00Z',
                },
                response_only=True,
                status_codes=[200],
                media_type='application/json',
            ),
            OpenApiExample(
                name='Server Error',
                value={
                    'detail': 'Failed to generate CRL'
                },
                response_only=True,
                status_codes=[500],
                media_type='application/json',
            ),
        ],
    )
    @action(
        detail=True,
        methods=['post'],
        permission_classes=[IsAuthenticated],
        url_path='generate-crl',
    )
    def generate_crl(self, _request: Request, pk: int | None = None, **_kwargs: Any) -> Response:
        """Generate a new CRL for this Issuing CA."""
        del pk # not needed, but passed by DRF
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

    @extend_schema(
        summary='Download CRL',
        description=(
            'Download the Certificate Revocation List (CRL) for this Issuing CA. '
            'Requires authentication. '
            'Supports both PEM (default) and DER formats via the format query parameter. '
            'If no CRL is available, use the POST /api/issuing-cas/<pk>/generate-crl/ endpoint to generate one first.'
        ),
        parameters=[
            OpenApiParameter(
                'encoding',
                location=OpenApiParameter.QUERY,
                description='CRL encoding: "pem" (default) or "der"',
                type=OpenApiTypes.STR,
                enum=['pem', 'der'],
                default='pem',
            ),
        ],
        responses={
            200: OpenApiTypes.OBJECT,
            400: OpenApiTypes.OBJECT,
            404: OpenApiTypes.OBJECT
        },
        examples=[
            OpenApiExample(
                name='CRL Generated',
                value={
                    'detail': 'CRL file downloaded successfully.',
                },
                response_only=True,
                status_codes=[200],
                media_type='application/json',
            ),
            OpenApiExample(
                name='Invalid format parameter',
                value={
                    'error': 'No CRL available for Issuing CA "MyCA".',
                    'hint': 'Generate a CRL first using POST /api/issuing-cas/1/generate-crl/',
                },
                response_only=True,
                status_codes=[400],
                media_type='application/json',
            ),
            OpenApiExample(
                name='Not Found',
                value={
                    'error': 'No CRL available for Issuing CA "MyCA".',
                    'hint': 'Generate a CRL first using POST /api/issuing-cas/1/generate-crl/',
                },
                response_only=True,
                status_codes=[404],
                media_type='application/json',
            ),
        ],
    )
    @action(
        detail=True,
        methods=['get'],
        permission_classes=[IsAuthenticated],
        url_path='crl',
    )
    def crl(self, request: Request, pk: int | None = None, **_kwargs: Any) -> Response | HttpResponse:
        """Download the CRL for this Issuing CA."""
        del pk # not needed, but passed by DRF
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


class RaConfigView(LoggerMixin, IssuingCaContextMixin, DetailView[CaModel]):
    """View to display the details of an RA (Registration Authority)."""

    model = CaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    template_name = 'pki/issuing_cas/ra_config.html'
    context_object_name = 'ra'

    def get_queryset(self) -> QuerySet[CaModel, CaModel]:
        """Return only RA CAs."""
        return super().get_queryset().filter(
            ca_type__in=[CaModel.CaTypeChoice.REMOTE_EST_RA, CaModel.CaTypeChoice.REMOTE_CMP_RA]
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds RA-specific information to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data()

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        ra = self.get_object()

        if ra.chain_truststore:
            truststore_certificates = [
                cert_order.certificate
                for cert_order in ra.chain_truststore.truststoreordermodel_set.order_by('order')
            ]
        else:
            truststore_certificates = []

        context['truststore_certificates'] = truststore_certificates
        context['active_crl'] = None
        return context
