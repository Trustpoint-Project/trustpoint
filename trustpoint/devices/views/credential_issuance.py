"""Views for device credential issuance workflows."""

import abc
import asyncio
import json
from typing import Any, cast

from cryptography import x509
from django import forms
from django.contrib import messages
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.http.request import HttpRequest
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext_lazy, ngettext
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormMixin, FormView

from devices.forms import (
    BaseCredentialForm,
    IssueDomainCredentialForm,
    IssueOpcUaGdsPushDomainCredentialForm,
    OpcUaGdsPushTruststoreAssociationForm,
)

# noinspection PyUnresolvedReferences
from devices.issuer import (
    BaseTlsCredentialIssuer,
    LocalDomainCredentialIssuer,
)
from devices.models import (
    DeviceModel,
)
from onboarding.models import (
    NoOnboardingPkiProtocol,
    OnboardingPkiProtocol,
)
from pki.forms import TruststoreAddForm
from pki.forms.cert_profiles import CertificateIssuanceForm
from pki.models import IssuedCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.domain import DomainAllowedCertificateProfileModel
from pki.models.truststore import TruststoreModel
from request.authorization import ManualAuthorization
from request.gds_push import GdsPushService
from request.operation_processor.issue_cred import CredentialIssueProcessor
from request.request_context import ManualCredentialRequestContext
from trustpoint.logger import LoggerMixin
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

class AbstractNoOnboardingIssueNewApplicationCredentialView(PageContextMixin, DetailView[DeviceModel]):
    """Abstract view for selecting how to issue a new application credential for a no-onboarding device."""

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/credentials/issue_credential.html'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the sections to the context.

        Args:
            **kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data for the view.
        """
        context = super().get_context_data(**kwargs)
        context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'
        context['heading'] = 'Issue New Application Credential'
        sections = []

        if not self.object.no_onboarding_config:
            err_msg = gettext_lazy('Device is configured for onboarding')
            raise ValueError(err_msg)

        sections.append(
            {
                'heading': gettext_lazy('CMP with OpenSSL (shared-secret)'),
                'description': gettext_lazy(
                    'This option will guide you through all steps and commands that are '
                    'required to issue a new application certificate '
                    'using CMP with OpenSSL using a shared-secret (HMAC).'
                ),
                'protocol': 'cmp-shared-secret',
                'enabled': self.object.no_onboarding_config.has_pki_protocol(NoOnboardingPkiProtocol.CMP_SHARED_SECRET),
                'url': f'{self.page_category}:{self.page_name}_no_onboarding_cmp_shared_secret_help',
            }
        )

        sections.append(
            {
                'heading': gettext_lazy('EST with OpenSSL and curL (username & password)'),
                'description': gettext_lazy(
                    'This option will guide you through all steps and commands that are '
                    'required to issue a new application certificate using EST using OpenSSL and curL.'
                ),
                'protocol': 'est-username-password',
                'enabled': self.object.no_onboarding_config.has_pki_protocol(
                    NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD
                ),
                'url': f'{self.page_category}:{self.page_name}_no_onboarding_est_username_password_help',
            }
        )

        sections.append(
            {
                'heading': gettext_lazy('Manual Issuance'),
                'description': gettext_lazy(
                    'This option will allow you to issue a new domain credential on the Trustpoint. '
                    'The domain credential can then be downloaded for manual injection into the device, '
                    'e.g., using a USB-stick.'
                ),
                'protocol': 'manual',
                'enabled': self.object.no_onboarding_config.has_pki_protocol(NoOnboardingPkiProtocol.MANUAL),
                'url': f'{self.page_category}:{self.page_name}_no_onboarding_select_certificate_profile',
            }
        )

        sections.append(
            {
                'heading': gettext_lazy('REST with curl (username & password)'),
                'description': gettext_lazy(
                    'This option will guide you through all steps and commands that are '
                    'required to issue a new application certificate using REST with curl.'
                ),
                'protocol': 'rest-username-password',
                'enabled': self.object.no_onboarding_config.has_pki_protocol(
                    NoOnboardingPkiProtocol.REST_USERNAME_PASSWORD
                ),
                'url': f'{self.page_category}:{self.page_name}_no_onboarding_rest_username_password_help',
            }
        )



        context['sections'] = sections

        return context

    def _get_redirect_url(self) -> HttpResponseRedirect:
        return redirect(f'{self.page_category}:{self.page_name}_certificate_lifecycle_management', pk=self.object.pk)

    def get(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Adds checks if the device is configured for no-onboarding and has a domain set.

        Args:
            request: The django request object.
            *_args: Positional arguments are discarded.
            **_kwargs: Keyword arguments are discarded.

        Returns:
            The HttpResponse Or HttpRedirect to the CLM page.
        """
        self.object = self.get_object()

        if not self.object.no_onboarding_config:
            err_msg = gettext_lazy('This device is configured for onboarding.')
            messages.warning(request, err_msg)
            return self._get_redirect_url()

        if not self.object.no_onboarding_config.get_pki_protocols():
            err_msg = gettext_lazy(
                'All PKI protocols for this device to request application certifciates are disabled.'
            )
            messages.warning(request, err_msg)
            return self._get_redirect_url()

        if not self.object.domain:
            err_msg = gettext_lazy('No domain is configured for this device.')
            messages.warning(request, err_msg)
            return self._get_redirect_url()

        context = self.get_context_data(object=self.object)
        return self.render_to_response(context)


class DeviceNoOnboardingIssueNewApplicationCredentialView(AbstractNoOnboardingIssueNewApplicationCredentialView):
    """Issue a new application credential for a no-onboarding device in the Devices section."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsNoOnboardingIssueNewApplicationCredentialView(AbstractNoOnboardingIssueNewApplicationCredentialView):
    """Issue a new application credential for a no-onboarding OPC UA GDS device."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class AbstractSelectCertificateProfileNewApplicationCredentialView(PageContextMixin, DetailView[DeviceModel]):
    """abc."""

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/credentials/profile_select.html'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the sections to the context.

        Args:
            **kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data for the view.
        """
        context = super().get_context_data(**kwargs)

        domain = self.object.domain
        if not domain:
            err_msg = gettext_lazy('No domain is configured for this device.')
            raise ValueError(err_msg)

        allowed_app_profiles = list(
            domain.get_allowed_cert_profiles().exclude(certificate_profile__unique_name='domain_credential'))
        profile_list = DomainAllowedCertificateProfileModel.get_list_of_display_names(allowed_app_profiles)

        context['cert_profile_list'] = {}
        for (profile_id, display_name, _unique_name) in profile_list:
            context['cert_profile_list'][profile_id] = display_name

        context['profile_issuance_url'] = \
            f'{self.page_category}:{self.page_name}_certificate_lifecycle_management_issue_profile_credential'

        return context


class DeviceSelectCertificateProfileNewApplicationCredentialView(
    AbstractSelectCertificateProfileNewApplicationCredentialView
):
    """abc."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsSelectCertificateProfileNewApplicationCredentialView(
    AbstractSelectCertificateProfileNewApplicationCredentialView
):
    """abc."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class AbstractOnboardingIssueNewApplicationCredentialView(PageContextMixin, DetailView[DeviceModel]):
    """abc."""

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/credentials/issue_credential.html'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the sections to the context.

        Args:
            **kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data for the view.
        """
        context = super().get_context_data(**kwargs)
        context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'
        context['heading'] = 'Issue New Application Credential'
        sections = []

        if not self.object.onboarding_config:
            err_msg = gettext_lazy('Device is not configured for onboarding')
            raise ValueError(err_msg)

        sections.append(
            {
                'heading': gettext_lazy('CMP with Domain Credential'),
                'description': gettext_lazy(
                    'This option will guide you through all steps and commands that are '
                    'required to issue a new application certificate using CMP '
                    'with OpenSSL using a shared-secret (HMAC).'
                ),
                'protocol': 'cmp',
                'enabled': self.object.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.CMP),
                'url': (
                    f'{self.page_category}:{self.page_name}_onboarding_clm_issue_application_credential_cmp_domain_credential'
                ),
            }
        )

        sections.append(
            {
                'heading': gettext_lazy('EST with Domain Credential'),
                'description': gettext_lazy(
                    'This option will guide you through all steps and commands that are '
                    'required to issue a new application certificate using EST using OpenSSL and curL.'
                ),
                'protocol': 'est',
                'enabled': self.object.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.EST),
                'url': (
                    f'{self.page_category}:{self.page_name}_onboarding_clm_issue_application_credential_est_domain_credential'
                ),
            }
        )

        sections.append(
            {
                'heading': gettext_lazy('REST with Domain Credential'),
                'description': gettext_lazy(
                    'This option will guide you through all steps and commands that are '
                    'required to issue a new application certificate using REST using curL.'
                ),
                'protocol': 'rest',
                'enabled': self.object.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.REST),
                'url': (
                    f'{self.page_category}:{self.page_name}_onboarding_clm_issue_application_credential_rest_domain_credential'
                ),
            }
        )

        context['sections'] = sections

        return context


class DeviceOnboardingIssueNewApplicationCredentialView(AbstractOnboardingIssueNewApplicationCredentialView):
    """abc."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsOnboardingIssueNewApplicationCredentialView(AbstractOnboardingIssueNewApplicationCredentialView):
    """abc."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class OpcUaGdsPushOnboardingIssueNewApplicationCredentialView(AbstractOnboardingIssueNewApplicationCredentialView):
    """View for issuing application credentials for OPC UA GDS Push devices - redirects directly to help page."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

    def get(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Redirect directly to the GDS Push application certificate help page if GDS Push is the only protocol."""
        self.object = self.get_object()

        if not self.object.onboarding_config:
            err_msg = gettext_lazy('Device is not configured for onboarding')
            messages.warning(request, err_msg)
            return redirect(
                f'{self.page_category}:{self.page_name}_certificate_lifecycle_management',
                pk=self.object.pk
            )

        if not self.object.onboarding_config.get_pki_protocols():
            err_msg = gettext_lazy(
                'All PKI protocols for this device to request application certificates are disabled.'
            )
            messages.warning(request, err_msg)
            return redirect(
                f'{self.page_category}:{self.page_name}_certificate_lifecycle_management',
                pk=self.object.pk
            )

        if not self.object.domain:
            err_msg = gettext_lazy('No domain is configured for this device.')
            messages.warning(request, err_msg)
            return redirect(
                f'{self.page_category}:{self.page_name}_certificate_lifecycle_management',
                pk=self.object.pk
            )

        # If CMP or EST are enabled, show the protocol selection page
        if (
            self.object.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.CMP)
            or self.object.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.EST)
        ):
            return super().get(request, *_args, **_kwargs)

        # Otherwise, redirect directly to the GDS Push application certificate help page
        return redirect(
            f'{self.page_category}:{self.page_name}_onboarding_clm_issue_application_credential_opc_ua_gds_push_domain_credential',
            pk=self.object.pk
        )


class AbstractIssueCredentialView[FormClass: forms.Form, IssuerClass: BaseTlsCredentialIssuer](
    PageContextMixin, FormMixin[forms.Form], DetailView[DeviceModel]
):
    """Base view for all credential issuance views."""

    http_method_names = ('get', 'post')

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/credentials/issue_application_credential.html'

    form_class: type[forms.Form]
    issuer_class: type[IssuerClass]
    friendly_name: str

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the form to the context.

        Args:
            **kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data for the view.
        """
        context = super().get_context_data(**kwargs)
        if 'form' not in kwargs:
            context['form'] = self.form_class(**self.get_form_kwargs())

        context['clm_url'] = f'devices:{self.page_name}_certificate_lifecycle_management'
        return context

    def get_form_kwargs(self) -> dict[str, Any]:
        """This method adds the concerning device model to the form kwargs and returns them.

        Returns:
            The form kwargs including the concerning device model.
        """
        if self.object.domain is None:
            raise Http404(DeviceWithoutDomainErrorMsg)

        form_kwargs = {}
        if not issubclass(self.form_class, CertificateIssuanceForm):
            form_kwargs = {
                'initial': self.issuer_class.get_fixed_values(device=self.object, domain=self.object.domain),
                'prefix': None,
                'device': self.object,
            }

        if self.request.method == 'POST':
            form_kwargs.update({'data': self.request.POST})

        return form_kwargs

    @abc.abstractmethod
    def issue_credential(self, device: DeviceModel, form: forms.Form) -> IssuedCredentialModel:
        """Abstract method to issue a credential.

        Args:
            device: The device to be associated with the new credential.
            form: The form instance containing the validated data.

        Returns:
            The IssuedCredentialModel object that was created and saved.
        """

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Adds the object model to the instance and forwards to super().post().

        Args:
            request: The Django request object is only used implicitly through self.
            *_args: Positional arguments are discarded.
            **_kwargs: Keyword arguments are discarded.

        Returns:
            The HttpResponseBase object returned by super().post().
        """
        self.object = self.get_object()
        form = self.form_class(**self.get_form_kwargs())

        if form.is_valid():
            try:
                credential = self.issue_credential(device=self.object, form=form)
                del credential  # result unused beyond this point
                messages.success(
                    request, f'Successfully issued {self.friendly_name} for device {self.object.common_name}'
                )
            except Exception as e:  # noqa: BLE001
                messages.error(request, f'Failed to issue {self.friendly_name}: {e}')
            return HttpResponseRedirect(
                reverse_lazy(
                    f'devices:{self.page_name}_certificate_lifecycle_management', kwargs={'pk': self.get_object().id}
                )
            )

        return self.render_to_response(self.get_context_data(form=form))


class AbstractIssueDomainCredentialView(
    AbstractIssueCredentialView[IssueDomainCredentialForm, LocalDomainCredentialIssuer]
):
    """Base view for issuing domain credentials."""

    form_class: type[BaseCredentialForm] = IssueDomainCredentialForm
    template_name = 'devices/credentials/issue_domain_credential.html'
    issuer_class = LocalDomainCredentialIssuer
    friendly_name = 'Domain Credential'

    def issue_credential(self, device: DeviceModel, _form: forms.Form) -> IssuedCredentialModel:
        """Issue a domain credential for the device.

        Args:
            device: The device to issue the credential for.
            _form: The form instance containing the validated data.

        Returns:
            The issued credential model.
        """
        if device.domain is None:
            err_msg = gettext_lazy('Device has no domain configured.')
            raise Http404(err_msg)

        issuer = self.issuer_class(device=device, domain=device.domain)
        return issuer.issue_domain_credential()


class DeviceIssueDomainCredentialView(AbstractIssueDomainCredentialView):
    """View for issuing domain credentials for devices."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsIssueDomainCredentialView(AbstractIssueDomainCredentialView):
    """View for issuing domain credentials for OPC-UA GDS devices."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class OpcUaGdsPushIssueDomainCredentialView(AbstractIssueDomainCredentialView):
    """View for issuing domain credentials for OPC-UA GDS Push devices."""

    form_class = IssueOpcUaGdsPushDomainCredentialForm
    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

    def issue_credential(self, device: DeviceModel, form: forms.Form) -> IssuedCredentialModel:
        """Issues a domain credential for the device with OPC UA specific extensions.

        Args:
            device: The device to be associated with the new credential.
            form: The form instance containing the validated data.

        Returns:
            The IssuedCredentialModel object that was created and saved.
        """
        if not device.domain:
            raise Http404(DeviceWithoutDomainErrorMsg)

        issuer = self.issuer_class(device=device, domain=device.domain)
        application_uri = cast('str', form.cleaned_data.get('application_uri'))

        opc_ua_extensions = [
            (
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=True,  # Required for OPC UA SignAndEncrypt security mode
                    data_encipherment=True,  # Additional encryption capability
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            ),
            (x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), False),
        ]

        if application_uri:
            opc_ua_extensions.append(
                (x509.SubjectAlternativeName([x509.UniformResourceIdentifier(application_uri)]), False)
            )

        return issuer.issue_domain_credential(
            application_uri=None,
            extra_extensions=opc_ua_extensions
        )

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Handle the POST request with custom redirect to truststore association."""
        self.object = self.get_object()
        form = self.form_class(**self.get_form_kwargs())

        if form.is_valid():
            self.issue_credential(device=self.object, form=form)
            messages.success(
                request, f'Successfully issued {self.friendly_name} for device {self.object.common_name}'
            )
            return HttpResponseRedirect(
                reverse_lazy(
                    f'devices:{self.page_name}_truststore_association', kwargs={'pk': self.get_object().id}
                )
            )

        return self.render_to_response(self.get_context_data(form=form))


class OpcUaGdsPushDiscoverServerView(PageContextMixin, DetailView[DeviceModel]):
    """View to discover OPC UA server information without authentication."""

    http_method_names = ('post',)
    model = DeviceModel
    context_object_name = 'device'
    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Handle the POST request to discover server information."""
        self.object = self.get_object()

        try:
            service = GdsPushService(device=self.object, insecure=True)

            success, message, server_info = asyncio.run(service.discover_server())

            if success and server_info:
                messages.success(request, message)

                request.session['opc_ua_server_info'] = server_info

                if server_info.get('server_certificate_available'):
                    messages.info(
                        request,
                        'Server certificate found. You can update the truststore with this certificate.'
                    )
            else:
                messages.error(request, f'Failed to discover server: {message}')

        except Exception as e:  # noqa: BLE001
            messages.error(request, f'Unexpected error during discovery: {e}')

        return HttpResponseRedirect(
            reverse_lazy(
                f'devices:{self.page_name}_onboarding_truststore_associated_help',
                kwargs={'pk': self.object.pk}
            )
        )


class OpcUaGdsPushTruststoreAssociationView(
    LoggerMixin, PageContextMixin, FormView[OpcUaGdsPushTruststoreAssociationForm]
):
    """View for associating a truststore with an OPC UA GDS Push device's onboarding configuration."""

    form_class = OpcUaGdsPushTruststoreAssociationForm
    template_name = 'devices/truststore_association.html'
    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

    def get_form_kwargs(self) -> dict[str, Any]:
        """Add the device instance to the form kwargs."""
        kwargs = super().get_form_kwargs()
        kwargs['instance'] = self.get_device()
        truststore_id = self.request.GET.get('truststore_id')
        if truststore_id:
            try:
                truststore = TruststoreModel.objects.get(pk=truststore_id)
                kwargs['initial'] = kwargs.get('initial', {})
                kwargs['initial']['opc_trust_store'] = truststore
            except TruststoreModel.DoesNotExist:
                self.logger.warning(
                    'Truststore with id %s does not exist. Ignoring truststore_id parameter.', truststore_id
                )

        return kwargs

    def get_device(self) -> DeviceModel:
        """Get the device from the URL parameters."""
        pk = self.kwargs.get('pk')
        try:
            return DeviceModel.objects.get(pk=pk)
        except DeviceModel.DoesNotExist as e:
            exc_msg = f'Device with pk {pk} does not exist.'
            raise Http404(exc_msg) from e

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the device and import form to the context."""
        context = super().get_context_data(**kwargs)
        context['device'] = self.get_device()
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
            n_certificates = truststore.number_of_certificates
            msg_str = ngettext(
                'Successfully created the Truststore %(name)s with %(count)i certificate.',
                'Successfully created the Truststore %(name)s with %(count)i certificates.',
                n_certificates,
            ) % {
                'name': truststore.unique_name,
                'count': n_certificates,
            }
            messages.success(request, msg_str)

            return HttpResponseRedirect(
                reverse('devices:devices_truststore_association', kwargs={'pk': self.get_device().pk}) +
                f'?truststore_id={truststore.id}'
            )

        context = self.get_context_data()
        context['import_form'] = import_form
        return self.render_to_response(context)

    def form_valid(self, form: OpcUaGdsPushTruststoreAssociationForm) -> HttpResponseRedirect:
        """Handle successful form submission."""
        form.save()
        messages.success(
            self.request,
            f'Successfully associated truststore with device {self.get_device().common_name}'
        )
        return HttpResponseRedirect(
            reverse_lazy(
                f'devices:{DEVICES_PAGE_DEVICES_SUBCATEGORY}_onboarding_truststore_associated_help',
                kwargs={'pk': self.get_device().pk}
            )
        )


class AbstractIssueProfileCredentialView(
    AbstractIssueCredentialView[CertificateIssuanceForm, BaseTlsCredentialIssuer]
):
    """View to issue a new certificate profile credential."""

    issuer_class = BaseTlsCredentialIssuer
    friendly_name = 'Certificate Profile Credential'

    page_name: str

    template_name = 'pki/cert_profiles/issuance.html'
    form_class = CertificateIssuanceForm

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Dispatch the request, ensuring the profile exists."""
        self.profile = get_object_or_404(CertificateProfileModel, pk=kwargs['profile_id'])
        return cast('HttpResponse', super().dispatch(request, *args, **kwargs))

    def get_form_kwargs(self) -> dict[str, Any]:
        """Get form kwargs, including the profile."""
        kwargs = super().get_form_kwargs()
        raw_profile = json.loads(self.profile.profile_json)
        kwargs['profile'] = raw_profile
        return kwargs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context data."""
        context = super().get_context_data(**kwargs)
        context['profile'] = self.profile
        context['profile_dict'] = self.get_form_kwargs()['profile']
        return context

    def form_invalid(self, form: forms.Form) -> HttpResponse:
        """Handle the case where the form is invalid."""
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(self.request, f'{field}: {error}')
        return super().form_invalid(form)

    def form_valid(self, form: forms.Form) -> HttpResponse:
        """Handle the case where the form is valid."""
        if not isinstance(form, CertificateIssuanceForm):
            err_msg = 'Invalid form type. Expected CertificateIssuanceForm.'
            messages.error(self.request, err_msg)
            return self.form_invalid(form)
        try:
            self.cert_builder = form.get_certificate_builder()
        except ValueError as e:
            messages.error(self.request,
                           gettext_lazy('Error generating certificate builder: {error}').format(error=str(e)))
            return self.form_invalid(form)

        messages.success(
            self.request,
            gettext_lazy('Certificate builder generated successfully.'),
        )
        return HttpResponseRedirect(reverse_lazy('pki:cert_profiles'))

    def issue_credential(self, device: DeviceModel, form: forms.Form
                         ) -> IssuedCredentialModel:
        """Issues a credential based on the selected certificate profile.

        Args:
            device: The device to be associated with the new credential.
            form: The form instance containing the validated data.

        Returns:
            The IssuedCredentialModel object that was created and saved.
        """
        if not isinstance(form, CertificateIssuanceForm):
            err_msg = 'Invalid form type. Expected CertificateIssuanceForm.'
            raise TypeError(err_msg)
        cert_builder = form.get_certificate_builder()
        if not device.domain:
            raise Http404(DeviceWithoutDomainErrorMsg)

        ctx = ManualCredentialRequestContext(
            device=device,
            domain=device.domain,
            cert_profile_str=self.profile.unique_name,
            cert_requested=cert_builder,
            actor=self.request.user if self.request.user.is_authenticated else None,
        )
        ManualAuthorization().authorize(ctx)
        CredentialIssueProcessor().process_operation(ctx)
        if not ctx.issued_credential:
            err_msg = 'Issued credential not in context.'
            raise ValueError(err_msg)
        return ctx.issued_credential


class DeviceIssueProfileCredentialView(AbstractIssueProfileCredentialView):
    """Issue a new certificate profile credential within the devices section."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsIssueProfileCredentialView(AbstractIssueProfileCredentialView):
    """Issue a new certificate profile credential within the devices section."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY

