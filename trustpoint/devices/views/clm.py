"""Views for certificate lifecycle management (CLM)."""

import abc
import datetime
from typing import Any, cast

from django import forms
from django.core.paginator import Paginator
from django.db.models import Q, QuerySet
from django.http import HttpResponse, HttpResponseBase
from django.http.request import HttpRequest
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.html import format_html
from django.utils.translation import gettext_lazy
from django.views.generic.detail import DetailView

from devices.forms import (
    ClmDeviceModelNoOnboardingForm,
    ClmDeviceModelOnboardingForm,
    ClmDeviceModelOpcUaGdsPushOnboardingForm,
)

# noinspection PyUnresolvedReferences
from devices.models import (
    DeviceModel,
)
from onboarding.models import (
    NoOnboardingPkiProtocol,
    OnboardingPkiProtocol,
    OnboardingProtocol,
    OnboardingStatus,
)
from pki.models import IssuedCredentialModel, RemoteIssuedCredentialModel
from pki.models.ca import CaModel
from pki.models.certificate import CertificateModel
from pki.models.credential import OwnerCredentialModel
from trustpoint.page_context import (
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    DEVICES_PAGE_OPC_UA_SUBCATEGORY,
    PageContextMixin,
)
from trustpoint.settings import UIConfig

DeviceWithoutDomainErrorMsg = gettext_lazy('Device does not have an associated domain.')
NamedCurveMissingForEccErrorMsg = gettext_lazy('Failed to retrieve named curve for ECC algorithm.')
ActiveTrustpointTlsServerCredentialModelMissingErrorMsg = gettext_lazy(
    'No active trustpoint TLS server credential found.'
)

# This only occurs if no domain is configured
PublicKeyInfoMissingErrorMsg = DeviceWithoutDomainErrorMsg

class AbstractCertificateLifecycleManagementSummaryView(PageContextMixin, DetailView[DeviceModel], abc.ABC):
    """This is the CLM summary view in the devices section."""

    http_method_names = ('get', 'post')

    model = DeviceModel
    template_name = 'devices/credentials/certificate_lifecycle_management.html'
    context_object_name = 'device'

    default_sort_param = 'common_name'
    issued_creds_qs: QuerySet[IssuedCredentialModel]
    remote_issued_creds_qs: QuerySet[RemoteIssuedCredentialModel]
    domain_credentials_qs: QuerySet[IssuedCredentialModel] | QuerySet[RemoteIssuedCredentialModel]
    application_credentials_qs: QuerySet[IssuedCredentialModel] | QuerySet[RemoteIssuedCredentialModel]

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    _RA_CA_TYPES = (CaModel.CaTypeChoice.REMOTE_EST_RA, CaModel.CaTypeChoice.REMOTE_CMP_RA)

    def _is_ra_domain(self) -> bool:
        """Return True if the device's domain uses a remote RA CA (EST or CMP)."""
        device = self.object
        if not device.domain or not device.domain.issuing_ca:
            return False
        return device.domain.issuing_ca.ca_type in self._RA_CA_TYPES

    def _get_owner_credential_for_device(self) -> OwnerCredentialModel | None:
        """Find the OwnerCredentialModel associated with this device."""
        device_domain_cred = IssuedCredentialModel.objects.filter(
            device=self.object,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
        ).select_related('credential__certificate').first()

        if device_domain_cred is None or device_domain_cred.credential.certificate is None:
            return None

        fingerprint = device_domain_cred.credential.certificate.sha256_fingerprint
        owner_ic = RemoteIssuedCredentialModel.objects.filter(
            credential__certificates__sha256_fingerprint=fingerprint,
            owner_credential__isnull=False,
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DOMAIN_CREDENTIAL,
        ).select_related('owner_credential').first()

        if owner_ic is None:
            return None
        return owner_ic.owner_credential

    def _get_dev_owner_id_credentials_qs(
        self, owner_credential: OwnerCredentialModel,
    ) -> QuerySet[RemoteIssuedCredentialModel]:
        """Return enrolled DevOwnerID credentials for the given owner credential."""
        return RemoteIssuedCredentialModel.objects.filter(
            owner_credential=owner_credential,
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
            credential__certificate__isnull=False,
        ).select_related('credential__certificate').order_by('-created_at')

    def get_issued_creds_qs(self) -> QuerySet[IssuedCredentialModel]:
        """Gets a sorted queryset of all IssuedCredentialModels.

        Returns:
            Sorted queryset of all IssuedCredentialModels.
        """
        issued_creds_qs = IssuedCredentialModel.objects.all()

        sort_param = self.request.GET.get('sort', self.default_sort_param)
        return issued_creds_qs.order_by(sort_param)

    def get_remote_issued_creds_qs(self) -> QuerySet[RemoteIssuedCredentialModel]:
        """Gets a sorted queryset of all RemoteIssuedCredentialModels for RA-issued certs."""
        sort_param = self.request.GET.get('sort', self.default_sort_param)
        return RemoteIssuedCredentialModel.objects.filter(
            device=self.object,
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.RA_DEVICE,
        ).select_related('credential__certificate', 'domain').order_by(sort_param)

    def get_domain_credentials_qs(
        self,
    ) -> QuerySet[IssuedCredentialModel] | QuerySet[RemoteIssuedCredentialModel]:
        """Gets domain credentials — from RemoteIssuedCredentialModel for RA domains, otherwise IssuedCredentialModel.

        self.get_issued_creds_qs() or self.get_remote_issued_creds_qs() must be called first!

        Returns:
            Sorted queryset of domain credentials.
        """
        if self._is_ra_domain():
            return self.remote_issued_creds_qs.none()
        return self.issued_creds_qs.filter(
            Q(device=self.object)
            & Q(issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL.value)
        )

    def get_application_credentials_qs(
        self,
    ) -> QuerySet[IssuedCredentialModel] | QuerySet[RemoteIssuedCredentialModel]:
        """Gets application credentials — from RemoteIssuedCredentialModel for RA domains.

        self.get_issued_creds_qs() or self.get_remote_issued_creds_qs() must be called first!

        Returns:
            Sorted queryset of application credentials.
        """
        if self._is_ra_domain():
            return self.remote_issued_creds_qs
        return self.issued_creds_qs.filter(
            Q(device=self.object)
            & Q(issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL.value)
        )

    def _add_credential_pages_to_context(self, context: dict[str, Any]) -> None:
        """Paginate domain, application and DevOwnerID credentials into the template context."""
        paginator_domain = Paginator(self.domain_credentials_qs, UIConfig.paginate_by)
        page_number_domain = self.request.GET.get('page', 1)
        context['domain_credentials'] = paginator_domain.get_page(page_number_domain)
        context['is_paginated'] = paginator_domain.num_pages > 1

        paginator_application = Paginator(self.application_credentials_qs, UIConfig.paginate_by)
        page_number_application = self.request.GET.get('page-a', 1)
        context['application_credentials'] = paginator_application.get_page(page_number_application)
        context['is_paginated_a'] = paginator_application.num_pages > 1

        is_ra = self._is_ra_domain()

        for cred in context['domain_credentials']:
            cred.expires_in = self._get_expires_in(cred)
            cred.expiration_date = cast('datetime.datetime', cred.credential.certificate_or_error.not_valid_after)
            cred.revoke = self._get_revoke_button_html(cred) if not is_ra else ''

        for cred in context['application_credentials']:
            cred.expires_in = self._get_expires_in(cred)
            cred.expiration_date = cast('datetime.datetime', cred.credential.certificate_or_error.not_valid_after)
            cred.revoke = self._get_revoke_button_html(cred) if not is_ra else ''

        self._add_dev_owner_id_context(context)

    def _add_dev_owner_id_context(self, context: dict[str, Any]) -> None:
        """Add DevOwnerID credentials linked via the owner credential to the context."""
        owner_credential = self._get_owner_credential_for_device()
        context['owner_credential'] = owner_credential

        if owner_credential is None:
            context['dev_owner_id_credentials'] = []
            context['is_paginated_d'] = False
            return

        dev_owner_id_qs = self._get_dev_owner_id_credentials_qs(owner_credential)
        paginator_doid = Paginator(dev_owner_id_qs, UIConfig.paginate_by)
        page_number_doid = self.request.GET.get('page-d', 1)
        context['dev_owner_id_credentials'] = paginator_doid.get_page(page_number_doid)
        context['is_paginated_d'] = paginator_doid.num_pages > 1

        for cred in context['dev_owner_id_credentials']:
            cred.expires_in = self._get_expires_in(cred)
            cred.expiration_date = cast(
                'datetime.datetime', cred.credential.certificate_or_error.not_valid_after,
            )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the paginator and credential details to the context."""
        self.issued_creds_qs = self.get_issued_creds_qs()
        self.remote_issued_creds_qs = self.get_remote_issued_creds_qs()
        self.domain_credentials_qs = self.get_domain_credentials_qs()
        self.application_credentials_qs = self.get_application_credentials_qs()
        context = super().get_context_data(**kwargs)

        context['domain_credentials'] = self.domain_credentials_qs
        context['application_credentials'] = self.application_credentials_qs

        self._add_credential_pages_to_context(context)

        context['main_url'] = f'{self.page_category}:{self.page_name}'

        is_cmp_ra = (
            self.object.domain
            and self.object.domain.issuing_ca
            and self.object.domain.issuing_ca.ca_type == CaModel.CaTypeChoice.REMOTE_CMP_RA
        )
        context['is_cmp_ra_domain'] = bool(is_cmp_ra)

        context['issue_app_cred_no_onboarding_url'] = ''
        if (
            not is_cmp_ra
            and self.object.domain
            and self.object.no_onboarding_config
            and self.object.no_onboarding_config.get_pki_protocols()
            and self.object.device_type != DeviceModel.DeviceType.AGENT_ONE_TO_N
        ):
            context['issue_app_cred_no_onboarding_url'] = (
                f'{self.page_category}:{self.page_name}_no_onboarding_clm_issue_application_credential'
            )
        issue_domain_cred_onboarding_url = ''
        if self.object.onboarding_config:
            if self.object.onboarding_config.onboarding_protocol == OnboardingProtocol.CMP_SHARED_SECRET:
                issue_domain_cred_onboarding_url = (
                    f'{self.page_category}:{self.page_name}'
                    '_certificate_lifecycle_management_issue_domain_credential_cmp_shared_secret'
                )
            elif self.object.onboarding_config.onboarding_protocol == OnboardingProtocol.EST_USERNAME_PASSWORD:
                issue_domain_cred_onboarding_url = (
                    f'{self.page_category}:{self.page_name}'
                    '_certificate_lifecycle_management_issue_domain_credential_est_username_password'
                )
            elif self.object.onboarding_config.onboarding_protocol == OnboardingProtocol.REST_USERNAME_PASSWORD:
                issue_domain_cred_onboarding_url = (
                    f'{self.page_category}:{self.page_name}'
                    '_certificate_lifecycle_management_issue_domain_credential_rest_username_password'
                )
            elif self.object.onboarding_config.onboarding_protocol == OnboardingProtocol.OPC_GDS_PUSH:
                issue_domain_cred_onboarding_url = (
                    f'{self.page_category}:{self.page_name}_onboarding_clm_issue_domain_credential'
                )

        context['issue_app_cred_onboarding_url'] = ''
        if (
            self.object.domain
            and self.object.onboarding_config
            and self.object.onboarding_config.get_pki_protocols()
            and self.object.device_type != DeviceModel.DeviceType.AGENT_ONE_TO_N
        ):
            context['issue_app_cred_onboarding_url'] = (
                f'{self.page_category}:{self.page_name}_onboarding_clm_issue_application_credential'
            )

        context['issue_domain_cred_onboarding_url'] = issue_domain_cred_onboarding_url

        context['download_url'] = f'{self.page_category}:{self.page_name}_download'

        context['help_dispatch_domain_url'] = f'{self.page_category}:{self.page_name}_help_dispatch_domain'
        context['help_dispatch_device_type_url'] = f'{self.page_category}:{self.page_name}_help_dispatch_domain'

        context['pki_protocols'] = self._get_pki_protocols(self.object)

        context['OnboardingProtocol'] = OnboardingProtocol
        context['OnboardingPkiProtocol'] = OnboardingPkiProtocol
        context['NoOnboardingPkiProtocol'] = NoOnboardingPkiProtocol
        context['OnboardingStatus'] = OnboardingStatus

        context['device_form'] = self.get_device_form()
        if self.object.onboarding_config:
            context['onboarding_form'] = self.get_onboarding_form()

        return context

    def get_onboarding_initial(self) -> dict[str, Any]:
        """Gets the initial values for onboarding.

        Returns:
            Initial values for onboarding.
        """
        if not self.object.onboarding_config:
            err_msg = gettext_lazy('The device does not have onboarding configured.')
            raise ValueError(err_msg)
        return {
            'common_name': self.object.common_name,
            'serial_number': self.object.serial_number,
            'domain': self.object.domain,
            'onboarding_protocol': self.object.onboarding_config.onboarding_protocol,
            'onboarding_status': OnboardingStatus(self.object.onboarding_config.onboarding_status).label,
            'pki_protocol_cmp': self.object.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.CMP),
            'pki_protocol_est': self.object.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.EST),
            'pki_protocol_rest': self.object.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.REST),
        }

    def get_no_onboarding_initial(self) -> dict[str, Any]:
        """Gets the initial values for no onboarding.

        Returns:
            Initial values for no onboarding.
        """
        if not self.object.no_onboarding_config:
            err_msg = gettext_lazy('The object has onboarding configured.')
            raise ValueError(err_msg)
        return {
            'common_name': self.object.common_name,
            'serial_number': self.object.serial_number,
            'domain': self.object.domain,
            'pki_protocol_cmp': self.object.no_onboarding_config.has_pki_protocol(
                NoOnboardingPkiProtocol.CMP_SHARED_SECRET
            ),
            'pki_protocol_est': self.object.no_onboarding_config.has_pki_protocol(
                NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD
            ),
            'pki_protocol_manual': self.object.no_onboarding_config.has_pki_protocol(NoOnboardingPkiProtocol.MANUAL),
            'pki_protocol_rest': self.object.no_onboarding_config.has_pki_protocol(
                NoOnboardingPkiProtocol.REST_USERNAME_PASSWORD
            ),
        }

    def get_onboarding_form(self) -> forms.Form:
        """Gets the form for onboarding.

        Returns:
            The onboarding form.
        """
        return ClmDeviceModelOnboardingForm(initial=self.get_onboarding_initial(), instance=self.object)

    def get_no_onboarding_form(self) -> ClmDeviceModelNoOnboardingForm:
        """Gets the form for no onboarding.

        Returns:
            The no onboarding form.
        """
        if self.request.method == 'POST':
            return ClmDeviceModelNoOnboardingForm(self.request.POST, instance=self.object)
        return ClmDeviceModelNoOnboardingForm(initial=self.get_no_onboarding_initial(), instance=self.object)

    def get_device_form(self) -> forms.Form:
        """Gets the device Form for onboarding or no onboarding.

        Returns:
            The required form.
        """
        if self.object.onboarding_config:
            return self.get_onboarding_form()
        return self.get_no_onboarding_form()

    @staticmethod
    def _get_expires_in(record: IssuedCredentialModel | RemoteIssuedCredentialModel) -> str:
        """Gets the remaining time until the credential expires as human-readable string.

        Args:
            record: The corresponding IssuedCredentialModel or RemoteIssuedCredentialModel.

        Returns:
            The remaining time until the credential expires as human-readable string.
        """
        cert = record.credential.certificate_or_error
        if cert.certificate_status != CertificateModel.CertificateStatus.OK:
            return str(cert.certificate_status.label)
        now = datetime.datetime.now(datetime.UTC)
        expire_timedelta = cert.not_valid_after - now
        days = expire_timedelta.days
        hours, remainder = divmod(expire_timedelta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f'{days} days, {hours}:{minutes:02d}:{seconds:02d}'

    def _get_revoke_button_html(self, record: IssuedCredentialModel | RemoteIssuedCredentialModel) -> str:
        """Gets the HTML for the revoke button in the devices table.

        Args:
            record: The corresponding IssuedCredentialModel or RemoteIssuedCredentialModel.

        Returns:
            The HTML of the hyperlink for the revoke button.
        """
        if not isinstance(record, IssuedCredentialModel):
            return ''
        cert = record.credential.certificate_or_error
        if cert.certificate_status == CertificateModel.CertificateStatus.REVOKED:
            return format_html('<a class="btn btn-danger tp-table-btn w-100 disabled">{}</a>', gettext_lazy('Revoked'))
        url = reverse(f'{self.page_category}:{self.page_name}_credential_revoke', kwargs={'pk': record.pk})
        return format_html('<a href="{}" class="btn btn-danger tp-table-btn w-100">{}</a>', url, gettext_lazy('Revoke'))

    def _get_pki_protocols(self, record: DeviceModel) -> str:
        if record.onboarding_config:
            return ', '.join([str(p.label) for p in record.onboarding_config.get_pki_protocols()])

        if record.no_onboarding_config:
            return ', '.join([str(p.label) for p in record.no_onboarding_config.get_pki_protocols()])

        return ''

    def post(self, request: HttpRequest, *_args: Any, **kwargs: Any) -> HttpResponse:
        """Handles the POST request used for device form submission.

        Args:
            request: The django request object.
            _args: Positional arguments are discarded.
            kwargs: Keyword arguments are passed to get_context_data.

        Returns:
            The HttpResponse.
        """
        self.object = self.get_object()

        form: ClmDeviceModelOnboardingForm | ClmDeviceModelNoOnboardingForm
        if self.object.onboarding_config:
            form = ClmDeviceModelOnboardingForm(request.POST, instance=self.object)
            if form.is_valid():
                form.save(onboarding_protocol=OnboardingProtocol(self.object.onboarding_config.onboarding_protocol))
        else:
            form = ClmDeviceModelNoOnboardingForm(request.POST, instance=self.object)
            if form.is_valid():
                form.save()

        context = self.get_context_data(object=self.object, **kwargs)
        return self.render_to_response(context)


class DeviceCertificateLifecycleManagementSummaryView(AbstractCertificateLifecycleManagementSummaryView):
    """Certificate Lifecycle Management Summary View for devices."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Redirect OPC UA GDS Push devices to their specific view if GDS Push is the only protocol."""
        device = self.get_object()

        if (
            device.device_type == DeviceModel.DeviceType.OPC_UA_GDS_PUSH
            and device.onboarding_config
            and not (
                device.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.CMP)
                or device.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.EST)
                or device.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.REST)
            )
        ):
            url = reverse('devices:opc_ua_gds_push_certificate_lifecycle_management', kwargs={'pk': device.pk})
            return redirect(url)

        return super().dispatch(request, *args, **kwargs)


class OpcUaGdsCertificateLifecycleManagementSummaryView(AbstractCertificateLifecycleManagementSummaryView):
    """Certificate Lifecycle Management Summary View for OPC UA Devcies."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class OpcUaGdsPushCertificateLifecycleManagementSummaryView(AbstractCertificateLifecycleManagementSummaryView):
    """Certificate Lifecycle Management Summary View for OPC UA GDS Push devices."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add OPC UA GDS Push specific context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data(**kwargs).

        Returns:
            The context data for the view.
        """
        return super().get_context_data(**kwargs)

    def get_onboarding_initial(self) -> dict[str, Any]:
        """Gets the initial values for onboarding for GDS Push.

        Returns:
            Initial values for onboarding.
        """
        if not self.object.onboarding_config:
            err_msg = gettext_lazy('The device does not have onboarding configured.')
            raise ValueError(err_msg)
        return {
            'common_name': self.object.common_name,
            'serial_number': self.object.serial_number,
            'domain': self.object.domain,
            'ip_address': self.object.ip_address,
            'opc_server_port': self.object.opc_server_port,
            'onboarding_protocol': OnboardingProtocol.OPC_GDS_PUSH.label,
            'onboarding_status': OnboardingStatus(self.object.onboarding_config.onboarding_status).label,
            'pki_protocol_opc_gds_push': self.object.onboarding_config.has_pki_protocol(
                OnboardingPkiProtocol.OPC_GDS_PUSH
            ),
        }

    def get_onboarding_form(self) -> ClmDeviceModelOpcUaGdsPushOnboardingForm:
        """Gets the form for GDS Push onboarding.

        Returns:
            The GDS Push onboarding form.
        """
        return ClmDeviceModelOpcUaGdsPushOnboardingForm(initial=self.get_onboarding_initial(), instance=self.object)

    def post(self, request: HttpRequest, *_args: Any, **kwargs: Any) -> HttpResponse:
        """Handles the POST request used for device form submission.

        Args:
            request: The django request object.
            _args: Positional arguments are discarded.
            kwargs: Keyword arguments are passed to get_context_data.

        Returns:
            The HttpResponse.
        """
        self.object = self.get_object()

        if self.object.onboarding_config:
            form = ClmDeviceModelOpcUaGdsPushOnboardingForm(request.POST, instance=self.object)
            if form.is_valid():
                form.save()
        else:
            # This shouldn't happen for GDS Push
            pass

        context = self.get_context_data(object=self.object, **kwargs)
        return self.render_to_response(context)
