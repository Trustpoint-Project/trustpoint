# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Views for OPC UA GDS Push certificate distribution."""

import asyncio
import io
import zipfile
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.contrib import messages
from django.db import transaction
from django.http import FileResponse, Http404, HttpResponse, HttpResponseRedirect
from django.http.request import HttpRequest
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy
from django.views.generic.detail import DetailView

# noinspection PyUnresolvedReferences
from devices.models import (
    DeviceModel,
)
from onboarding.models import (
    OnboardingProtocol,
    OnboardingStatus,
)
from pki.models import IssuedCredentialModel
from pki.models.ca import CaModel
from request.gds_push import GdsPushService
from request.gds_push.gds_push_service import GdsPushError
from trustpoint.page_context import (
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    PageContextMixin,
)
from trustpoint.views.base import UserPermissionRequiredMixin
from users.permissions import AppPermissions

DeviceWithoutDomainErrorMsg = gettext_lazy('Device does not have an associated domain.')
NamedCurveMissingForEccErrorMsg = gettext_lazy('Failed to retrieve named curve for ECC algorithm.')
ActiveTrustpointTlsServerCredentialModelMissingErrorMsg = gettext_lazy(
    'No active trustpoint TLS server credential found.'
)

# This only occurs if no domain is configured
PublicKeyInfoMissingErrorMsg = DeviceWithoutDomainErrorMsg

class OpcUaGdsPushUpdateTrustlistView(PageContextMixin, DetailView[DeviceModel]):
    """View to update the trustlist on an OPC UA GDS Push device."""

    http_method_names = ('post',)
    model = DeviceModel
    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    page_category = DEVICES_PAGE_CATEGORY

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Handle the POST request to update the trustlist.

        Args:
            request: The Django request object.
            _args: Positional arguments are discarded.
            kwargs: Keyword arguments are passed to get_object().

        Returns:
            HttpResponse redirecting back to the help page.
        """
        self.object = self.get_object()

        try:
            service = GdsPushService(device=self.object)

            success, message = asyncio.run(service.update_trustlist())

            if success:
                messages.success(request, f'Trustlist updated successfully: {message}')
            else:
                messages.error(request, f'Failed to update trustlist: {message}')

        except GdsPushError as e:
            messages.error(request, f'GDS Push error: {e}')
        except Exception as e:  # noqa: BLE001
            messages.error(request, f'Unexpected error: {e}')

        return self._redirect_to_help_page()

    def _redirect_to_help_page(self) -> HttpResponseRedirect:
        """Redirect back to the help page.

        Returns:
            HttpResponseRedirect to the help page.
        """
        return HttpResponseRedirect(
            reverse_lazy(
                f'{self.page_category}:{self.page_name}_onboarding_truststore_associated_help',
                kwargs={'pk': self.object.pk}
            )
        )

class OpcUaGdsPushUpdateServerCertificateView(PageContextMixin, DetailView[DeviceModel]):
    """View to update the server certificate on an OPC UA GDS Push device."""

    http_method_names = ('post',)
    model = DeviceModel
    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    page_category = DEVICES_PAGE_CATEGORY

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Handle the POST request to update the server certificate.

        Args:
            request: The Django request object.
            _args: Positional arguments are discarded.
            kwargs: Keyword arguments are passed to get_object().

        Returns:
            HttpResponse redirecting back to the help page.
        """
        self.object = self.get_object()

        try:

            service = GdsPushService(device=self.object)

            success, message, certificate_bytes = asyncio.run(service.update_server_certificate())

            if success and certificate_bytes:
                messages.success(request, f'Server certificate updated successfully: {message}')

                if self.object.onboarding_config:
                    self.object.onboarding_config.onboarding_status = OnboardingStatus.ONBOARDED
                    self.object.onboarding_config.save()

            else:
                messages.error(request, f'Failed to update server certificate: {message}')

        except GdsPushError as e:
            messages.error(request, f'GDS Push error: {e}')
        except Exception as e:  # noqa: BLE001
            messages.error(request, f'Unexpected error: {e}')

        return self._redirect_to_help_page()

    def _redirect_to_help_page(self) -> HttpResponseRedirect:
        """Redirect back to the help page.

        Returns:
            HttpResponseRedirect to the help page.
        """
        referer = self.request.META.get('HTTP_REFERER', '')
        if referer and 'issue-application-credential' in referer:
            return HttpResponseRedirect(
                reverse_lazy(
                    f'{self.page_category}:{self.page_name}_onboarding_clm_issue_application_credential_opc_ua_gds_push_domain_credential',
                    kwargs={'pk': self.object.pk}
                )
            )
        return HttpResponseRedirect(
            reverse_lazy(
                f'{self.page_category}:{self.page_name}_onboarding_truststore_associated_help',
                kwargs={'pk': self.object.pk}
            )
        )


class OpcUaGdsPushCertRenewalSettingsView(PageContextMixin, DetailView[DeviceModel]):
    """View to save the periodic server certificate and trustlist renewal settings for an OPC UA GDS Push device."""

    http_method_names = ('post',)
    model = DeviceModel
    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    page_category = DEVICES_PAGE_CATEGORY

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Handle the POST request to update the renewal settings.

        Args:
            request: The Django request object.
            _args: Positional arguments are discarded.
            _kwargs: Keyword arguments are discarded.

        Returns:
            HttpResponse redirecting back to the help page.
        """
        self.object = self.get_object()

        enable = request.POST.get('opc_gds_push_enable_periodic_update') == 'on'
        interval_raw = request.POST.get('opc_gds_push_renewal_interval', '')

        try:
            interval = int(interval_raw)
            if interval < 1:
                err_msg = 'Interval must be at least 1.'
                raise ValueError(err_msg)  # noqa: TRY301
        except (ValueError, TypeError):
            messages.error(
                request,
                gettext_lazy('Invalid renewal interval. Please enter a positive integer (hours).')
            )
            return self._redirect_to_help_page()

        self.object.opc_ua_gds_push_config.opc_gds_push_enable_periodic_update = enable
        self.object.opc_ua_gds_push_config.opc_gds_push_renewal_interval = interval
        self.object.opc_ua_gds_push_config.save(
            update_fields=['opc_gds_push_enable_periodic_update', 'opc_gds_push_renewal_interval']
        )

        if enable:
            messages.success(
                request,
                gettext_lazy(
                    f'Periodic server certificate and trustlist renewal enabled (every {interval} hour(s)).'
                )
            )
        else:
            messages.success(
                request,
                gettext_lazy('Periodic server certificate and trustlist renewal disabled.')
            )

        return self._redirect_to_help_page()

    def _redirect_to_help_page(self) -> HttpResponseRedirect:
        """Redirect back to the application certificate help page.

        Returns:
            HttpResponseRedirect to the help page.
        """
        return HttpResponseRedirect(
            reverse_lazy(
                f'{self.page_category}:{self.page_name}_onboarding_clm_issue_application_credential_opc_ua_gds_push_domain_credential',
                kwargs={'pk': self.object.pk}
            )
        )


class OpcUaGdsPushDomainCredentialRenewalSettingsView(
    UserPermissionRequiredMixin, PageContextMixin, DetailView[DeviceModel],
):
    """Save the independent periodic GDS Push domain credential renewal settings."""

    permission_required = AppPermissions.MANAGE_DEVICES

    http_method_names = ('post',)
    model = DeviceModel
    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    page_category = DEVICES_PAGE_CATEGORY

    @transaction.atomic
    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Validate the interval and schedule or cancel renewal on the onboarding page."""
        self.object = self.get_object(queryset=self.get_queryset().select_for_update())
        if (
            self.object.device_type != DeviceModel.DeviceType.OPC_UA_GDS_PUSH
            or not self.object.onboarding_config
            or self.object.onboarding_config.onboarding_protocol != OnboardingProtocol.OPC_GDS_PUSH
        ):
            raise Http404(gettext_lazy('Device is not configured for OPC UA GDS Push onboarding.'))
        redirect = HttpResponseRedirect(reverse_lazy(
            f'{self.page_category}:{self.page_name}_onboarding_truststore_associated_help',
            kwargs={'pk': self.object.pk},
        ))
        enabled = request.POST.get('opc_gds_push_enable_domain_credential_renewal') == 'on'
        try:
            interval = int(request.POST.get('opc_gds_push_domain_credential_renewal_interval', ''))
            if interval < 1:
                message = 'Interval must be at least 1.'
                raise ValueError(message)  # noqa: TRY301
        except (ValueError, TypeError):
            messages.error(request, gettext_lazy('Invalid renewal interval. Please enter a positive integer (hours).'))
            return redirect
        if enabled and (self.object.domain is None or not self.object.issued_credentials.filter(
            domain=self.object.domain,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
            credential__certificate__isnull=False,
            credential__certificate__revoked_certificate__isnull=True,
        ).exists()):
            messages.error(
                request, gettext_lazy('Issue an initial domain credential before enabling periodic renewal.')
            )
            return redirect
        self.object.opc_ua_gds_push_config.opc_gds_push_enable_domain_credential_renewal = enabled
        self.object.opc_ua_gds_push_config.opc_gds_push_domain_credential_renewal_interval = interval
        self.object.opc_ua_gds_push_config.save(update_fields=[
            'opc_gds_push_enable_domain_credential_renewal', 'opc_gds_push_domain_credential_renewal_interval',
        ])
        if enabled:
            messages.success(request, gettext_lazy(
                'Periodic domain credential renewal enabled (every %(interval)s hour(s)).'
            ) % {'interval': interval})
        else:
            messages.success(request, gettext_lazy('Periodic domain credential renewal disabled.'))
        return redirect


class TrustBundleDownloadView(PageContextMixin, DetailView[CaModel]):
    """View to download the trust bundle (CA certificates and CRLs) for a given Issuing CA."""

    http_method_names = ('get',)
    model = CaModel

    def _collect_ca_chain_data(self, ca_chain: list[CaModel]) -> dict[str, bytes]:
        """Collect certificate and CRL data from CA chain.

        Args:
            ca_chain: List of CA models in the chain.

        Returns:
            Dictionary mapping filenames to file data (bytes).
        """
        data_to_archive: dict[str, bytes] = {}

        for ca in ca_chain:
            try:
                if not ca.ca_certificate_model:
                    continue
                cert_der = ca.ca_certificate_model.get_certificate_serializer().as_der()
                if cert_der is None:
                    continue

                safe_name = ''.join(c if c.isalnum() or c in '._-' else '_' for c in ca.unique_name)
                cert_filename = f'{safe_name}.der'
                data_to_archive[cert_filename] = cert_der

                if ca.crl_pem:
                    try:
                        crl_crypto = x509.load_pem_x509_crl(ca.crl_pem.encode())
                        crl_der = crl_crypto.public_bytes(serialization.Encoding.DER)
                        crl_filename = f'{safe_name}.crl'
                        data_to_archive[crl_filename] = crl_der
                    except (ValueError, TypeError):
                        pass
            except (ValueError, TypeError, AttributeError):
                continue

        return data_to_archive

    def _create_trust_bundle_zip(self, data_to_archive: dict[str, bytes]) -> bytes:
        """Create a ZIP file containing trust bundle data.

        Args:
            data_to_archive: Dictionary mapping filenames to file data.

        Returns:
            The ZIP file as bytes.

        Raises:
            Http404: If no data or ZIP creation fails.
        """
        if not data_to_archive:
            msg = 'No certificates found in truststore.'
            raise Http404(msg)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for filename, data in data_to_archive.items():
                zip_file.writestr(filename, data)
        zip_data = zip_buffer.getvalue()

        if not zip_data or len(zip_data) == 0:
            msg = f'Failed to create ZIP file. Found {len(data_to_archive)} files to archive.'
            raise Http404(msg)

        return zip_data

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:  # noqa: ARG002
        """Handle the GET request to download the trust bundle.

        Args:
            request: The Django request object.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            FileResponse with the trust bundle zip file.
        """
        self.object = self.get_object()
        issuing_ca = self.object

        try:
            ca_chain = issuing_ca.get_ca_chain_from_truststore()
        except ValueError as e:
            msg = f'Invalid truststore configuration: {e}'
            raise Http404(msg) from e

        data_to_archive = self._collect_ca_chain_data(ca_chain)
        zip_data = self._create_trust_bundle_zip(data_to_archive)

        response = FileResponse(
            io.BytesIO(zip_data),
            content_type='application/zip',
            as_attachment=True,
            filename=f'trustpoint-{self.object.unique_name}-trust-bundle.zip',
        )

        return cast('HttpResponse', response)
