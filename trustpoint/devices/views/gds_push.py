"""Views for OPC UA GDS Push certificate distribution."""

import asyncio
import io
import zipfile
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from django.contrib import messages
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
    OnboardingStatus,
)
from pki.models.ca import CaModel
from pki.models.certificate import CertificateModel, RevokedCertificateModel
from pki.models.truststore import TruststoreModel, TruststoreOrderModel
from request.gds_push import GdsPushService
from request.gds_push.gds_push_service import GdsPushError
from trustpoint.page_context import (
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    PageContextMixin,
)

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

    def _update_truststore_with_certificate(self, certificate_bytes: bytes) -> None:
        """Update or create truststore with the new server certificate.

        This method adds the new server certificate to the truststore WITHOUT removing
        the old one immediately. This ensures that if something goes wrong, the old
        certificate is still available for recovery.

        Args:
            certificate_bytes: DER-encoded certificate bytes
        """
        if self.object.onboarding_config is None:
            msg = 'Onboarding config must exist for GDS Push devices'
            raise ValueError(msg)
        try:

            cert = x509.load_der_x509_certificate(certificate_bytes, default_backend())

            truststore = self.object.onboarding_config.opc_trust_store
            if not truststore:
                truststore = TruststoreModel.objects.create(
                    unique_name=f'opc_server_{self.object.common_name}',
                    intended_usage=TruststoreModel.IntendedUsage.OPC_UA_GDS_PUSH
                )
                self.object.onboarding_config.opc_trust_store = truststore
                self.object.onboarding_config.save()

            existing_certs = list(truststore.certificates.all())
            cert_serial = cert.serial_number
            cert_fingerprint = cert.fingerprint(hashes.SHA256())

            cert_exists = False
            for existing_cert_model in existing_certs:
                existing_cert = existing_cert_model.get_certificate_serializer().as_crypto()
                if (existing_cert.serial_number == cert_serial and
                    existing_cert.fingerprint(hashes.SHA256()) == cert_fingerprint):
                    cert_exists = True
                    break

            if not cert_exists:
                for existing_cert_model in truststore.certificates.all():
                    if not existing_cert_model.is_ca:
                         RevokedCertificateModel.objects.create(
                            certificate=existing_cert_model,
                            revocation_reason=RevokedCertificateModel.ReasonCode.CESSATION
                        )

                truststore.truststoreordermodel_set.all().delete()

                cert_model = CertificateModel.save_certificate(cert)

                TruststoreOrderModel.objects.create(
                    trust_store=truststore,
                    certificate=cert_model,
                    order=0
                )

                messages.info(
                    self._get_request(),
                    f'Updated truststore "{truststore.unique_name}" with new server certificate '
                    f'(total: {truststore.certificates.count()} cert(s))'
                )
            else:
                messages.info(
                    self._get_request(),
                    f'Server certificate already exists in truststore "{truststore.unique_name}"'
                )

        except Exception as e:  # noqa: BLE001
            messages.warning(
                self._get_request(),
                f'Server certificate updated but failed to update truststore: {e}'
            )

    def _get_request(self) -> HttpRequest:
        """Get the current request from view context.

        Returns:
            The current HttpRequest
        """
        return self.request

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

        self.object.opc_gds_push_enable_periodic_update = enable
        self.object.opc_gds_push_renewal_interval = interval
        self.object.save(
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
