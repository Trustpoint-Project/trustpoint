"""This module contains all views concerning the PKI -> Certificates section."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.http import Http404, HttpRequest, HttpResponse
from django.urls import reverse_lazy
from django.views.generic.base import RedirectView
from django.views.generic.detail import DetailView
from django.views.generic.list import ListView
from django_filters.rest_framework import DjangoFilterBackend
from drf_yasg.utils import swagger_auto_schema  # type: ignore[import-untyped]
from rest_framework import filters, status, viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from trustpoint_core.archiver import ArchiveFormat, Archiver
from trustpoint_core.oid import NameOid
from trustpoint_core.serializer import CertificateFormat

from pki.models import CertificateModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from pki.serializer.certificate import CertificateSerializer
from trustpoint.page_context import (
    PKI_PAGE_CATEGORY,
    PKI_PAGE_CERTIFICATES_SUBCATEGORY,
    PageContextMixin,
)
from trustpoint.settings import UIConfig
from trustpoint.views.base import PrimaryKeyListFromPrimaryKeyString, SortableTableMixin

if TYPE_CHECKING:
    from typing import ClassVar


class CertificatesRedirectView(RedirectView):
    """View that redirects to the index of the PKI Issuing CA application: Issuing CAs."""

    permanent = False
    pattern_name = 'pki:certificates'


class CertificatesContextMixin(PageContextMixin):
    """Mixin which adds data to the context for the PKI -> Certificates application."""
    page_category = PKI_PAGE_CATEGORY
    page_name = PKI_PAGE_CERTIFICATES_SUBCATEGORY


class CertificateTableView(
    CertificatesContextMixin, SortableTableMixin[CertificateModel], ListView[CertificateModel]):
    """Certificate Table View."""

    model = CertificateModel
    template_name = 'pki/certificates/certificates.html'  # Template file
    context_object_name = 'certificates'
    paginate_by = UIConfig.paginate_by
    default_sort_param = 'common_name'

OID_MAP = {oid.dotted_string: oid.verbose_name for oid in NameOid}

class CertificateDetailView(CertificatesContextMixin, DetailView[CertificateModel]):
    """The certificate detail view."""

    model = CertificateModel
    success_url = reverse_lazy('pki:certificates')
    ignore_url = reverse_lazy('pki:certificates')
    template_name = 'pki/certificates/details.html'
    context_object_name = 'cert'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adding map of attribute and its oid with its values.

        Args:
                   **kwargs: Keyword arguments passed to super().get_context_data().

        Returns:
               dict: The context data.
        """
        context = super().get_context_data(**kwargs)
        cert = context['cert']

        subject_entries = []
        for entry in cert.subject.all():
            name = OID_MAP.get(entry.oid)
            subject_entries.append({
                'oid': entry.oid,
                'name': name,
                'value': entry.value,
            })
        context['subject_entries'] = subject_entries
        issuer_entries = []
        for entry in cert.issuer.all():
            name = OID_MAP.get(entry.oid)
            issuer_entries.append({
                'oid': entry.oid,
                'name': name,
                'value': entry.value,
                'id': entry.id,
            })
        context['issuer_entries'] = issuer_entries
        ip_addresses = []
        san_ext = getattr(cert, 'subject_alternative_name_extension', None)
        if san_ext and getattr(san_ext, 'subject_alt_name', None):
            ip_addresses = [
                str(entry).split(':', 1)[-1].strip()
                for entry in san_ext.subject_alt_name.ip_addresses.all()
            ]
        context['ip_addresses'] = ip_addresses

        return context

class IssuingCaCertificateDownloadView(CertificatesContextMixin, DetailView[CertificateModel]):
    """View for downloading a single certificate."""

    model = CertificateModel
    context_object_name = 'certificate'

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """HTTP GET Method.

        If only the certificate primary key are passed in the url, the download summary will be displayed.
        If value for file_format is also provided, a file download will be performed.

        Compare the re_path regex in the pki.urls package.

        Args:
            request: The HttpRequest object.
            pk: A string containing the certificate primary key.
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            HttpResponse: The HTTP response with either the download summary or a file download.

        Raises:
            Http404
        """
        del args, request
        pk = kwargs.get('pk')
        if not pk:
            raise Http404

        certificate_serializer = CertificateModel.objects.get(pk=pk).get_certificate_serializer()
        file_bytes = certificate_serializer.as_pem()

        response = HttpResponse(file_bytes, content_type=CertificateFormat.PEM.mime_type)
        response['Content-Disposition'] = 'attachment; filename="issuing_ca_cert.pem"'

        return response


class CertificateDownloadView(CertificatesContextMixin, DetailView[CertificateModel]):
    """View for downloading a single certificate."""

    model = CertificateModel
    success_url = reverse_lazy('pki:certificates')
    ignore_url = reverse_lazy('pki:certificates')
    template_name = 'pki/certificates/download.html'
    context_object_name = 'certificate'

    def get(
        self,
        request: HttpRequest,
        pk: str | None = None,
        file_format: str | None = None,
        *args: tuple[Any],
        **kwargs: dict[str, Any],
    ) -> HttpResponse:
        """HTTP GET Method.

        If only the certificate primary key are passed in the url, the download summary will be displayed.
        If value for file_format is also provided, a file download will be performed.

        Compare the re_path regex in the pki.urls package.

        Args:
            request: The HttpRequest object.
            pk: A string containing the certificate primary key.
            file_format: The format of the certificate to download.
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            HttpResponse: The HTTP response with either the download summary or a file download.

        Raises:
            Http404
        """
        if not pk:
            raise Http404

        if file_format is None:
            return super().get(request, *args, **kwargs)

        try:
            file_format_enum = CertificateFormat(value=self.kwargs.get('file_format'))
        except Exception as exception:
            raise Http404 from exception

        certificate_model = CertificateModel.objects.get(pk=pk)
        file_name = self.kwargs.get('file_name', None)
        if not file_name:
            if certificate_model.common_name:
                common_name_safe = ''.join(c if c.isalnum() else '_' for c in certificate_model.common_name)
                file_name = f'{common_name_safe}{file_format_enum.file_extension}'
            else:
                file_name = f'certificate{file_format_enum.file_extension}'

        certificate_serializer = certificate_model.get_certificate_serializer()
        file_bytes = certificate_serializer.as_format(file_format_enum)

        response = HttpResponse(file_bytes, content_type=file_format_enum.mime_type)
        response['Content-Disposition'] = f'attachment; filename="{file_name}"'

        return response


class CertificateMultipleDownloadView(
    CertificatesContextMixin, PrimaryKeyListFromPrimaryKeyString, ListView[CertificateModel]
):
    """View for downloading multiple certificates at once as archived files."""

    model = CertificateModel
    success_url = reverse_lazy('pki:certificates')
    ignore_url = reverse_lazy('pki:certificates')
    template_name = 'pki/certificates/download_multiple.html'
    context_object_name = 'certificates'

    def get_context_data(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Adding the part of the url to the context, that contains the certificate primary keys.

        This is used for the {% url }% tags in the template to download files.

        Args:
            *args: Positional arguments passed to super().get_context_data().
            **kwargs: Keyword arguments passed to super().get_context_data().

        Returns:
            dict: The context data.
        """
        context = super().get_context_data(*args, **kwargs)
        context['pks_path'] = self.kwargs.get('pks')
        return context

    def get(
        self,
        request: HttpRequest,
        pks: str | None = None,
        file_format: None | str = None,
        archive_format: None | str = None,
        *args: tuple[Any],
        **kwargs: dict[str, Any],
    ) -> HttpResponse:
        """HTTP GET Method.

        If only certificate primary keys are passed in the url, the download summary will be displayed.
        If value for file_format and archive_format are also provided, a file download will be performed.

        Compare the re_path regex in the pki.urls package.

        Args:
            request: The HttpRequest object.
            pks: A string containing the certificate primary keys, e.g. 1/2/3/4/5
            file_format: The format of the archived certificate files.
            archive_format: The archive format that will be provided as download.
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            HttpResponse: The HTTP response with either the download summary or a file download.

        Raises:
            Http404
        """
        if not pks:
            raise Http404

        pks_list = self.get_pks_as_list(pks=pks)
        self.queryset = self.model.objects.filter(pk__in=pks_list)

        if len(pks_list) != len(self.queryset):
            raise Http404

        if not file_format and not archive_format:
            return super().get(request, *args, **kwargs)

        try:
            file_format_enum = CertificateFormat(value=file_format)
        except Exception as exception:
            raise Http404 from exception

        try:
            archive_format_enum = ArchiveFormat(archive_format)
        except Exception as exception:
            raise Http404 from exception

        data_to_archive = {}
        for i, certificate_model in enumerate(self.queryset):
            # Generate filename with certificate common name if available
            if certificate_model.common_name:
                # Sanitize common name for filename (replace spaces and special chars with underscores)
                common_name_safe = ''.join(c if c.isalnum() else '_' for c in certificate_model.common_name)
                file_key = f'{common_name_safe}'
            else:
                file_key = f'certificate-{i}'
            data_to_archive[file_key] = certificate_model.get_certificate_serializer().as_format(file_format_enum)

        file_bytes = Archiver.archive(data_to_archive, archive_format_enum)

        response = HttpResponse(file_bytes, content_type=archive_format_enum.mime_type)
        response['Content-Disposition'] = f'attachment; filename="certificates{archive_format_enum.file_extension}"'

        return response


class TlsServerCertificateDownloadView(CertificatesContextMixin, DetailView[CertificateModel]):
    """View for downloading the TLS server certificate of trustpoint."""

    model = CertificateModel
    context_object_name = 'certificate'

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Download the active Trustpoint TLS server certificate."""
        del args, kwargs, request
        tls_cert = ActiveTrustpointTlsServerCredentialModel.objects.first()
        if not tls_cert or not tls_cert.credential:
            msg = 'No TLS server certificate available. Are you on the development server?'
            raise Http404(msg)

        tls_server_certificate = tls_cert.credential.certificate.get_certificate_serializer()

        file_bytes = tls_server_certificate.as_pem()

        response = HttpResponse(file_bytes, content_type=CertificateFormat.PEM.mime_type)
        response['Content-Disposition'] = 'attachment; filename="server_cert.pem"'

        return response

class CertificateViewSet(viewsets.ModelViewSet[CertificateModel]):
    """ViewSet for managing Certificate instances.

    Supports standard CRUD operations such as list, retrieve,
    create, update, and delete.
    """
    queryset = CertificateModel.objects.all().order_by('-created_at')
    serializer_class = CertificateSerializer
    permission_classes = (IsAuthenticated,)
    filter_backends = (
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter
    )
    filterset_fields: ClassVar = ['serial_number', 'not_valid_before']
    search_fields: ClassVar = ['common_name', 'sha256_fingerprint']
    ordering_fields: ClassVar = ['common_name', 'created_at']

    # ignoring untyped decorator (drf-yasg not typed)
    @swagger_auto_schema(
        operation_summary='List certificates',
        operation_description='Retrieve certificates from the database.',
        tags=['certificates']
    ) # type: ignore[misc]
    def list(self, request: HttpRequest, *args: Any, **_kwargs: Any) -> HttpResponse:
        """API endpoint to get all certificates."""
        del request, args, _kwargs
        queryset = self.get_queryset()

        for backend in self.filter_backends:
            if hasattr(backend, 'filter_queryset'):
                queryset = backend().filter_queryset(self.request, queryset, self)

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
