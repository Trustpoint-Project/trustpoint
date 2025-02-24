"""This module contains all views concerning the PKI -> Certificates section."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.file_builder.certificate import CertificateArchiveFileBuilder, CertificateFileBuilder
from core.file_builder.enum import ArchiveFormat, CertificateFileFormat
from django.http import Http404, HttpRequest, HttpResponse
from django.urls import reverse_lazy
from django.views.generic.base import RedirectView
from django.views.generic.detail import DetailView
from django.views.generic.list import ListView

from pki.models import CertificateModel
from trustpoint.settings import UIConfig
from trustpoint.views.base import PrimaryKeyListFromPrimaryKeyString, SortableTableMixin, TpLoginRequiredMixin

if TYPE_CHECKING:
    from typing import ClassVar


class CertificatesRedirectView(TpLoginRequiredMixin, RedirectView):
    """View that redirects to the index of the PKI Issuing CA application: Issuing CAs."""

    permanent = False
    pattern_name = 'pki:certificates'


class CertificatesContextMixin:
    """Mixin which adds some extra context for the PKI Views."""

    extra_context: ClassVar = {'page_category': 'pki', 'page_name': 'certificates'}


class CertificateTableView(CertificatesContextMixin, TpLoginRequiredMixin, SortableTableMixin, ListView):
    """Certificate Table View."""

    model = CertificateModel
    template_name = 'pki/certificates/certificates.html'  # Template file
    context_object_name = 'certificates'
    paginate_by = UIConfig.paginate_by
    default_sort_param = 'common_name'

class CertificateDetailView(CertificatesContextMixin, TpLoginRequiredMixin, DetailView):
    """The certificate detail view."""

    model = CertificateModel
    success_url = reverse_lazy('pki:certificates')
    ignore_url = reverse_lazy('pki:certificates')
    template_name = 'pki/certificates/details.html'
    context_object_name = 'cert'

class CmpIssuingCaCertificateDownloadView(CertificatesContextMixin, TpLoginRequiredMixin, DetailView):
    """View for downloading a single certificate."""

    model = CertificateModel
    context_object_name = 'certificate'

    def get(self, request: HttpRequest, pk: str | None = None, *args: tuple, **kwargs: dict) -> HttpResponse:
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
        if not pk:
            raise Http404

        certificate_serializer = CertificateModel.objects.get(pk=pk).get_certificate_serializer()
        file_bytes = CertificateFileBuilder.build(certificate_serializer, file_format=CertificateFileFormat.PEM)

        response = HttpResponse(file_bytes, content_type=CertificateFileFormat.PEM.mime_type)
        response['Content-Disposition'] = 'attachment; filename="issuing_ca_cert.pem"'

        return response


class CertificateDownloadView(CertificatesContextMixin, TpLoginRequiredMixin, DetailView):
    """View for downloading a single certificate."""

    model = CertificateModel
    success_url = reverse_lazy('pki:certificates')
    ignore_url = reverse_lazy('pki:certificates')
    template_name = 'pki/certificates/download.html'
    context_object_name = 'certificate'

    def get(
        self, request: HttpRequest, pk: str | None = None, file_format: str | None = None, *args: tuple, **kwargs: dict
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
            file_format_enum = CertificateFileFormat(value=self.kwargs.get('file_format'))
        except Exception as exception:
            raise Http404 from exception

        certificate_serializer = CertificateModel.objects.get(pk=pk).get_certificate_serializer()
        file_bytes = CertificateFileBuilder.build(certificate_serializer, file_format=file_format_enum)

        response = HttpResponse(file_bytes, content_type=file_format_enum.mime_type)
        response['Content-Disposition'] = f'attachment; filename="certificate{file_format_enum.file_extension}"'

        return response


class CertificateMultipleDownloadView(
    CertificatesContextMixin, TpLoginRequiredMixin, PrimaryKeyListFromPrimaryKeyString, ListView
):
    """View for downloading multiple certificates at once as archived files."""

    model = CertificateModel
    success_url = reverse_lazy('pki:certificates')
    ignore_url = reverse_lazy('pki:certificates')
    template_name = 'pki/certificates/download_multiple.html'
    context_object_name = 'certificates'

    def get_context_data(self, **kwargs: dict) -> dict:
        """Adding the part of the url to the context, that contains the certificate primary keys.

        This is used for the {% url }% tags in the template to download files.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data().

        Returns:
            dict: The context data.
        """
        context = super().get_context_data(**kwargs)
        context['pks_path'] = self.kwargs.get('pks')
        return context

    def get(
        self,
        request: HttpRequest,
        pks: str | None = None,
        file_format: None | str = None,
        archive_format: None | str = None,
        *args: tuple,
        **kwargs: dict,
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
            file_format_enum = CertificateFileFormat(value=file_format)
        except Exception as exception:
            raise Http404 from exception

        try:
            archive_format_enum = ArchiveFormat(archive_format)
        except Exception as exception:
            raise Http404 from exception

        file_bytes = CertificateArchiveFileBuilder.build(
            certificate_serializers=[certificate_model.get_certificate_serializer() for certificate_model in self.queryset],
            file_format=file_format_enum,
            archive_format=archive_format_enum,
        )

        response = HttpResponse(file_bytes, content_type=archive_format_enum.mime_type)
        response['Content-Disposition'] = f'attachment; filename="certificates{archive_format_enum.file_extension}"'

        return response
