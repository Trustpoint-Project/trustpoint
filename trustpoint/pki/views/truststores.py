"""This module contains all views concerning the PKI -> Truststore section."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import ProtectedError
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext
from django.views.generic.base import RedirectView
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView
from django.views.generic.list import ListView
from django_filters.rest_framework import DjangoFilterBackend
from drf_yasg.utils import swagger_auto_schema  # type: ignore[import-untyped]
from rest_framework import filters, status, viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from trustpoint_core.archiver import ArchiveFormat, Archiver
from trustpoint_core.oid import NameOid
from trustpoint_core.serializer import CertificateFormat

from pki.forms import TruststoreAddForm
from pki.models import DomainModel
from pki.models.truststore import TruststoreModel
from pki.serializer.truststore import TruststoreSerializer
from pki.services.truststore import TruststoreService
from trustpoint.page_context import PKI_PAGE_CATEGORY, PKI_PAGE_TRUSTSTORES_SUBCATEGORY, PageContextMixin
from trustpoint.settings import UIConfig
from trustpoint.views.base import (
    BulkDeleteView,
    PrimaryKeyListFromPrimaryKeyString,
    SortableTableMixin,
)

if TYPE_CHECKING:
    from typing import Any, ClassVar

    from django.forms import Form


class TruststoresRedirectView(RedirectView):
    """View that redirects to the index of the PKI Truststores application: Truststores."""

    permanent = False
    pattern_name = 'pki:truststores'


class TruststoresContextMixin(PageContextMixin):
    """Mixin which adds some extra context for the PKI Views."""

    page_category = PKI_PAGE_CATEGORY
    page_name = PKI_PAGE_TRUSTSTORES_SUBCATEGORY


class TruststoreTableView(TruststoresContextMixin, SortableTableMixin[TruststoreModel], ListView[TruststoreModel]):
    """Truststore Table View."""

    model = TruststoreModel
    template_name = 'pki/truststores/truststores.html'
    context_object_name = 'truststores'
    paginate_by = UIConfig.paginate_by
    default_sort_param = 'unique_name'


class TruststoreCreateView(TruststoresContextMixin, FormView[TruststoreAddForm]):
    """View for creating a new Truststore."""

    model = TruststoreModel
    form_class = TruststoreAddForm
    template_name = 'pki/truststores/add/file_import.html'
    ignore_url = reverse_lazy('pki:truststores')

    def form_valid(self, form: TruststoreAddForm) -> HttpResponseRedirect:
        """If the form is valid, redirect to Truststore overview."""
        truststore = form.cleaned_data['truststore']
        domain_id = self.kwargs.get('pk')

        if domain_id:
            return HttpResponseRedirect(
                reverse(
                    'pki:devid_registration_create-with_truststore_id',
                    kwargs={'pk': domain_id, 'truststore_id': truststore.id},
                )
            )

        n_certificates = truststore.number_of_certificates
        msg_str = ngettext(
            'Successfully created the Truststore %(name)s with %(count)i certificate.',
            'Successfully created the Truststore %(name)s with %(count)i certificates.',
            n_certificates,
        ) % {
            'name': truststore.unique_name,
            'count': n_certificates,
        }

        messages.success(self.request, msg_str)

        return HttpResponseRedirect(reverse('pki:truststores'))

    def get_success_url(self) -> str:
        """You could still use a success URL here if needed."""
        return reverse_lazy('pki:truststores')  # type: ignore[return-value]

    def get_context_data(self, **kwargs: dict[str, Any]) -> dict[str, Any]:
        """Include domain in context only if pk is present."""
        context = super().get_context_data(**kwargs)
        pk = self.kwargs.get('pk')
        if pk:
            context['domain'] = get_object_or_404(DomainModel, id=pk)
        return context


OID_MAP = {oid.dotted_string: oid.verbose_name for oid in NameOid}


class TruststoreDetailView(TruststoresContextMixin, DetailView[TruststoreModel]):
    """The truststore detail view."""

    model = TruststoreModel
    success_url = reverse_lazy('pki:truststores')
    ignore_url = reverse_lazy('pki:truststores')
    template_name = 'pki/truststores/details.html'
    context_object_name = 'truststore'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adding map of attribute and its oid with its values.

        Args:
                   **kwargs: Keyword arguments passed to super().get_context_data().

        Returns:
               dict: The context data.
        """
        context = super().get_context_data(**kwargs)
        truststore: TruststoreModel = context['truststore']

        # For each certificate in this truststore, build subject/issuer entries
        cert_context = []
        for cert in truststore.certificates.all():
            subject_entries = [
                {'oid': entry.oid, 'name': OID_MAP.get(entry.oid), 'value': entry.value} for entry in cert.subject.all()
            ]

            issuer_entries = [
                {'oid': entry.oid, 'name': OID_MAP.get(entry.oid), 'value': entry.value, 'id': entry.id}
                for entry in cert.issuer.all()
            ]

            cert_context.append(
                {'certificate': cert, 'subject_entries': subject_entries, 'issuer_entries': issuer_entries}
            )

        context['cert_context'] = cert_context
        return context


class TruststoreDownloadView(TruststoresContextMixin, DetailView[TruststoreModel]):
    """View for downloading a single truststore."""

    model = TruststoreModel
    success_url = reverse_lazy('pki:truststores')
    ignore_url = reverse_lazy('pki:truststores')
    template_name = 'pki/truststores/download.html'
    context_object_name = 'truststore'

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

        certificate_serializer = TruststoreModel.objects.get(pk=pk).get_certificate_collection_serializer()
        file_bytes = certificate_serializer.as_format(file_format_enum)

        response = HttpResponse(file_bytes, content_type=file_format_enum.mime_type)
        response['Content-Disposition'] = f'attachment; filename="truststore{file_format_enum.file_extension}"'

        return response


class TruststoreMultipleDownloadView(
    TruststoresContextMixin, PrimaryKeyListFromPrimaryKeyString, ListView[TruststoreModel]
):
    """View for downloading multiple truststores at once as archived files."""

    model = TruststoreModel
    success_url = reverse_lazy('pki:truststores')
    ignore_url = reverse_lazy('pki:truststores')
    template_name = 'pki/truststores/download_multiple.html'
    context_object_name = 'truststores'

    def get_context_data(self, *args: Any, **kwargs: dict[str, Any]) -> dict[str, Any]:  # type: ignore[override]
        """Adding the part of the url to the context, that contains the truststores primary keys.

        This is used for the {% url }% tags in the template to download files.

        Args:
            *args: Positional arguments, unused.
            **kwargs: Keyword arguments passed to super().get_context_data().

        Returns:
            dict: The context data.
        """
        del args
        context = super().get_context_data(**kwargs)
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

        certificate_collection_serializers = [
            TruststoreModel.objects.get(pk=pk).get_certificate_collection_serializer() for pk in pks_list
        ]

        data_to_archive = {
            f'trust-store-{i}': trust_store.as_format(file_format_enum)
            for i, trust_store in enumerate(certificate_collection_serializers)
        }

        file_bytes = Archiver.archive(data_to_archive, archive_format_enum)

        response = HttpResponse(file_bytes, content_type=archive_format_enum.mime_type)
        response['Content-Disposition'] = f'attachment; filename="truststores{archive_format_enum.file_extension}"'

        return response


class TruststoreBulkDeleteConfirmView(TruststoresContextMixin, BulkDeleteView):
    """View for confirming the deletion of multiple truststores."""

    model = TruststoreModel
    success_url = reverse_lazy('pki:truststores')
    ignore_url = reverse_lazy('pki:truststores')
    template_name = 'pki/truststores/confirm_delete.html'
    context_object_name = 'truststores'

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests."""
        queryset = self.get_queryset()
        if not queryset.exists():
            messages.error(request, _('No truststores selected for deletion.'))
            return HttpResponseRedirect(self.success_url)
        return super().get(request, *args, **kwargs)

    def form_valid(self, form: Form) -> HttpResponse:
        """Attempts to delete the selected truststores on valid form."""
        queryset = self.get_queryset()
        deleted_count = queryset.count()

        try:
            response = super().form_valid(form)

        except ProtectedError:
            messages.error(
                self.request,
                _('Cannot delete the selected Truststore(s) because they are referenced by other objects.'),
            )
            return HttpResponseRedirect(self.success_url)
        except ValidationError as exc:
            messages.error(self.request, exc.message)
            return HttpResponseRedirect(self.success_url)

        messages.success(self.request, _('Successfully deleted {count} Truststore(s).').format(count=deleted_count))

        return response


class TruststoreViewSet(viewsets.ModelViewSet[TruststoreModel]):
    """ViewSet for managing Truststore instances.

    Supports standard CRUD operations such as list, retrieve,
    create, update, and delete.
    """

    queryset = TruststoreModel.objects.all().order_by('-created_at')
    serializer_class = TruststoreSerializer
    permission_classes = (IsAuthenticated,)
    filter_backends = (DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter)
    filterset_fields: ClassVar = ['intended_usage']
    search_fields: ClassVar = ['unique_name']
    ordering_fields: ClassVar = ['unique_name', 'created_at']

    # ignoring untyped decorator (drf-yasg not typed)
    @swagger_auto_schema(
        operation_summary='Create a new truststore',
        operation_description='Add a new truststore by providing its unique_name, intended_usage and trust_store_file.',
        tags=['truststores'],
    )  # type: ignore[misc]
    def create(self, request: HttpRequest, *args: Any, **_kwargs: Any) -> HttpResponse:
        """API endpoint to create truststore."""
        del args, _kwargs
        serializer = self.get_serializer(data=request.data)  # type: ignore[attr-defined]
        serializer.is_valid(raise_exception=True)

        truststore = TruststoreService().create(
            unique_name=serializer.validated_data.get('unique_name'),
            intended_usage=serializer.validated_data['intended_usage'],
            trust_store_file=serializer.validated_data['trust_store_file'],
        )

        return Response(TruststoreSerializer(truststore).data, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(
        operation_summary='List Truststores',
        operation_description='Retrieve truststore from the database.',
        tags=['truststores'],
    )  # type: ignore[misc]
    def list(self, request: HttpRequest, *args: Any, **_kwargs: Any) -> HttpResponse:
        """API endpoint to get all truststores."""
        del request, args, _kwargs
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
