# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Audit log views."""

from __future__ import annotations

import base64
from io import BytesIO
from typing import TYPE_CHECKING, Any
from zipfile import ZipFile

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django import forms
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.utils.translation import gettext_lazy as _
from django.views.generic import FormView
from django.views.generic.list import ListView

from crypto.domain.errors import CryptoError
from management.filters.audit_log import AuditLogFilter
from management.models.audit_log import AuditLog
from management.models.traceability import TraceabilityCredentialModel
from management.services.audit_log_export import create_signed_export
from trustpoint.logger import LoggerMixin
from trustpoint.page_context import PageContextMixin
from trustpoint.views.base import UserPermissionRequiredMixin
from users.permissions import AppPermissions
from util.audit_log_export import base64url_decode, encode_json, load_json

if TYPE_CHECKING:
    from django.db.models import QuerySet


class AuditLogListView(UserPermissionRequiredMixin, PageContextMixin, LoggerMixin, ListView[AuditLog]):
    """Paginated, filterable list view for audit log entries."""

    model = AuditLog
    template_name = 'management/audit_log/list.html'
    context_object_name = 'audit_log_entries'
    paginate_by = 50

    permission_required = AppPermissions.VIEW_AUDIT_LOG

    page_category = 'management'
    page_name = 'audit_log'

    def get_queryset(self) -> QuerySet[AuditLog]:
        """Return a filtered and pre-fetched queryset."""
        qs: QuerySet[AuditLog] = AuditLog.objects.select_related('target_content_type', 'actor').order_by('-timestamp')
        self._filter = AuditLogFilter(self.request.GET, queryset=qs)
        filtered_qs: QuerySet[AuditLog] = self._filter.qs
        return filtered_qs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the active filter to the template context."""
        context = super().get_context_data(**kwargs)
        context['filter'] = self._filter
        return context


class AuditLogExportForm(forms.Form):
    """Choose a traceability identity for this signed export."""

    credential = forms.ModelChoiceField(
        queryset=TraceabilityCredentialModel.objects.filter(status=TraceabilityCredentialModel.Status.ACTIVE),
        label=_('Signing credential'),
        widget=forms.Select(attrs={'class': 'form-select'}),
    )
    include_certificate = forms.BooleanField(
        required=False,
        label=_('Include signing certificate (PEM) in a ZIP download'),
    )


class AuditLogExportView(UserPermissionRequiredMixin, PageContextMixin, LoggerMixin, FormView[AuditLogExportForm]):
    """Download a signed snapshot of the current audit log selection."""

    form_class = AuditLogExportForm
    template_name = 'management/audit_log/export.html'
    permission_required = AppPermissions.VIEW_AUDIT_LOG
    page_category = 'management'
    page_name = 'audit_log'

    def has_permission(self) -> bool:
        """Require audit access and permission to manage signing identities."""
        return super().has_permission() and self.request.user.has_perm(AppPermissions.MANAGE_TRACEABILITY_CREDENTIALS)

    def form_valid(self, form: AuditLogExportForm) -> HttpResponse:
        """Validate filters and sign all matching entries, independent of pagination."""
        selection = AuditLogFilter(self.request.GET, queryset=AuditLog.objects.all())
        if not selection.form.is_valid():
            form.add_error(None, _('Invalid audit log filters. Return to the audit log and correct them.'))
            return self.form_invalid(form)
        filters = {name: self.request.GET[name] for name in selection.filters if self.request.GET.get(name)}
        try:
            document = create_signed_export(selection.qs, form.cleaned_data['credential'], filters)
        except ValidationError as error:
            form.add_error(None, error)
            return self.form_invalid(form)
        except (CryptoError, RuntimeError, ValueError):
            self.logger.exception('Could not create signed audit log export.')
            form.add_error(None, _('Could not sign the export. Check the signing credential and crypto backend.'))
            return self.form_invalid(form)
        content = encode_json(document)
        content_type = 'application/jose+json'
        filename = 'trustpoint-audit-log.json'
        if form.cleaned_data['include_certificate']:
            header = load_json(base64url_decode(document['protected']))
            certificate = x509.load_der_x509_certificate(base64.b64decode(header['x5c'][0], validate=True))
            archive = BytesIO()
            with ZipFile(archive, 'w') as bundle:
                bundle.writestr(filename, content)
                bundle.writestr('signing-certificate.pem', certificate.public_bytes(serialization.Encoding.PEM))
            content = archive.getvalue()
            content_type, filename = 'application/zip', 'trustpoint-audit-log.zip'
        response = HttpResponse(content, content_type=content_type)
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        response['Cache-Control'] = 'no-store'
        return response
