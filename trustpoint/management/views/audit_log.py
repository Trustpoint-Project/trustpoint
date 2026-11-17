# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Audit log views."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar, cast

from django import forms
from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.generic import FormView, TemplateView
from django.views.generic.list import ListView
from drf_spectacular.utils import extend_schema
from rest_framework import mixins, viewsets
from rest_framework.permissions import BasePermission

from crypto.domain.errors import CryptoError
from management.filters.audit_log import AuditLogFilter
from management.models.audit_log import AuditLog
from management.models.audit_signing import AuditLogCheckpoint, AuditSigningConfig
from management.models.traceability import TraceabilityCredentialModel
from management.serializer.audit_log import AuditLogIngestSerializer
from management.services.audit_integrity import AuditVerificationReport, verify_audit_chain
from management.services.audit_log_export import create_evidence_export
from management.services.audit_signing import create_checkpoint, sync_signing_schedule
from trustpoint.logger import LoggerMixin
from trustpoint.page_context import PageContextMixin
from trustpoint.views.base import UserPermissionRequiredMixin
from users.permissions import AppPermissions
from util.audit_log_export import encode_json

if TYPE_CHECKING:
    from django.db import models
    from django.db.models import QuerySet

MAX_UI_VERIFY_ENTRIES = 10_000
CHECKPOINT_HISTORY_LIMIT = 50


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


def _audit_filters(request: Any) -> dict[str, str]:
    selection = AuditLogFilter(request.GET, queryset=AuditLog.objects.none())
    return {name: request.GET[name] for name in selection.filters if request.GET.get(name)}


class AuditLogExportView(UserPermissionRequiredMixin, PageContextMixin, TemplateView):
    """Explain the evidence package before a read-only download request."""

    template_name = 'management/audit_log/export.html'
    permission_required = AppPermissions.VIEW_AUDIT_LOG
    page_category = 'management'
    page_name = 'audit_log'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Explain whether the download will be a complete chain or a signed filtered subset."""
        context = super().get_context_data(**kwargs)
        scope = 'filtered' if _audit_filters(self.request) else 'full'
        config = AuditSigningConfig.objects.filter(pk=1, enabled=True).first()
        credential = config.traceability_credential if config is not None else None
        signing_available = bool(config is not None and credential is not None and credential.is_usable)
        can_sign_filtered = self.request.user.has_perm(AppPermissions.MANAGE_TRACEABILITY_CREDENTIALS)
        return context | {
            'scope': scope,
            'signing_available': signing_available,
            'can_sign_filtered': can_sign_filtered,
        }


class AuditLogExportDownloadView(UserPermissionRequiredMixin, PageContextMixin, LoggerMixin, View):
    """Create a checkpoint-anchored evidence package for the current selection."""

    permission_required = AppPermissions.VIEW_AUDIT_LOG
    page_category = 'management'
    page_name = 'audit_log'

    def get(self, request: Any, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Export all matching entries, independent of pagination, using a safe GET request."""
        selection = AuditLogFilter(request.GET, queryset=AuditLog.objects.all())
        export_url = reverse('management:audit-log-export')
        return_url = f'{export_url}?{request.GET.urlencode()}'
        if not url_has_allowed_host_and_scheme(return_url, allowed_hosts=set()):
            return_url = export_url
        if not selection.form.is_valid():
            messages.error(request, _('Invalid audit log filters. Return to the audit log and correct them.'))
            return redirect(return_url)
        filters = {name: request.GET[name] for name in selection.filters if request.GET.get(name)}
        if filters and not request.user.has_perm(AppPermissions.MANAGE_TRACEABILITY_CREDENTIALS):
            raise PermissionDenied
        try:
            document = create_evidence_export(selection.qs, filters)
        except ValidationError as error:
            messages.error(request, str(error))
            return redirect(return_url)
        except (CryptoError, RuntimeError, ValueError):
            self.logger.exception('Could not create audit evidence export.')
            messages.error(request, _('Could not create the evidence package. Check the audit signing configuration.'))
            return redirect(return_url)
        content = encode_json(document)
        response = HttpResponse(content, content_type='application/json')
        response['Content-Disposition'] = 'attachment; filename="trustpoint-audit-evidence.json"'
        response['Cache-Control'] = 'no-store'
        return response


class AuditSigningConfigForm(forms.ModelForm[AuditSigningConfig]):
    """Configure global audit checkpoint signing."""

    class Meta:
        """Bind the form to the singleton configuration model."""

        model = AuditSigningConfig
        fields: ClassVar[list[str]] = [
            'enabled',
            'traceability_credential',
            'checkpoint_event_interval',
            'checkpoint_time_interval_minutes',
        ]
        widgets: ClassVar[dict[str, Any]] = {
            'enabled': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'traceability_credential': forms.Select(attrs={'class': 'form-select'}),
            'checkpoint_event_interval': forms.NumberInput(attrs={'class': 'form-control', 'min': 1}),
            'checkpoint_time_interval_minutes': forms.NumberInput(attrs={'class': 'form-control', 'min': 1}),
        }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Offer only signing identities that can be activated."""
        super().__init__(*args, **kwargs)
        credential_field = cast(
            'forms.ModelChoiceField[TraceabilityCredentialModel]',
            self.fields['traceability_credential'],
        )
        credential_field.queryset = TraceabilityCredentialModel.objects.filter(
            status=TraceabilityCredentialModel.Status.ACTIVE
        )


class AuditSigningConfigView(
    UserPermissionRequiredMixin,
    PageContextMixin,
    LoggerMixin,
    FormView[AuditSigningConfigForm],
):
    """Manage audit checkpoint signing and create the first checkpoint on enable."""

    form_class = AuditSigningConfigForm
    template_name = 'management/audit_log/signing.html'
    permission_required = AppPermissions.MANAGE_SECURITY_CONFIGURATION
    page_category = 'management'
    page_name = 'audit_log'

    def get_form_kwargs(self) -> dict[str, Any]:
        """Always edit the singleton configuration row."""
        return super().get_form_kwargs() | {'instance': AuditSigningConfig.get()}

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Show the latest coverage and unresolved signing failures."""
        context = super().get_context_data(**kwargs)
        config = AuditSigningConfig.get()
        latest = AuditLogCheckpoint.objects.order_by('-checkpoint_number').first()
        head = AuditLog.objects.order_by('-sequence').only('sequence').first()
        covered = latest.last_sequence if latest else 0
        head_sequence = head.sequence if head else 0
        checkpoints = AuditLogCheckpoint.objects.select_related(
            'traceability_credential',
            'traceability_generation__credential__certificate',
        ).order_by('-checkpoint_number')[:CHECKPOINT_HISTORY_LIMIT]
        checkpoint_total = AuditLogCheckpoint.objects.count()
        return context | {
            'config': config,
            'latest_checkpoint': latest,
            'covered_sequence': covered,
            'head_sequence': head_sequence,
            'unsigned_entries': max(0, head_sequence - covered),
            'checkpoints': checkpoints,
            'checkpoint_total': checkpoint_total,
            'checkpoint_history_limit': CHECKPOINT_HISTORY_LIMIT,
        }

    def form_valid(self, form: AuditSigningConfigForm) -> HttpResponse:
        """Persist settings and require a successful baseline signature before enabling."""
        was_enabled = bool(AuditSigningConfig.objects.filter(pk=1).values_list('enabled', flat=True).first())
        config = form.save(commit=False)
        try:
            with transaction.atomic():
                config.full_clean()
                config.save()
                if config.enabled and not was_enabled:
                    create_checkpoint(config=config)
                AuditLog.create_entry(
                    operation_type=AuditLog.OperationType.AUDIT_SIGNING_CONFIG_UPDATED,
                    target=config,
                    target_display='Audit Log Signing Configuration',
                    actor=cast('models.Model', self.request.user),
                    details={
                        'enabled': config.enabled,
                        'checkpoint_event_interval': config.checkpoint_event_interval,
                        'checkpoint_time_interval_minutes': config.checkpoint_time_interval_minutes,
                        'traceability_credential_id': config.traceability_credential_id,
                    },
                )
        except ValidationError as error:
            form.add_error(None, error)
            return self.form_invalid(form)
        except Exception:
            self.logger.exception('Could not save audit signing configuration.')
            form.add_error(None, _('Could not create the audit checkpoint. Check the signing credential and backend.'))
            return self.form_invalid(form)
        transaction.on_commit(
            lambda: sync_signing_schedule(
                enabled=config.enabled,
                time_interval_minutes=config.checkpoint_time_interval_minutes,
            )
        )
        messages.success(self.request, _('Audit log signing settings saved.'))
        return redirect('management:audit-log-signing')


class AuditLogVerifyView(UserPermissionRequiredMixin, PageContextMixin, LoggerMixin, TemplateView):
    """Verify the complete audit chain and all retained checkpoint signatures."""

    template_name = 'management/audit_log/verify.html'
    permission_required = AppPermissions.VIEW_AUDIT_LOG
    page_category = 'management'
    page_name = 'audit_log'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Run verification on demand and expose structured findings."""
        context = super().get_context_data(**kwargs)
        report: AuditVerificationReport | None = None
        error = ''
        if AuditLog.objects.count() > MAX_UI_VERIFY_ENTRIES:
            error = str(
                _(
                    'The audit log is too large to verify in the browser. '
                    'Run "python manage.py verify_audit_log" instead.'
                )
            )
        else:
            try:
                report = verify_audit_chain()
            except Exception:
                self.logger.exception('Could not verify the audit log chain.')
                error = str(_('The audit chain could not be verified due to an internal error.'))
        checkpoints = AuditLogCheckpoint.objects.select_related(
            'traceability_credential',
            'traceability_generation__credential__certificate',
        ).order_by('-checkpoint_number')[:CHECKPOINT_HISTORY_LIMIT]
        checkpoint_total = AuditLogCheckpoint.objects.count()
        return context | {
            'report': report,
            'verification_error': error,
            'checkpoints': checkpoints,
            'checkpoint_total': checkpoint_total,
            'checkpoint_history_limit': CHECKPOINT_HISTORY_LIMIT,
        }


class CanAddAuditLog(BasePermission):
    """Allow appending external entries only with the dedicated permission."""

    def has_permission(self, request: Any, _view: Any) -> bool:
        """Check the caller's append permission."""
        return bool(
            request.user and request.user.is_authenticated and request.user.has_perm(AppPermissions.ADD_AUDIT_LOG)
        )


@extend_schema(tags=['Audit'])
class AuditLogViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet[AuditLog]):
    """Append an external event to the tamper-evident audit chain."""

    # shortcut: payload size and rate rely on global Django/DRF limits; add a cap and throttle if ingestion grows.
    serializer_class = AuditLogIngestSerializer
    permission_classes = (CanAddAuditLog,)
    filter_backends = ()
