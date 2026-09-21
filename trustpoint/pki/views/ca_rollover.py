# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Views for CA rollover management within the Issuing CA config page."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext as _
from django.views import View

from management.models.audit_log import AuditLog
from pki.models import CaModel
from pki.models.ca_rollover import CaRolloverModel, CaRolloverStrategyType
from pki.rollover.generate_keypair import GenerateKeypairCmpRolloverForm, GenerateKeypairEstRolloverForm
from pki.rollover.import_ca import ImportCaRolloverForm, SeparateFilesCaRolloverForm
from pki.rollover.registry import rollover_registry
from pki.services.ca_rollover import CaRolloverError, CaRolloverService
from users.permissions import AppPermissions

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse

logger = logging.getLogger(__name__)


def _ensure_strategies_loaded() -> None:
    """Ensure all strategy modules are imported so they register themselves."""


def _get_local_issuing_ca(pk: int) -> CaModel:
    """Return a locally managed issuing CA or reject rollover access."""
    issuing_ca = get_object_or_404(CaModel, pk=pk)
    local_types = {
        CaModel.CaTypeChoice.AUTOGEN,
        CaModel.CaTypeChoice.LOCAL_UNPROTECTED,
        CaModel.CaTypeChoice.LOCAL_PKCS11,
    }
    if issuing_ca.ca_type not in local_types:
        raise PermissionDenied
    return issuing_ca


def _ensure_rollover_can_start(issuing_ca: CaModel) -> None:
    """Reject a second or already completed rollover before showing methods."""
    if CaRolloverService.get_active_rollover(issuing_ca) is not None:
        raise PermissionDenied
    if CaRolloverService.has_completed_rollover(issuing_ca):
        raise PermissionDenied


class RolloverMethodSelectView(LoginRequiredMixin, View):
    """Select how a replacement credential should be acquired."""

    template_name = 'pki/issuing_cas/rollover/method_select.html'

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Render the top-level rollover method selection page."""
        issuing_ca = _get_local_issuing_ca(pk)
        _ensure_rollover_can_start(issuing_ca)
        return render(request, self.template_name, {'issuing_ca': issuing_ca})

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Route the selected top-level rollover method."""
        issuing_ca = _get_local_issuing_ca(pk)
        _ensure_rollover_can_start(issuing_ca)
        method = request.POST.get('method')
        if method == 'import':
            return redirect('pki:issuing_cas-rollover-file-method-select', pk=pk)
        if method == 'generate':
            return redirect('pki:issuing_cas-rollover-request-method-select', pk=pk)
        messages.error(request, _('Invalid rollover method.'))
        return redirect('pki:issuing_cas-config', pk=pk)


class RolloverFileMethodSelectView(RolloverMethodSelectView):
    """Select the file format for an imported replacement credential."""

    template_name = 'pki/issuing_cas/rollover/file_method_select.html'

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Route the selected file import method."""
        issuing_ca = _get_local_issuing_ca(pk)
        _ensure_rollover_can_start(issuing_ca)
        method = request.POST.get('method')
        if method == 'pkcs12':
            return redirect('pki:issuing_cas-rollover-import-pkcs12', pk=pk)
        if method == 'separate_files':
            return redirect('pki:issuing_cas-rollover-import-separate-files', pk=pk)
        messages.error(request, _('Invalid import method.'))
        return redirect('pki:issuing_cas-rollover-method-select', pk=pk)


class RolloverRequestMethodSelectView(RolloverMethodSelectView):
    """Select the upstream protocol for a generated replacement keypair."""

    template_name = 'pki/issuing_cas/rollover/request_method_select.html'

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Route the selected EST or CMP request method."""
        issuing_ca = _get_local_issuing_ca(pk)
        _ensure_rollover_can_start(issuing_ca)
        method = request.POST.get('method')
        if method == 'est':
            return redirect('pki:issuing_cas-rollover-request-est', pk=pk)
        if method == 'cmp':
            return redirect('pki:issuing_cas-rollover-request-cmp', pk=pk)
        messages.error(request, _('Invalid certificate request method.'))
        return redirect('pki:issuing_cas-rollover-method-select', pk=pk)


class RolloverCredentialView(LoginRequiredMixin, View):
    """Create a pending replacement CA using a shared acquisition form."""

    form_class: Any
    template_name = 'pki/issuing_cas/rollover/credential_form.html'
    strategy_type: CaRolloverStrategyType
    request_protocol: str | None = None

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Render the shared credential acquisition form."""
        issuing_ca = _get_local_issuing_ca(pk)
        _ensure_rollover_can_start(issuing_ca)
        return render(request, self.template_name, {'issuing_ca': issuing_ca, 'form': self.form_class()})

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Validate and persist a pending rollover credential."""
        if not request.user.has_perm(AppPermissions.MANAGE_CAS):
            raise PermissionDenied
        issuing_ca = _get_local_issuing_ca(pk)
        _ensure_rollover_can_start(issuing_ca)
        form = self.form_class(request.POST, request.FILES)
        if not form.is_valid():
            return render(request, self.template_name, {'issuing_ca': issuing_ca, 'form': form})
        try:
            rollover = CaRolloverService.plan_rollover(
                old_ca=issuing_ca,
                strategy_type=self.strategy_type,
                form=form,
                initiated_by=request.user if request.user.is_authenticated else None,
            )
        except CaRolloverError as exc:
            form.add_error(None, str(exc))
            return render(request, self.template_name, {'issuing_ca': issuing_ca, 'form': form})
        messages.success(request, _('Pending CA rollover credential created.'))
        if self.request_protocol and rollover.new_issuing_ca is not None:
            return redirect(
                f'pki:issuing_cas-define-cert-content-{self.request_protocol}',
                pk=rollover.new_issuing_ca.pk,
            )
        return redirect('pki:issuing_cas-config', pk=issuing_ca.pk)


class RolloverImportPkcs12View(RolloverCredentialView):
    """Import a pending rollover CA using PKCS#12."""

    form_class = ImportCaRolloverForm
    strategy_type = CaRolloverStrategyType.IMPORT_CA


class RolloverImportSeparateFilesView(RolloverCredentialView):
    """Import a pending rollover CA from separate key and certificate files."""

    form_class = SeparateFilesCaRolloverForm
    strategy_type = CaRolloverStrategyType.IMPORT_CA


class RolloverRequestEstView(RolloverCredentialView):
    """Generate a managed key and configure an editable EST request."""

    form_class = GenerateKeypairEstRolloverForm
    strategy_type = CaRolloverStrategyType.GENERATE_KEYPAIR
    request_protocol = 'est'


class RolloverRequestCmpView(RolloverCredentialView):
    """Generate a managed key and configure an editable CMP request."""

    form_class = GenerateKeypairCmpRolloverForm
    strategy_type = CaRolloverStrategyType.GENERATE_KEYPAIR
    request_protocol = 'cmp'


class PlanRolloverView(LoginRequiredMixin, View):
    """Handle POST to plan a new CA rollover from the Issuing CA config page."""

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Plan a new rollover for the given Issuing CA."""
        if not request.user.has_perm(AppPermissions.MANAGE_CAS):
            raise PermissionDenied
        _ensure_strategies_loaded()
        issuing_ca = get_object_or_404(CaModel, pk=pk)

        strategy_type_value = request.POST.get('strategy_type', CaRolloverStrategyType.IMPORT_CA)
        try:
            strategy_type = CaRolloverStrategyType(strategy_type_value)
        except ValueError:
            messages.error(request, _('Invalid rollover strategy type.'))
            return redirect('pki:issuing_cas-config', pk=pk)

        try:
            strategy = rollover_registry.get(strategy_type)
        except KeyError:
            messages.error(request, _('Selected rollover strategy is not available.'))
            return redirect('pki:issuing_cas-config', pk=pk)

        form = strategy.get_plan_form(
            old_ca=issuing_ca,
            data=request.POST,
            files=request.FILES,
        )

        if not form.is_valid():
            for errors in form.errors.values():
                for error in errors:
                    messages.error(request, str(error))
            return redirect('pki:issuing_cas-config', pk=pk)

        try:
            rollover = CaRolloverService.plan_rollover(
                old_ca=issuing_ca,
                strategy_type=strategy_type,
                form=form,
                initiated_by=request.user if request.user.is_authenticated else None,
            )
            messages.success(request, _('CA rollover planned successfully.'))
            actor = request.user if request.user.is_authenticated else None
            AuditLog.create_entry(
                operation_type=AuditLog.OperationType.CA_ROLLOVER_PLANNED,
                target=rollover,
                target_display=f'CA Rollover: {issuing_ca.unique_name} → {rollover.new_issuing_ca}',
                actor=actor,
            )
        except CaRolloverError as exc:
            messages.error(request, str(exc))

        return redirect('pki:issuing_cas-config', pk=pk)


class StartRolloverView(LoginRequiredMixin, View):
    """Handle GET (confirmation page) and POST (execute) for starting a CA rollover."""

    def get(self, request: HttpRequest, pk: int, rollover_pk: int) -> HttpResponse:
        """Render the confirmation page for starting the rollover."""
        _ensure_strategies_loaded()
        issuing_ca = get_object_or_404(CaModel, pk=pk)
        rollover = get_object_or_404(CaRolloverModel, pk=rollover_pk, old_issuing_ca_id=pk)
        return render(request, 'pki/issuing_cas/rollover/confirm_start.html', {
            'issuing_ca': issuing_ca,
            'rollover': rollover,
        })

    def post(self, request: HttpRequest, pk: int, rollover_pk: int) -> HttpResponse:
        """Start the specified rollover."""
        if not request.user.has_perm(AppPermissions.MANAGE_CAS):
            raise PermissionDenied
        _ensure_strategies_loaded()
        rollover = get_object_or_404(CaRolloverModel, pk=rollover_pk, old_issuing_ca_id=pk)

        try:
            CaRolloverService.execute_rollover(rollover)
            messages.success(
                request,
                _('Rollover started. New certificates will be issued by the new CA.'),
            )
            actor = request.user if request.user.is_authenticated else None
            AuditLog.create_entry(
                operation_type=AuditLog.OperationType.CA_ROLLOVER_STARTED,
                target=rollover,
                target_display=f'CA Rollover: {rollover.old_issuing_ca} → {rollover.new_issuing_ca}',
                actor=actor,
            )
        except CaRolloverError as exc:
            messages.error(request, str(exc))

        return redirect('pki:issuing_cas-config', pk=pk)


class TransitionRolloverView(LoginRequiredMixin, View):
    """Handle GET (confirmation page) and POST (execute) for transitioning a CA rollover."""

    def get(self, request: HttpRequest, pk: int, rollover_pk: int) -> HttpResponse:
        """Render the confirmation page for transitioning the rollover."""
        _ensure_strategies_loaded()
        issuing_ca = get_object_or_404(CaModel, pk=pk)
        rollover = get_object_or_404(CaRolloverModel, pk=rollover_pk, old_issuing_ca_id=pk)
        return render(request, 'pki/issuing_cas/rollover/confirm_transition.html', {
            'issuing_ca': issuing_ca,
            'rollover': rollover,
        })

    def post(self, request: HttpRequest, pk: int, rollover_pk: int) -> HttpResponse:
        """Transition the specified rollover from PREPARATION to TRANSITION."""
        if not request.user.has_perm(AppPermissions.MANAGE_CAS):
            raise PermissionDenied
        _ensure_strategies_loaded()
        rollover = get_object_or_404(CaRolloverModel, pk=rollover_pk, old_issuing_ca_id=pk)

        try:
            rollover.transition_to_transition()
            messages.success(
                request,
                _('Rollover transitioned. New CA is now issuing certificates, old CA remains in truststore.'),
            )
            actor = request.user if request.user.is_authenticated else None
            AuditLog.create_entry(
                operation_type=AuditLog.OperationType.CA_ROLLOVER_TRANSITIONED,
                target=rollover,
                target_display=f'CA Rollover: {rollover.old_issuing_ca} → {rollover.new_issuing_ca}',
                actor=actor,
            )
        except ValueError as exc:
            messages.error(request, str(exc))

        return redirect('pki:issuing_cas-config', pk=pk)


class CompleteRolloverView(LoginRequiredMixin, View):
    """Handle GET (confirmation page) and POST (finalize) for completing a CA rollover."""

    def get(self, request: HttpRequest, pk: int, rollover_pk: int) -> HttpResponse:
        """Render the confirmation page for completing the rollover."""
        _ensure_strategies_loaded()
        issuing_ca = get_object_or_404(CaModel, pk=pk)
        rollover = get_object_or_404(CaRolloverModel, pk=rollover_pk, old_issuing_ca_id=pk)
        return render(request, 'pki/issuing_cas/rollover/confirm_complete.html', {
            'issuing_ca': issuing_ca,
            'rollover': rollover,
        })

    def post(self, request: HttpRequest, pk: int, rollover_pk: int) -> HttpResponse:
        """Complete the specified rollover."""
        if not request.user.has_perm(AppPermissions.MANAGE_CAS):
            raise PermissionDenied
        _ensure_strategies_loaded()
        rollover = get_object_or_404(CaRolloverModel, pk=rollover_pk, old_issuing_ca_id=pk)

        try:
            CaRolloverService.finalize_rollover(rollover)
            messages.success(request, _('Rollover completed successfully.'))
            actor = request.user if request.user.is_authenticated else None
            AuditLog.create_entry(
                operation_type=AuditLog.OperationType.CA_ROLLOVER_COMPLETED,
                target=rollover,
                target_display=f'CA Rollover: {rollover.old_issuing_ca} → {rollover.new_issuing_ca}',
                actor=actor,
            )
        except CaRolloverError as exc:
            messages.error(request, str(exc))

        return redirect('pki:issuing_cas-config', pk=pk)


class CancelRolloverView(LoginRequiredMixin, View):
    """Handle GET (confirmation page) and POST (cancel) for cancelling a CA rollover."""

    def get(self, request: HttpRequest, pk: int, rollover_pk: int) -> HttpResponse:
        """Render the confirmation page for cancelling the rollover."""
        _ensure_strategies_loaded()
        issuing_ca = get_object_or_404(CaModel, pk=pk)
        rollover = get_object_or_404(CaRolloverModel, pk=rollover_pk, old_issuing_ca_id=pk)
        return render(request, 'pki/issuing_cas/rollover/confirm_cancel.html', {
            'issuing_ca': issuing_ca,
            'rollover': rollover,
        })

    def post(self, request: HttpRequest, pk: int, rollover_pk: int) -> HttpResponse:
        """Cancel the specified rollover."""
        if not request.user.has_perm(AppPermissions.MANAGE_CAS):
            raise PermissionDenied
        _ensure_strategies_loaded()
        rollover = get_object_or_404(CaRolloverModel, pk=rollover_pk, old_issuing_ca_id=pk)

        try:
            CaRolloverService.cancel_rollover(rollover)
            messages.success(request, _('Rollover cancelled.'))
            actor = request.user if request.user.is_authenticated else None
            AuditLog.create_entry(
                operation_type=AuditLog.OperationType.CA_ROLLOVER_CANCELLED,
                target=rollover,
                target_display=f'CA Rollover: {rollover.old_issuing_ca} → {rollover.new_issuing_ca}',
                actor=actor,
            )
        except CaRolloverError as exc:
            messages.error(request, str(exc))

        return redirect('pki:issuing_cas-config', pk=pk)
