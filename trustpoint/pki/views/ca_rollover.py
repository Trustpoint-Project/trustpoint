"""Views for CA rollover management within the Issuing CA config page."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext as _
from django.views import View

from management.models.audit_log import AuditLog
from pki.models import CaModel
from pki.models.ca_rollover import CaRolloverModel, CaRolloverStrategyType
from pki.rollover.registry import rollover_registry
from pki.services.ca_rollover import CaRolloverError, CaRolloverService

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse

logger = logging.getLogger(__name__)


def _ensure_strategies_loaded() -> None:
    """Ensure all strategy modules are imported so they register themselves."""
    import pki.rollover.import_ca  # noqa: F401, PLC0415


class PlanRolloverView(LoginRequiredMixin, View):
    """Handle POST to plan a new CA rollover from the Issuing CA config page."""

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Plan a new rollover for the given Issuing CA.

        :param request: The HTTP request.
        :param pk: Primary key of the current (old) Issuing CA.
        :returns: Redirect back to the Issuing CA config page.
        """
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
                initiated_by=request.user,
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
        """Render the confirmation page for starting the rollover.

        :param request: The HTTP request.
        :param pk: Primary key of the Issuing CA.
        :param rollover_pk: Primary key of the rollover to start.
        :returns: Rendered confirmation page.
        """
        _ensure_strategies_loaded()
        issuing_ca = get_object_or_404(CaModel, pk=pk)
        rollover = get_object_or_404(CaRolloverModel, pk=rollover_pk, old_issuing_ca_id=pk)
        return render(request, 'pki/issuing_cas/rollover/confirm_start.html', {
            'issuing_ca': issuing_ca,
            'rollover': rollover,
        })

    def post(self, request: HttpRequest, pk: int, rollover_pk: int) -> HttpResponse:
        """Start the specified rollover.

        :param request: The HTTP request.
        :param pk: Primary key of the Issuing CA.
        :param rollover_pk: Primary key of the rollover to start.
        :returns: Redirect back to the Issuing CA config page.
        """
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


class CompleteRolloverView(LoginRequiredMixin, View):
    """Handle GET (confirmation page) and POST (finalize) for completing a CA rollover."""

    def get(self, request: HttpRequest, pk: int, rollover_pk: int) -> HttpResponse:
        """Render the confirmation page for completing the rollover.

        :param request: The HTTP request.
        :param pk: Primary key of the Issuing CA.
        :param rollover_pk: Primary key of the rollover to complete.
        :returns: Rendered confirmation page.
        """
        _ensure_strategies_loaded()
        issuing_ca = get_object_or_404(CaModel, pk=pk)
        rollover = get_object_or_404(CaRolloverModel, pk=rollover_pk, old_issuing_ca_id=pk)
        return render(request, 'pki/issuing_cas/rollover/confirm_complete.html', {
            'issuing_ca': issuing_ca,
            'rollover': rollover,
        })

    def post(self, request: HttpRequest, pk: int, rollover_pk: int) -> HttpResponse:
        """Complete the specified rollover.

        :param request: The HTTP request.
        :param pk: Primary key of the Issuing CA.
        :param rollover_pk: Primary key of the rollover to complete.
        :returns: Redirect back to the Issuing CA config page.
        """
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
        """Render the confirmation page for cancelling the rollover.

        :param request: The HTTP request.
        :param pk: Primary key of the Issuing CA.
        :param rollover_pk: Primary key of the rollover to cancel.
        :returns: Rendered confirmation page.
        """
        _ensure_strategies_loaded()
        issuing_ca = get_object_or_404(CaModel, pk=pk)
        rollover = get_object_or_404(CaRolloverModel, pk=rollover_pk, old_issuing_ca_id=pk)
        return render(request, 'pki/issuing_cas/rollover/confirm_cancel.html', {
            'issuing_ca': issuing_ca,
            'rollover': rollover,
        })

    def post(self, request: HttpRequest, pk: int, rollover_pk: int) -> HttpResponse:
        """Cancel the specified rollover.

        :param request: The HTTP request.
        :param pk: Primary key of the Issuing CA.
        :param rollover_pk: Primary key of the rollover to cancel.
        :returns: Redirect back to the Issuing CA config page.
        """
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
