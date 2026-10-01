# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Service layer for Issuing CA rollover operations."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from django.db import IntegrityError, transaction
from django.db.models import Q

from pki.models import CaModel
from pki.models.ca_rollover import CaRolloverModel, CaRolloverState, CaRolloverStrategyType
from pki.rollover.registry import rollover_registry

if TYPE_CHECKING:
    from django import forms
    from django.db.models import QuerySet

    from pki.rollover.base import RolloverStrategy
    from users.models import TrustpointUser

logger = logging.getLogger(__name__)


class CaRolloverError(Exception):
    """Raised when a CA rollover operation fails."""


class CaRolloverService:
    """Orchestrates Issuing CA rollover workflows.

    Delegates provisioning-specific logic to the appropriate RolloverStrategy.
    """

    @staticmethod
    def get_strategy(strategy_type: CaRolloverStrategyType) -> RolloverStrategy:
        """Resolve a strategy by its type identifier.

        :param strategy_type: The strategy type to look up.
        :returns: The registered RolloverStrategy instance.
        :raises CaRolloverError: If the strategy type is not registered.
        """
        try:
            return rollover_registry.get(strategy_type)
        except KeyError as exc:
            raise CaRolloverError(str(exc)) from exc

    @staticmethod
    def get_available_strategies() -> list[tuple[str, str]]:
        """Return the list of available rollover strategies for form dropdowns.

        :returns: List of (value, label) tuples.
        """
        return rollover_registry.get_available()

    @staticmethod
    def plan_rollover(
        old_ca: CaModel,
        strategy_type: CaRolloverStrategyType,
        form: forms.Form,
        initiated_by: TrustpointUser | None = None,
    ) -> CaRolloverModel:
        """Plan and create a new CA rollover.

        :param old_ca: The current Issuing CA being replaced.
        :param strategy_type: Which provisioning strategy to use.
        :param form: The validated strategy-specific form.
        :param initiated_by: The user who initiated the rollover.
        :returns: The created CaRolloverModel.
        :raises CaRolloverError: If validation or creation fails.
        """
        local_types = {
            old_ca.CaTypeChoice.AUTOGEN,
            old_ca.CaTypeChoice.LOCAL_UNPROTECTED,
            old_ca.CaTypeChoice.LOCAL_PKCS11,
        }
        if old_ca.ca_type not in local_types:
            msg = 'Only locally managed Issuing CAs can be rolled over.'
            raise CaRolloverError(msg)

        try:
            with transaction.atomic():
                locked_ca = type(old_ca).objects.select_for_update().get(pk=old_ca.pk)
                active_exists = CaRolloverModel.objects.filter(
                    old_issuing_ca=locked_ca,
                    state__in=[
                        CaRolloverState.PLANNED,
                        CaRolloverState.AWAITING_NEW_CA,
                        CaRolloverState.PREPARATION,
                        CaRolloverState.TRANSITION,
                    ],
                ).exists()
                if active_exists:
                    msg = f'Issuing CA "{old_ca}" already has an active rollover.'
                    raise CaRolloverError(msg)

                completed_exists = CaRolloverModel.objects.filter(
                    old_issuing_ca=locked_ca,
                    state=CaRolloverState.COMPLETED,
                ).exists()
                if completed_exists:
                    msg = f'Issuing CA "{old_ca}" has already been rolled over. A second rollover is not permitted.'
                    raise CaRolloverError(msg)

                strategy = CaRolloverService.get_strategy(strategy_type)
                new_ca = strategy.create_new_ca(form, locked_ca)
                transition_scheduled_at = (
                    form.cleaned_data.get('transition_scheduled_at') if hasattr(form, 'cleaned_data') else None
                )
                notes = form.cleaned_data.get('notes', '') if hasattr(form, 'cleaned_data') else ''
                initial_state = (
                    CaRolloverState.AWAITING_NEW_CA
                    if strategy.awaits_new_ca_certificate
                    else CaRolloverState.PLANNED
                )
                rollover = CaRolloverModel.objects.create(
                    old_issuing_ca=locked_ca,
                    new_issuing_ca=new_ca,
                    state=initial_state,
                    strategy_type=strategy_type,
                    transition_scheduled_at=transition_scheduled_at,
                    initiated_by=initiated_by,
                    notes=notes,
                )
        except IntegrityError as exc:
            msg = f'Issuing CA "{old_ca}" already has an active rollover.'
            raise CaRolloverError(msg) from exc

        logger.info(
            'Planned CA rollover %s (%s): %s → %s [state=%s]',
            rollover.pk,
            strategy_type,
            old_ca,
            new_ca or '(pending)',
            initial_state,
        )
        return rollover

    @staticmethod
    @transaction.atomic
    def complete_awaiting_rollover_for_ca(ca: CaModel) -> CaRolloverModel | None:
        """Validate a requested CA certificate and make its rollover startable."""
        rollover = (
            CaRolloverModel.objects.select_for_update()
            .filter(new_issuing_ca=ca, state=CaRolloverState.AWAITING_NEW_CA)
            .first()
        )
        if rollover is None:
            return None
        if ca.credential is None or ca.credential.certificate is None:
            msg = 'The replacement CA certificate is not available yet.'
            raise CaRolloverError(msg)

        certificate = ca.credential.certificate.get_certificate_serializer().as_crypto()
        try:
            basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
            key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound as exc:
            msg = 'The replacement certificate is missing required CA extensions.'
            raise CaRolloverError(msg) from exc
        if not basic_constraints.ca or not key_usage.key_cert_sign or not key_usage.crl_sign:
            msg = 'The replacement certificate is not a valid issuing CA certificate.'
            raise CaRolloverError(msg)

        managed_key = ca.credential.managed_private_key
        if managed_key is None:
            msg = 'The replacement CA key is not managed by the configured crypto backend.'
            raise CaRolloverError(msg)
        public_key_der = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        certificate_key_fingerprint = hashes.Hash(hashes.SHA256())
        certificate_key_fingerprint.update(public_key_der)
        if certificate_key_fingerprint.finalize().hex().upper() != managed_key.public_key_fingerprint_sha256.upper():
            msg = 'The replacement certificate does not match the generated private key.'
            raise CaRolloverError(msg)

        ca.ca_type = CaModel.CaTypeChoice.LOCAL_PKCS11
        if ca.chain_truststore is None:
            ca.chain_truststore = CaModel._create_chain_truststore(ca)  # noqa: SLF001
        ca.save(update_fields=['ca_type', 'chain_truststore'])
        rollover.state = CaRolloverState.PLANNED
        rollover.save(update_fields=['state'])
        return rollover

    @staticmethod
    def execute_rollover(rollover: CaRolloverModel) -> None:
        """Start the rollover: transition from PLANNED to PREPARATION.

        :param rollover: The rollover to execute.
        :raises CaRolloverError: If the rollover cannot be started.
        """
        strategy = CaRolloverService.get_strategy(
            CaRolloverStrategyType(rollover.strategy_type),
        )

        try:
            rollover.start()
        except ValueError as exc:
            raise CaRolloverError(str(exc)) from exc

        strategy.on_start(rollover)

        rollover.schedule_transition_check()

        logger.info('Rollover %s started.', rollover.pk)

    @staticmethod
    def finalize_rollover(rollover: CaRolloverModel) -> None:
        """Complete the rollover.

        :param rollover: The rollover to finalize.
        :raises CaRolloverError: If the rollover cannot be completed.
        """
        strategy = CaRolloverService.get_strategy(
            CaRolloverStrategyType(rollover.strategy_type),
        )

        try:
            rollover.complete()
        except ValueError as exc:
            raise CaRolloverError(str(exc)) from exc

        strategy.on_complete(rollover)
        logger.info('Rollover %s completed.', rollover.pk)

    @staticmethod
    def cancel_rollover(rollover: CaRolloverModel) -> None:
        """Cancel the rollover.

        :param rollover: The rollover to cancel.
        :raises CaRolloverError: If the rollover cannot be cancelled.
        """
        strategy = CaRolloverService.get_strategy(
            CaRolloverStrategyType(rollover.strategy_type),
        )

        try:
            rollover.cancel()
        except ValueError as exc:
            raise CaRolloverError(str(exc)) from exc

        strategy.on_cancel(rollover)
        logger.info('Rollover %s cancelled.', rollover.pk)

    @staticmethod
    def get_active_rollover(issuing_ca: CaModel) -> CaRolloverModel | None:
        """Return the active rollover for the given Issuing CA, if any.

        :param issuing_ca: The Issuing CA to check.
        :returns: The active CaRolloverModel or None.
        """
        return CaRolloverModel.objects.filter(
            old_issuing_ca=issuing_ca,
            state__in=[
                CaRolloverState.PLANNED,
                CaRolloverState.AWAITING_NEW_CA,
                CaRolloverState.PREPARATION,
                CaRolloverState.TRANSITION,
            ],
        ).first()

    @staticmethod
    def get_rollover_history(issuing_ca: CaModel) -> QuerySet[CaRolloverModel]:
        """Return completed/cancelled rollovers involving the given CA.

        :param issuing_ca: The Issuing CA to look up.
        :returns: QuerySet of CaRolloverModel instances.
        """
        return CaRolloverModel.objects.filter(
            Q(old_issuing_ca=issuing_ca) | Q(new_issuing_ca=issuing_ca),
            state__in=[CaRolloverState.COMPLETED, CaRolloverState.CANCELLED],
        ).order_by('-planned_at')

    @staticmethod
    def has_completed_rollover(issuing_ca: CaModel) -> bool:
        """Return True if the given Issuing CA already has a completed rollover.

        :param issuing_ca: The Issuing CA to check.
        :returns: True if a completed rollover exists for this CA as the old CA.
        """
        return CaRolloverModel.objects.filter(
            old_issuing_ca=issuing_ca,
            state=CaRolloverState.COMPLETED,
        ).exists()
