"""Django signals for PKI models."""

from __future__ import annotations

from typing import Any

from django.db.models.signals import post_save
from django.dispatch import receiver

from pki.models import CaModel, CrlModel


@receiver(post_save, sender=CrlModel)
def schedule_next_crl_after_generation(
    sender: type[CrlModel],  # noqa: ARG001
    instance: CrlModel,
    *,
    created: bool,
    **kwargs: Any,  # noqa: ARG001
) -> None:
    """Schedule the next CRL generation after a CRL is created.

    Args:
        sender: The model class.
        instance: The CrlModel instance.
        created: Whether the instance was created.
        **kwargs: Additional keyword arguments.
    """
    if not created or instance.ca is None:
        return

    ca = instance.ca
    if ca.crl_cycle_enabled:
        ca.schedule_next_crl_generation()


@receiver(post_save, sender=CaModel)
def schedule_crl_on_cycle_enable(
    sender: type[CaModel],  # noqa: ARG001
    instance: CaModel,
    *,
    created: bool,
    update_fields: set[str] | None,
    **kwargs: Any,  # noqa: ARG001
) -> None:
    """Schedule CRL generation when CRL cycle is enabled on a CA.

    Args:
        sender: The model class.
        instance: The CaModel instance.
        created: Whether the instance was created.
        update_fields: The fields that were updated.
        **kwargs: Additional keyword arguments.
    """
    if created:
        return

    # Check if crl_cycle_enabled was toggled to True
    if update_fields and 'crl_cycle_enabled' in update_fields and instance.crl_cycle_enabled:
        instance.schedule_next_crl_generation()
