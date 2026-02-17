"""SetupWizard Models."""
from datetime import UTC
from typing import Any, Final

from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone


class SetupWizardCompletedModel(models.Model):
    """Global, write-once configuration state for an on-prem installation.

    This model is designed as a singleton row (primary key fixed to `SINGLETON_ID`)
    that records whether initial setup has completed. Once `setup_completed_at` is
    set (non-null), it is treated as immutable by application-level validation.

    For a hard guarantee (including against direct SQL), enforce immutability with
    a PostgreSQL trigger as well.
    """

    SINGLETON_ID: Final[int] = 1

    singleton_id: models.PositiveSmallIntegerField[int, int] = models.PositiveSmallIntegerField(
        primary_key=True,
        default=SINGLETON_ID,
        editable=False,
        help_text='Singleton primary key. Always 1.',
    )
    setup_completed_at: models.DateTimeField[timezone.datetime | None, timezone.datetime | None] = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Timestamp when initial setup was completed. Write-once once set.',
    )

    def __str__(self) -> str:
        """Return a human-readable representation of the singleton configuration.

        Returns:
            A short string indicating whether setup is pending or completed, and
            the completion timestamp if present.
        """
        if self.setup_completed_at is None:
            return 'SetupWizardCompletedModel(setup=pending)'
        return f'SetupWizardCompletedModel(setup=completed at {self.setup_completed_at:%Y-%m-%d %H:%M:%S%z})'

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Persist this instance after validating write-once semantics.

        Args:
            *args: Positional arguments forwarded to Django's `Model.save()`.
            **kwargs: Keyword arguments forwarded to Django's `Model.save()`.
        """
        self.full_clean()
        super().save(*args, **kwargs)

    @property
    def setup_wizard_completed(self) -> bool:
        """Return whether the setup wizard has been completed.

        Returns:
            True if the setup wizard was completed, False otherwise.
        """
        return self.setup_completed_at is not None

    def clean(self) -> None:
        """Validate model state.

        Enforces application-level immutability: if `setup_completed_at` has ever
        been set in the database, attempts to change it (including resetting to
        null or changing the timestamp) raise `ValidationError`.

        Raises:
            ValidationError: If `setup_completed_at` is modified after being set.
        """
        if self.pk:
            prior = (
                SetupWizardCompletedModel
                .objects.filter(pk=self.pk)
                .values_list('setup_completed_at', flat=True)
                .first()
            )
            if prior is not None and self.setup_completed_at != prior:
                raise ValidationError(
                    {'setup_completed_at": "Initial setup is write-once and cannot be modified.'}
                )

    @classmethod
    def mark_setup_complete_once(cls) -> bool:
        """Atomically mark setup as complete exactly once.

        Uses a row-level lock to prevent races. If setup is already complete,
        the method is a no-op.

        Returns:
            True if setup completion was recorded by this call, otherwise False.
        """
        with transaction.atomic():
            cfg, _created = cls.objects.select_for_update().get_or_create(
                singleton_id=cls.SINGLETON_ID
            )
            if cfg.setup_completed_at is not None:
                return False
            cfg.setup_completed_at = timezone.now().astimezone(UTC)
            cfg.save(update_fields=['setup_completed_at'])
            return True


class SetupWizardConfigurationModel(models.Model):
    """Model that holds the data that will be applied when the setup wizard is completed."""

    SINGLETON_ID: Final[int] = 1

    singleton_id = models.PositiveSmallIntegerField(
        primary_key=True,
        default=SINGLETON_ID,
        editable=False,
        help_text='Singleton primary key. Always 1.',
    )

    inject_demo_data = models.BooleanField(default=False, help_text='Inject demo data.')

