"""SetupWizard Models."""
from datetime import UTC
from typing import Any, Final, ClassVar, Self

from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy


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
    setup_completed_at = models.DateTimeField(
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

    @classmethod
    def setup_wizard_completed(cls) -> bool:
        """Class-level check.

        Returns:
            False if row does not exist or setup_completed_at is NULL, True otherwise.
        """
        return cls.objects.filter(pk=cls.SINGLETON_ID, setup_completed_at__isnull=False).exists()

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
                err_msg =  {'setup_completed_at': 'Initial setup is write-once and cannot be modified.'}
                raise ValidationError(err_msg)

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


class SetupWizardConfigModel(models.Model):
    """Model that holds the data that will be applied when the setup wizard is completed."""

    # ClassVar and Final can be nested with python >= 3.13
    # noinspection PyFinal
    SINGLETON_ID: ClassVar[Final[int]] = 1

    singleton_id = models.PositiveSmallIntegerField(
        primary_key=True,
        default=SINGLETON_ID,
        editable=False,
        help_text='Singleton primary key. Always 1.',
    )

    class FreshInstallCurrentStep(models.IntegerChoices):
        CRYPTO_STORAGE = 0, gettext_lazy('Crypto-Storage')
        DEMO_DATA = 1, gettext_lazy('Demo-Data')
        TLS_CONFIG = 2, gettext_lazy('TLS-Config')
        SUMMARY = 3, gettext_lazy('Summary')

    fresh_install_current_step = models.PositiveSmallIntegerField(
        choices=FreshInstallCurrentStep,
        null=False,
        blank=True,
        default=FreshInstallCurrentStep.CRYPTO_STORAGE,
    )

    fresh_install_crypto_storage_submitted = models.BooleanField(
        default=False,
        help_text='Whether the crypto storage step was submitted.',
    )

    fresh_install_demo_data_submitted = models.BooleanField(
        default=False,
        help_text='Whether the demo data step was submitted.',
    )

    fresh_install_tls_config_submitted = models.BooleanField(
        default=False,
        help_text='Whether the TLS config step was submitted.',
    )

    fresh_install_summary_submitted = models.BooleanField(
        default=False,
        help_text='Whether the summary step was submitted.'
    )

    class CryptoStorageType(models.IntegerChoices):
        SoftwareStorage = 0, gettext_lazy('Software Storage')
        HsmStorage = 1, gettext_lazy('HSM Storage')

    crypto_storage = models.PositiveSmallIntegerField(
        choices=CryptoStorageType,
        null=False,
        blank=False,
        default=CryptoStorageType.SoftwareStorage
    )

    inject_demo_data = models.BooleanField(
        null=False,
        blank=False,
        help_text='Inject demo data.',
        default=True
    )

    @classmethod
    def get_singleton(cls) -> Self:
        obj, _ = cls.objects.get_or_create(pk=cls.SINGLETON_ID)
        return obj

    @classmethod
    def get_current_step(cls) -> FreshInstallCurrentStep:
        """Return the current fresh-install step as an enum member.

        Returns:
            The current step as FreshInstallCurrentStep.
        """
        singleton = cls.get_singleton()
        return singleton.FreshInstallCurrentStep(singleton.fresh_install_current_step)

    def is_step_submitted(self, step: FreshInstallCurrentStep) -> bool:
        """Return whether the given fresh-install step was submitted."""
        submitted_fields = {
            self.FreshInstallCurrentStep.CRYPTO_STORAGE: self.fresh_install_crypto_storage_submitted,
            self.FreshInstallCurrentStep.DEMO_DATA: self.fresh_install_demo_data_submitted,
            self.FreshInstallCurrentStep.TLS_CONFIG: self.fresh_install_tls_config_submitted,
            self.FreshInstallCurrentStep.SUMMARY: False,
        }
        return submitted_fields[step]

    def mark_step_submitted(self, step: FreshInstallCurrentStep) -> None:
        """Mark the given fresh-install step as submitted."""
        if step == self.FreshInstallCurrentStep.SUMMARY:
            return
        field_name = {
            self.FreshInstallCurrentStep.CRYPTO_STORAGE: 'fresh_install_crypto_storage_submitted',
            self.FreshInstallCurrentStep.DEMO_DATA: 'fresh_install_demo_data_submitted',
            self.FreshInstallCurrentStep.TLS_CONFIG: 'fresh_install_tls_config_submitted',
        }[step]
        setattr(self, field_name, True)

    def clean(self) -> None:
        super().clean()
        if self.pk is not None and self.pk != self.SINGLETON_ID:
            err_msg = {'singleton_id': gettext_lazy('singleton_id must always be 1.')}
            raise ValidationError(err_msg)

    def save(self, *args: Any, **kwargs: Any) -> None:

        if self.pk is None:
            self.pk = self.SINGLETON_ID
        elif self.pk != self.SINGLETON_ID:
            err_msg  = 'Only the singleton row with pk=1 is allowed.'
            raise ValidationError(err_msg)

        return super().save(*args, **kwargs)
