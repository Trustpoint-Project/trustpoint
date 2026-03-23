"""Internationalization configuration model."""

from __future__ import annotations

from typing import TYPE_CHECKING
from zoneinfo import ZoneInfo, available_timezones

if TYPE_CHECKING:
    from datetime import datetime

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

"""Supported Timezones"""
TIMEZONE_CHOICES = sorted((tz, tz) for tz in available_timezones())

class InternationalizationConfig(models.Model):
    """Internationalization configuration model."""

    class DateFormatChoices(models.TextChoices):
        """Types of date formats."""

        DD_MM_YYYY_24 = '0', 'dd/MM/yyyy HH:mm'
        MM_DD_YYYY_24 = '1', 'MM/dd/yyyy HH:mm'
        DD_MMM_YYYY_24 = '2', 'dd MMM yyyy HH:mm'
        DD_MMM_YYYY_12 = '3', 'dd MMM yyyy hh:mm a'
        DD_MMMM_YYYY_24_SEC = '4', 'dd MMMM yyyy HH:mm:ss'
        DD_MMMM_YYYY_12_SEC = '5', 'dd MMMM yyyy hh:mm:ss a'
        YYYY_MM_DD_24_SEC = '6', 'yyyy-MM-dd HH:mm:ss'
        ISO_LIKE = '7', "yyyy-MM-dd'T'HH:mm:ss"

    class LanguageChoices(models.TextChoices):
        """Supported languages."""

        DE = 'de', _('German')
        EN = 'en', _('English')

    date_format = models.CharField(max_length=1, choices=DateFormatChoices, default=DateFormatChoices.YYYY_MM_DD_24_SEC)
    language = models.CharField(max_length=2, choices=LanguageChoices, default=LanguageChoices.EN)
    timezone = models.CharField(max_length=64, choices=TIMEZONE_CHOICES, default='UTC')

    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        """Return a readable string representation of the configuration."""
        return f'{self.get_date_format_display()} | {self.language} | {self.timezone}'

    @classmethod
    def get_current(cls) -> InternationalizationConfig:
        """Return the current internationalization configuration."""
        config, _ = cls.objects.get_or_create(
            id=1,
            defaults={
                'date_format': cls.DateFormatChoices.YYYY_MM_DD_24_SEC,
                'language': cls.LanguageChoices.EN,
                'timezone': 'UTC',
            },
        )
        return config

    def get_python_datetime_format(self) -> str:
        """Return the configured format as Python strftime format."""
        format_map: dict[str, str] = {
            '0': '%d/%m/%Y %H:%M',
            '1': '%m/%d/%Y %H:%M',
            '2': '%d %b %Y %H:%M',
            '3': '%d %b %Y %I:%M %p',
            '4': '%d %B %Y %H:%M:%S',
            '5': '%d %B %Y %I:%M:%S %p',
            '6': '%Y-%m-%d %H:%M:%S',
            '7': '%Y-%m-%dT%H:%M:%S',
        }
        return format_map.get(self.date_format, '%Y-%m-%d %H:%M:%S')

    def format_datetime(self, value: datetime | None) -> str:
        """Format a datetime using the configured timezone and date format."""
        if value is None:
            return ''

        if timezone.is_naive(value):
            value = timezone.make_aware(value, ZoneInfo('UTC'))

        converted_value = value.astimezone(ZoneInfo(self.timezone))
        return converted_value.strftime(self.get_python_datetime_format())
