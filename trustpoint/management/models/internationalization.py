"""Date format configuration Model"""

from __future__ import annotations

from django.db import models
from django.utils.translation import gettext_lazy as _
from zoneinfo import available_timezones

"""Supported timezones"""
TIMEZONE_CHOICES = sorted((tz, tz) for tz in available_timezones())

class InternationalizationConfig(models.Model):
    """Dateformat Configuration model."""

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
        return f'{self.date_format} | {self.language} | {self.timezone}'