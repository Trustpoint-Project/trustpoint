# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Django application configuration for Web UI automation."""

from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class WebUiAutomationConfig(AppConfig):
    """Configure the Web UI automation application."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'web_ui_automation'
    verbose_name = _('Web UI Automation')
