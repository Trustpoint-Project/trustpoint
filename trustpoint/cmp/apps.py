# Copyright (c) 2026 The Trustpoint Project Authors

"""The Django CMP Application Configuration."""

from django.apps import AppConfig


class CmpConfig(AppConfig):
    """Cmp Configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'cmp'
