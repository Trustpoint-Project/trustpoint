# Copyright (c) The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""The Django CMP Application Configuration."""

from django.apps import AppConfig


class CmpConfig(AppConfig):
    """Cmp Configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'cmp'
