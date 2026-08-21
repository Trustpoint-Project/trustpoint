# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Django apps module which defines the app configuration."""

from django.apps import AppConfig


class UsersConfig(AppConfig):
    """App configuration for the users app."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users'
