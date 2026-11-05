# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Overrides django-extensions' runserver_plus so the TLS credential is stored in the database."""

from .custom_runserver_plus import Command

__all__ = ['Command']
