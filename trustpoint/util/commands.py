# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared logging and console output for management commands."""

from __future__ import annotations

from typing import TYPE_CHECKING

from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from django.core.management.base import OutputWrapper
    from django.core.management.color import Style


class CommandLoggingMixin(LoggerMixin):
    """Log command messages and write matching styled console output."""

    stdout: OutputWrapper
    style: Style

    def log_and_stdout(self, message: str, level: str = 'info') -> None:
        """Write one message to the logger and standard output."""
        getattr(self.logger, level, self.logger.info)(message)
        if level == 'error':
            self.stdout.write(self.style.ERROR(message))
        elif level == 'warning':
            self.stdout.write(self.style.WARNING(message))
        elif level == 'info':
            self.stdout.write(self.style.SUCCESS(message))
        else:
            self.stdout.write(message)
