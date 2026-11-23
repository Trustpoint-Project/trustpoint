# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management command to check certificates with insufficient key lengths."""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand

from management.services.certificate_policy_notifications import check_certificate_policy_notifications


class Command(BaseCommand):
    """Command to check for certificates using insufficient RSA key lengths."""

    help = 'Deprecated alias for check_certificate_policy; checks only RSA key lengths.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        check_certificate_policy_notifications(signature=False, key=True, curve=False)
        self.stdout.write(self.style.SUCCESS('Insufficient key length check completed.'))
