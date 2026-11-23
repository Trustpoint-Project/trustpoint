# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management command to check for not permitted signature algorithms."""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand

from management.services.certificate_policy_notifications import check_certificate_policy_notifications


class Command(BaseCommand):
    """Custom Django management command to check certificates for not permitted signature algorithms."""

    help = 'Deprecated alias for check_certificate_policy; checks only signature algorithms.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        check_certificate_policy_notifications(signature=True, key=False, curve=False)
        self.stdout.write(self.style.SUCCESS('Not permitted signature algorithms check completed.'))
