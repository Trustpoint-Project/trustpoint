# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management command that evaluates all certificate policy notifications in one pass."""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand

from management.services.certificate_policy_notifications import check_certificate_policy_notifications


class Command(BaseCommand):
    """Check certificate signatures, RSA key sizes and ECC curves in one scan."""

    help = 'Check certificates against the active cryptographic policy in one pass.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Run every certificate policy check over one streamed table scan."""
        check_certificate_policy_notifications()
        self.stdout.write(self.style.SUCCESS('Certificate policy checks completed.'))
