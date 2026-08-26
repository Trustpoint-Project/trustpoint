# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Discover USB smart-card HSMs through the bundled OpenSC module."""

from __future__ import annotations

import json
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from crypto.adapters.pkcs11.discovery import discover_pkcs11_tokens
from crypto.domain.errors import CryptoError


class Command(BaseCommand):
    """Print unauthenticated OpenSC token discovery results as JSON."""

    help = 'Discover USB smart-card HSMs through OpenSC and print token identities as JSON.'

    def handle(self, *_args: Any, **_options: Any) -> None:
        """Run token discovery in this isolated management-command process."""
        try:
            tokens = discover_pkcs11_tokens(str(settings.HSM_OPENSC_PKCS11_MODULE_PATH))
        except CryptoError as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(json.dumps({'tokens': [token.to_json_dict() for token in tokens]}, sort_keys=True))
