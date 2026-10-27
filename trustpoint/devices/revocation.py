# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Compatibility entry point for device credential revocation."""

from __future__ import annotations

from pki.services.revocation import revoke_primary_certificate


class DeviceCredentialRevocation:
    """Delegate existing device callers to the shared PKI service."""

    @staticmethod
    def revoke_certificate(issued_credential_id: int, reason: str) -> tuple[bool, str]:
        """Revokes a certificate given an ID of an IssuedCredentialModel instance."""
        return revoke_primary_certificate(issued_credential_id, reason)
