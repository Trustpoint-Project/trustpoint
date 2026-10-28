# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""PKI setup helpers for Behave tests."""

from __future__ import annotations

from pki.models import CaModel, DomainModel
from pki.tests.managed_ca_helpers import create_managed_root_ca
from pki.util.x509 import CertificateGenerator


def create_local_ca(unique_name: str = 'behave_ca') -> CaModel:
    """Create a local managed CA using the existing PKI test helper."""
    certificate, private_key = create_managed_root_ca(cn=unique_name)
    return CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=certificate,
        private_key=private_key,
        chain=[],
        unique_name=unique_name,
        ca_type=CaModel.CaTypeChoice.LOCAL_PKCS11,
    )


def create_domain(*, unique_name: str, issuing_ca: CaModel | None = None) -> DomainModel:
    """Create a domain with an optional issuing CA."""
    return DomainModel.objects.create(unique_name=unique_name, issuing_ca=issuing_ca)
