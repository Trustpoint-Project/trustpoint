# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared management test credentials."""

import pytest


@pytest.fixture
def traceability_curve():
    from management.models.traceability import TraceabilityCredentialModel

    return TraceabilityCredentialModel.Curve.SECP256R1


@pytest.fixture
def traceability_management_ca(traceability_curve):
    """A real backend-managed CA for traceability issuance and export tests."""
    from crypto.models import CryptoManagedKeyModel
    from pki.models import CaModel, CredentialModel
    from crypto.application.private_keys import generate_managed_signing_private_key
    from crypto.domain.algorithms import EllipticCurveName
    from crypto.domain.specs import EcKeySpec
    from management.models.traceability import TraceabilityCredentialModel
    from pki.util.x509 import CertificateGenerator

    curve = (
        EllipticCurveName.SECP384R1
        if traceability_curve == TraceabilityCredentialModel.Curve.SECP384R1
        else EllipticCurveName.SECP256R1
    )
    key = generate_managed_signing_private_key(alias='traceability-management-ca', key_spec=EcKeySpec(curve=curve))
    certificate, _ = CertificateGenerator.create_root_ca(cn='Traceability Management CA', private_key=key)
    credential = CredentialModel.save_managed_key_credential(
        certificate=certificate,
        certificate_chain=[],
        credential_type=CredentialModel.CredentialTypeChoice.ISSUING_CA,
        managed_key=CryptoManagedKeyModel.objects.get(pk=key.managed_key_ref.id),
    )
    return CaModel.objects.create(
        unique_name='Traceability Management CA',
        credential=credential,
        ca_type=CaModel.CaTypeChoice.SELF_SIGNED,
        ca_role=CaModel.CaRole.MANAGEMENT,
    )
