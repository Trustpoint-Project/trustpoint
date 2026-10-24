# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Public certificate export operations shared by the management API."""

from pki.models.certificate import CertificateModel


def certificate_chain(certificate: CertificateModel) -> list[CertificateModel]:
    """Return known issuers in order, rejecting circular issuer relationships."""
    chain = []
    seen = {certificate.pk}
    current = certificate
    while current.issuer_id is not None and current.issuer_id.pk != current.pk:
        issuer = current.issuer_id
        if issuer.pk in seen:
            msg = 'The certificate issuer chain contains a cycle.'
            raise ValueError(msg)
        seen.add(issuer.pk)
        chain.append(issuer)
        current = issuer
    return chain


def certificate_filename(certificate: CertificateModel, extension: str) -> str:
    """Keep filenames safe and unique even when common names are duplicated or empty."""
    name = ''.join(char if char.isalnum() or char in '._-' else '_' for char in certificate.common_name)
    name = name.strip('._-')[:100] or 'certificate'
    return f'{name}-{certificate.pk}{extension}'
