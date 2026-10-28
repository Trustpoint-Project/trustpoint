# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Verify shipped certificate profile CRL settings."""

import json
from pathlib import Path

from pki.util.cert_profile import JSONProfileVerifier


def test_shipped_device_profiles_expose_editable_crl_urls() -> None:
    """Shipped device profiles expose the active TLS IP and CA endpoint template."""
    paths = list((Path(__file__).parents[1] / 'default_certificate_profiles').glob('*.json'))
    assert paths
    for path in paths:
        if path.stem == 'issuing_ca':
            continue
        profile = JSONProfileVerifier(json.loads(path.read_text())).get_profile()
        crl = profile['extensions']['crl_distribution_points']
        assert crl['critical'] is False, path.name
        assert crl['uris']['mutable'] is True, path.name
        assert crl['uris']['value'] == ['http://{tls_certificate.ip_address.1}/crl/{issuing_ca.id}'], path.name
