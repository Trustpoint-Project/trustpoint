# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""CA discovery regressions using the enrollment workflow's complete setup."""

import base64
import io
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
from django.core.management import call_command
from trustpoint_core.serializer import CertificateCollectionSerializer

from est.views import EstCACertsView
from pki.models.ca import CaModel
from pki.util.x509 import CertificateGenerator


@pytest.mark.parametrize('suffix', ['', '/'])
def test_cacerts_with_local_and_ra_domains(client, settings, tmp_path, suffix):
    """Discovery includes keyless RAs and excludes their upstream TLS credentials."""
    settings.DEVELOPMENT_ENV = True
    settings.DOCKER_CONTAINER = False
    settings.TRUSTPOINT_IS_OPERATIONAL = True
    settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True
    environment_file = tmp_path / 'protocols.json'
    call_command('create_protocol_test_env', output=environment_file, stdout=io.StringIO())
    call_command('create_ra_setup', host='127.0.0.1', port=8443, output=environment_file, stdout=io.StringIO())
    protocols = json.loads(environment_file.read_text())['protocols']

    response = client.get('/.well-known/est/cacerts' + suffix)
    assert response.status_code == 200
    assert response['Content-Type'] == 'application/pkcs7-mime'
    certificates = load_der_pkcs7_certificates(base64.b64decode(response.content))
    assert certificates
    assert len(certificates) == len(set(certificates))
    assert all(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca for cert in certificates)

    for protocol in ['est', 'est_ra', 'cmp_ra']:
        scoped = client.get(f'/.well-known/est/{protocols[protocol]["domain"]}/cacerts{suffix}')
        assert scoped.status_code == 200
        scoped_certificates = load_der_pkcs7_certificates(base64.b64decode(scoped.content))
        assert set(scoped_certificates).issubset(set(certificates))
        if protocol.endswith('_ra'):
            # RA domains publish the upstream CA without owning its private key.
            ra = CaModel.objects.get(domains__unique_name=protocols[protocol]['domain'])
            assert ra.credential is None
            assert ra.get_certificate() in scoped_certificates


def test_ra_chain_only_includes_actual_ca_issuers(domain_instance):
    """Exclude unrelated CAs with matching names and TLS end-entity certificates."""
    root = domain_instance['cert']
    issuer_name = root.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    issuer, _ = CertificateGenerator.create_issuing_ca(domain_instance['priv_key'], issuer_name, 'Remote Issuer')
    unrelated, _ = CertificateGenerator.create_root_ca(issuer_name)
    tls = x509.load_pem_x509_certificate(
        (Path(__file__).resolve().parents[3] / 'tests/data/x509/https_server.crt').read_bytes()
    )
    ca = Mock(credential=None)
    ca.get_certificate.return_value = issuer
    ca.chain_truststore.get_certificate_collection_serializer.return_value = CertificateCollectionSerializer(
        [unrelated, tls, issuer, root]
    )
    assert EstCACertsView._get_ca_chain(ca).as_crypto() == [issuer, root]


def test_ra_without_ca_certificate_is_rejected():
    ca = Mock(credential=None)
    ca.get_certificate.return_value = None
    with pytest.raises(ValueError, match='no certificate available'):
        EstCACertsView._get_ca_chain(ca)
