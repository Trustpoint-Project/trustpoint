# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management TLS issuance (EST + local CA) view integration tests."""

import datetime as dt
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.core.management import call_command
from django.test import RequestFactory
from django.urls import resolve, reverse
from trustpoint_core.oid import PublicKeyAlgorithmOid, PublicKeyInfo

from crypto.models import CryptoManagedKeyModel
from management.forms import TlsLocalCaSelectForm
from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol
from pki.forms.truststores import TruststoreAddForm
from pki.models import CaModel, CredentialModel
from pki.models.truststore import TruststoreModel
from pki.services.management_issuance import key_type_for_management_ca
from pki.tests.managed_ca_helpers import create_managed_root_ca
from pki.util.x509 import CertificateGenerator

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _profiles() -> None:
    call_command('create_default_cert_profiles')


class Client:
    """Minimal session-preserving request helper for the TLS issuance wizard."""

    def __init__(self):
        self.session = {}
        self.user = Mock()
        self.user.has_perm.return_value = True
        self.factory = RequestFactory()

    def request(self, name, pk=None, method='get', data=None):
        url = reverse(f'management:{name}', kwargs={'pk': pk} if pk is not None else {})
        request = getattr(self.factory, method)(url, data=data or {})
        request.user = self.user
        request.session = self.session
        match = resolve(url)
        return match.func(request, **match.kwargs)

    def post_key(self, name):
        response = self.request(name, method='post', data={'key_type': 'ECC-SECP256R1'})
        assert response.status_code == 302
        return resolve(response.url).kwargs['pk']


def _local_ca(unique_name: str) -> CaModel:
    ca_cert, ca_key = create_managed_root_ca(unique_name)
    credential = CredentialModel.save_managed_key_credential(
        certificate=ca_cert,
        certificate_chain=[],
        credential_type=CredentialModel.CredentialTypeChoice.ISSUING_CA,
        managed_key=CryptoManagedKeyModel.objects.get(pk=ca_key.managed_key_ref.id),
    )
    ca = CaModel(
        unique_name=unique_name,
        credential=credential,
        ca_type=CaModel.CaTypeChoice.LOCAL_PKCS11,
        ca_role=CaModel.CaRole.MANAGEMENT,
    )
    ca.save()
    ca.chain_truststore = CaModel._create_chain_truststore(ca)  # noqa: SLF001
    ca.save(update_fields=['chain_truststore'])
    return ca


def _issuing_ca(unique_name: str) -> CaModel:
    ca_cert, ca_key = create_managed_root_ca(unique_name)
    return CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=ca_cert,
        private_key=ca_key,
        chain=[],
        unique_name=unique_name,
    )


def _remote_ra_ca(unique_name: str, truststore: TruststoreModel) -> CaModel:
    config = NoOnboardingConfigModel(
        pki_protocols=NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD,
        est_password='secret',
        trust_store=truststore,
    )
    config.save()
    ca = CaModel(
        unique_name=unique_name,
        ca_type=CaModel.CaTypeChoice.REMOTE_EST_RA,
        ca_role=CaModel.CaRole.MANAGEMENT,
        remote_host='ca.example',
        remote_port=8443,
        remote_path='/.well-known/est/simpleenroll',
        est_username='user',
        no_onboarding_config=config,
    )
    ca.save()
    ca.certificate = truststore.truststoreordermodel_set.order_by('order').first().certificate
    ca.chain_truststore = truststore
    ca.save(update_fields=['certificate', 'chain_truststore'])
    return ca


def _truststore(name: str) -> TruststoreModel:
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    issuer_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'External CA')])
    now = dt.datetime.now(dt.UTC)
    issuer_cert = (
        x509.CertificateBuilder()
        .subject_name(issuer_name)
        .issuer_name(issuer_name)
        .public_key(issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )
    return TruststoreAddForm.save_trust_store(name, TruststoreModel.IntendedUsage.TLS, [issuer_cert])


CONTENT = {
    'common_name': 'server.example',
    'organization_name': 'Example',
    'country_name': 'DE',
    'dns_names': 'server.example',
    'days': 10,
}

EST_REQUEST = {
    'key_type': 'ECC-SECP256R1',
    'remote_host': 'ca.example',
    'remote_port': 8443,
    'remote_path': '/.well-known/est/simpleenroll',
    'est_username': 'user',
    'est_password': 'secret',
}


def test_local_ca_flow_issues_tls_credential() -> None:
    """CA select -> content -> request issues a TLS credential signed by the management CA."""
    ca = _local_ca('Test Root CA')
    client = Client()

    response = client.request('tls-local-key', method='post', data={'issuing_ca': ca.pk})
    assert response.status_code == 302
    assert resolve(response.url).view_name == 'management:tls-local-content'
    pk = resolve(response.url).kwargs['pk']

    response = client.request('tls-local-content', pk=pk)
    response.render()
    assert 'Define Certificate Content' in response.content.decode()

    response = client.request('tls-local-content', pk=pk, method='post', data=CONTENT)
    assert response.status_code == 302
    assert resolve(response.url).view_name == 'management:tls-local-request'

    response = client.request('tls-local-request', pk=pk, method='post')
    assert response.status_code == 302

    credential = CredentialModel.objects.get(pk=pk)
    assert credential.certificate is not None
    assert credential.get_certificate().issuer == ca.get_certificate().subject


def test_ca_selection_lists_only_management_cas() -> None:
    """Endpoint issuing CAs are not selectable for TLS server certificates."""
    management_ca = _local_ca('TLS Management CA')
    _issuing_ca('TLS Endpoint CA')

    form = TlsLocalCaSelectForm()

    assert list(form.fields['issuing_ca'].queryset) == [management_ca]
    assert 'key_type' not in form.fields


def test_key_type_is_bound_to_an_mldsa_management_ca() -> None:
    """ML-DSA management CAs get a matching ML-DSA TLS key type."""
    ca = Mock()
    ca.public_key_info = PublicKeyInfo(public_key_algorithm_oid=PublicKeyAlgorithmOid.ML_DSA_65)

    assert key_type_for_management_ca(ca) == 'MLDSA-65'


def test_remote_management_ca_requests_certificate_from_external_pki() -> None:
    """An RA-type management CA forwards the TLS request instead of signing locally."""
    truststore = _truststore('ra-est-tls')
    ca = _remote_ra_ca('External TLS Management CA', truststore)
    client = Client()

    response = client.request('tls-local-key', method='post', data={'issuing_ca': ca.pk})
    pk = resolve(response.url).kwargs['pk']
    client.request('tls-local-content', pk=pk, method='post', data=CONTENT)

    with patch('management.views.tls_issuance.issue_tls_server_remote') as remote_issue:
        response = client.request('tls-local-request', pk=pk, method='post')

    assert response.status_code == 302
    remote_issue.assert_called_once()
    assert remote_issue.call_args.args[3] == ca


def test_est_flow_enrolls_via_service() -> None:
    """Request EST -> trust store -> content -> request drives the EST enrollment service once."""
    truststore = _truststore('est-tls')
    client = Client()

    response = client.request('tls-request-est', method='post', data=EST_REQUEST)
    assert response.status_code == 302
    pk = resolve(response.url).kwargs['pk']
    assert resolve(response.url).view_name == 'management:tls-truststore-association'

    response = client.request('tls-truststore-association', pk=pk, method='post', data={'trust_store': truststore.pk})
    assert response.status_code == 302
    assert resolve(response.url).view_name == 'management:tls-define-cert-content-est'

    response = client.request('tls-define-cert-content-est', pk=pk, method='post', data=CONTENT)
    assert response.status_code == 302
    assert resolve(response.url).view_name == 'management:tls-request-cert-est'

    with (
        patch('pki.views.est_request.enroll_est') as enroll,
        patch('management.views.tls_issuance.finalize_tls_server_enrollment'),
    ):
        enroll.return_value = (Mock(), [])
        response = client.request('tls-request-cert-est', pk=pk, method='post')
        assert response.status_code == 302
        enroll.assert_called_once()
    assert 'tls_issuance_%d' % pk not in client.session


def test_est_request_page_renders_without_content() -> None:
    """The review page renders the connection details and a missing-content warning."""
    truststore = _truststore('est-tls-2')
    client = Client()

    response = client.request('tls-request-est', method='post', data=EST_REQUEST)
    pk = resolve(response.url).kwargs['pk']
    client.request('tls-truststore-association', pk=pk, method='post', data={'trust_store': truststore.pk})

    response = client.request('tls-request-cert-est', pk=pk)
    response.render()
    content = response.content.decode()
    assert 'ca.example' in content
    assert 'No certificate content has been defined yet' in content


def test_method_select_lists_new_methods() -> None:
    """The add-method page exposes CSR and management CA entry points, not legacy enrollment."""
    client = Client()
    response = client.request('tls-add-method_select')
    response.render()
    content = response.content.decode()
    assert reverse('management:tls-external-csr-key') in content
    assert reverse('management:tls-local-key') in content
    assert reverse('management:tls-request-est') not in content
    assert reverse('management:tls-request-cmp') not in content
    assert reverse('management:tls-generate') not in content


def test_request_est_page_renders_help_texts() -> None:
    """The request-est form renders the same field help texts as the Issuing CA form."""
    client = Client()
    response = client.request('tls-request-est')
    response.render()
    content = response.content.decode()
    assert 'hostname or IP address of the remote PKI' in content
    assert 'port number of the remote PKI' in content
    assert 'Username for EST authentication' in content


def test_truststore_association_offers_import() -> None:
    """The trust store association page offers an import modal for a new trust store."""
    client = Client()
    response = client.request('tls-request-est', method='post', data=EST_REQUEST)
    pk = resolve(response.url).kwargs['pk']

    response = client.request('tls-truststore-association', pk=pk)
    response.render()
    content = response.content.decode()
    assert 'Import new Trust Store' in content
    assert 'truststoreImportModal' in content
