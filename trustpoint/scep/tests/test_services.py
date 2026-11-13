# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regressions for serving credential expiry and CA replacement."""

import datetime as dt
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from crypto.application.private_keys import generate_managed_signing_private_key
from crypto.domain.specs import RsaKeySpec
from django.test import Client
from pki.models import CaModel
from pki.util.x509 import CertificateGenerator

from scep import services
from scep.protocol.oids import PkiStatus
from scep.tests import support
from scep.tests.conftest import ScepEnv

pytestmark = pytest.mark.django_db


def _replace_ca(env: ScepEnv, *, days: int = 3650, same_key: bool = False, cn: str = 'SCEP Test Root') -> None:
    unique = f'replacement-{uuid.uuid4().hex}'
    key = (
        env.domain.issuing_ca.get_credential().get_private_key()
        if same_key
        else generate_managed_signing_private_key(alias=unique, key_spec=RsaKeySpec(key_size=2048))
    )
    cert, key = CertificateGenerator.create_root_ca(cn, validity_days=days, private_key=key)
    env.domain.issuing_ca = CertificateGenerator.save_issuing_ca(cert, [], key, unique_name=unique)
    env.domain.save(update_fields=['issuing_ca'])


def test_ca_near_expiry_keeps_server_key_and_allows_enrollment(client: Client, rsa_env: ScepEnv) -> None:
    _replace_ca(rsa_env, days=20)
    credential = services.ensure_server_credential(rsa_env.domain)
    assert services.ensure_server_credential(rsa_env.domain).pk == credential.pk
    key = support.make_key('rsa')
    body, _ = support.build_request(
        signer_key=key,
        signer_cert=support.make_self_signed(key, 'device'),
        server_cert=credential.get_certificate(),
        csr=support.make_csr(key, 'device', rsa_env.secret),
    )
    response = client.post(rsa_env.url, body, content_type='application/x-pki-message', secure=True)
    assert support.parse_cert_rep(response.content).status == PkiStatus.SUCCESS
    assert services.ensure_server_credential(rsa_env.domain).pk == credential.pk


@pytest.mark.parametrize(('same_key', 'cn'), [(False, 'SCEP Test Root'), (False, 'New CA'), (True, 'SCEP Test Root')])
def test_ca_replacement_refreshes_server_certificate_and_chain(rsa_env: ScepEnv, same_key: bool, cn: str) -> None:
    old = services.ensure_server_credential(rsa_env.domain)
    _replace_ca(rsa_env, same_key=same_key, cn=cn)
    new = services.ensure_server_credential(rsa_env.domain)
    issuer = rsa_env.domain.issuing_ca.get_credential().get_certificate()
    assert new.pk != old.pk
    new.get_certificate().verify_directly_issued_by(issuer)
    assert new.get_certificate_chain()[0] == issuer
    assert services.ensure_server_credential(rsa_env.domain).pk == new.pk


def test_expiring_server_certificate_renews_once(rsa_env: ScepEnv) -> None:
    old = services.ensure_server_credential(rsa_env.domain)
    now = old.get_certificate().not_valid_after_utc - dt.timedelta(days=1)
    clock = SimpleNamespace(datetime=SimpleNamespace(now=lambda _tz: now), UTC=dt.UTC, timedelta=dt.timedelta)
    with patch('scep.services.dt', clock):
        new = services.ensure_server_credential(rsa_env.domain)
        assert new.pk != old.pk
        assert services.ensure_server_credential(rsa_env.domain).pk == new.pk


@pytest.mark.parametrize('offset', [dt.timedelta(days=-1), dt.timedelta(days=1)])
def test_invalid_ca_is_not_served_or_used_to_generate_keys(rsa_env: ScepEnv, offset: dt.timedelta) -> None:
    ca_cert = rsa_env.domain.issuing_ca.get_credential().get_certificate()
    now = ca_cert.not_valid_before_utc + offset if offset.days < 0 else ca_cert.not_valid_after_utc + offset
    clock = SimpleNamespace(datetime=SimpleNamespace(now=lambda _tz: now), UTC=dt.UTC, timedelta=dt.timedelta)
    with patch('scep.services.dt', clock), patch('scep.services.rsa.generate_private_key') as generate:
        assert services.get_serving_credential(rsa_env.domain) is None
        generate.assert_not_called()


def test_self_signed_ca_is_supported(rsa_env: ScepEnv) -> None:
    """Self-signed CAs remain available for SCEP enrollment."""
    ca = rsa_env.domain.issuing_ca
    ca.ca_type = CaModel.CaTypeChoice.SELF_SIGNED
    ca.save(update_fields=['ca_type'])
    assert services.get_local_issuing_ca(rsa_env.domain) == ca
    assert services.ensure_server_credential(rsa_env.domain) is not None
