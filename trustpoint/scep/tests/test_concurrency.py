# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""SCEP issuance races over independent PostgreSQL connections."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch

import pytest
from django.db import connection, connections
from django.test import Client
from pki.models import IssuedCredentialModel
from pki.models.certificate import CertificateModel

from scep.handler import ScepPkiOperationHandler
from scep.protocol.oids import PkiStatus
from scep.tests import support
from scep.tests.conftest import ScepEnv

pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.skipif(connection.vendor != 'postgresql', reason='Requires PostgreSQL row locks'),
]


@pytest.mark.parametrize('same_transaction', [True, False])
def test_concurrent_initial_requests_issue_only_once(rsa_env: ScepEnv, same_transaction: bool) -> None:
    key = support.make_key('rsa')
    csr = support.make_csr(key, 'race-device', rsa_env.secret)
    signer = support.make_self_signed(key, 'race-device')
    bodies = [
        support.build_request(
            signer_key=key, signer_cert=signer, server_cert=rsa_env.server_cert, csr=csr,
            transaction_id='race' if same_transaction else f'race-{index}',
        )[0]
        for index in range(2)
    ]
    ready = Barrier(2)
    original = ScepPkiOperationHandler._issue_certificate_transaction

    def issue_after_both_authenticated(self, *args, **kwargs):
        ready.wait(timeout=15)
        return original(self, *args, **kwargs)

    def enroll(body):
        try:
            response = Client().post(rsa_env.url, body, content_type='application/x-pki-message', secure=True)
            assert response.status_code == 200
            return support.parse_cert_rep(response.content)
        finally:
            connections.close_all()

    with (
        patch.object(ScepPkiOperationHandler, '_issue_certificate_transaction', issue_after_both_authenticated),
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        futures = [pool.submit(enroll, body) for body in bodies]
        replies = [future.result(timeout=30) for future in futures]
    assert all(rep.signature_valid for rep in replies)
    assert sum(rep.status == PkiStatus.SUCCESS for rep in replies) == (2 if same_transaction else 1)
    if same_transaction:
        certificates = [support.decrypt_cert_rep(rep, key=key)[0] for rep in replies]
        assert certificates[0] == certificates[1]
    assert IssuedCredentialModel.objects.filter(device=rsa_env.device).count() == 1
    assert CertificateModel.objects.filter(subject_public_bytes=csr.subject.public_bytes().hex().upper()).count() == 1
    assert len(rsa_env.config.scep_transactions) == 1
    assert rsa_env.config.scep_challenge_consumed_at is not None
