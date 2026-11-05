# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Real GDS Push workflow over encrypted TCP against the standalone test server.

Run with RUN_GDS_INTEGRATION=1; all certificates and server state are disposable.
"""

import asyncio
import json
import os
import runpy
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import timedelta
from pathlib import Path

import pytest
from asyncua import ua
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.utils import timezone

from devices.models import DeviceModel, OpcUaGdsPushConfig
from devices.tasks import perform_gds_push_domain_credential_renewal, perform_gds_push_update
from onboarding.models import OnboardingConfigModel, OnboardingPkiProtocol, OnboardingProtocol
from pki.models import CertificateModel, IssuedCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.certificate import RevokedCertificateModel
from pki.models.domain import DomainAllowedCertificateProfileModel
from pki.models.truststore import TruststoreModel, TruststoreOrderModel
from request.authorization.manual import ManualAuthorization
from request.gds_push.gds_push_service import GdsPushService
from request.operation_processor import CredentialIssueProcessor
from request.request_context import ManualCredentialRequestContext, ManualIssuanceMethod

pytestmark = [
    pytest.mark.integration,
    pytest.mark.django_db(transaction=True),
    pytest.mark.skipif(
        os.getenv('RUN_GDS_INTEGRATION') != '1', reason='Set RUN_GDS_INTEGRATION=1 to run real OPC UA networking'
    ),
]
SCRIPT = Path(__file__).resolve().parents[2] / 'gds_push' / 'asyncua-gds-push-test' / 'server.py'
PROFILES = Path(__file__).resolve().parents[3] / 'pki' / 'default_certificate_profiles'


class ServerProcess:
    """Start, restart, and reliably clean up the standalone OPC UA server."""

    def __init__(self, state, endpoint, credentials):
        self.state = state
        self.endpoint = endpoint
        self.log_path = state.base / 'server.log'
        self.credentials = credentials
        self.process = None
        self.log_handle = None
        self.app_uri = None

    def start(self):
        env = {
            **os.environ,
            'GDS_DATA_DIR': str(self.state.base),
            'GDS_ENDPOINT': self.endpoint,
            'GDS_HOSTNAME': 'localhost',
            'GDS_APPLICATION_URI': self.app_uri,
            'GDS_ADMIN_USERNAME': self.credentials[0],
            'GDS_ADMIN_PASSWORD': self.credentials[1],
            'PYTHONUNBUFFERED': '1',
        }
        self.log_handle = self.log_path.open('a')
        self.process = subprocess.Popen(
            [sys.executable, str(SCRIPT)],
            env=env,
            stdout=self.log_handle,
            stderr=subprocess.STDOUT,
        )
        port = int(self.endpoint.rsplit(':', 1)[1])
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            assert self.process.poll() is None, self.log_path.read_text()
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.1)
        pytest.fail(f'Server did not become ready: {self.log_path.read_text()}')

    def stop(self):
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            self.process = None
        if self.log_handle is not None:
            self.log_handle.close()
            self.log_handle = None

    def restart(self):
        self.stop()
        self.start()


@pytest.fixture
def workflow(domain_instance, tmp_path, unused_tcp_port, request):
    domain = domain_instance['domain']
    ca = domain.issuing_ca
    ca.issue_crl()
    for name, credential_type in (
        ('opc_ua_domain_credential', CertificateProfileModel.ProfileCredentialType.DOMAIN),
        ('opc_ua', CertificateProfileModel.ProfileCredentialType.APPLICATION),
    ):
        definition = json.loads((PROFILES / f'{name}.json').read_text())
        definition['validity'] = {'days': 30}
        profile, _ = CertificateProfileModel.objects.update_or_create(
            unique_name=name,
            defaults={'profile_json': definition, 'credential_type': credential_type},
        )
        DomainAllowedCertificateProfileModel.objects.get_or_create(domain=domain, certificate_profile=profile)
        if credential_type == CertificateProfileModel.ProfileCredentialType.DOMAIN:
            domain.domain_credential_profile = profile
            domain.save()
    onboarding = OnboardingConfigModel(onboarding_protocol=OnboardingProtocol.OPC_GDS_PUSH)
    onboarding.set_pki_protocols([OnboardingPkiProtocol.OPC_GDS_PUSH])
    onboarding.save()
    device = DeviceModel.objects.create(
        common_name='gds-workflow',
        domain=domain,
        onboarding_config=onboarding,
        device_type=DeviceModel.DeviceType.OPC_UA_GDS_PUSH,
        ip_address='127.0.0.1',
    )
    app_uri = f'urn:trustpoint:opcua:{device.rfc_4122_uuid}'
    context = ManualCredentialRequestContext(
        device=device,
        domain=domain,
        cert_profile_str='opc_ua_domain_credential',
        manual_issuance_method=ManualIssuanceMethod.TRUSTPOINT_GENERATED,
        cert_requested=x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, 'GDS integration client'),
                ]
            )
        )
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(app_uri)]), critical=False),
    )
    ManualAuthorization().authorize(context)
    CredentialIssueProcessor().process_operation(context)
    credential = context.issued_credential
    assert credential is not None
    module = runpy.run_path(str(SCRIPT))
    # First boot uses the same application URI as the profile-issued replacement.
    module['PushState'].setup.__globals__['APP_URI'] = app_uri
    module['PushState'].setup.__globals__['HOST'] = 'localhost'
    state = module['PushState'](tmp_path / 'pki-state')
    asyncio.run(state.setup())
    for index, authority in enumerate(ca.get_ca_chain_from_truststore()):
        (state.trust / f'bootstrap-{index}.der').write_bytes(
            authority.ca_certificate_model.get_certificate_serializer().as_der()
        )
    (state.admin).write_bytes(credential.credential.get_certificate().public_bytes(serialization.Encoding.DER))
    truststore = TruststoreModel.objects.create(
        unique_name='gds-server',
        intended_usage=TruststoreModel.IntendedUsage.OPC_UA_GDS_PUSH,
    )
    TruststoreOrderModel.objects.create(
        trust_store=truststore,
        order=0,
        certificate=CertificateModel.save_certificate(x509.load_der_x509_certificate(state.cert.read_bytes())),
    )
    username, password = ('admin', 'integration-password') if request.param == 'password' else ('', '')
    config = device.opc_ua_gds_push_config
    config.opc_server_port = unused_tcp_port
    config.opc_user, config.opc_password = username, password
    config.opc_trust_store = truststore
    config.save()
    server = ServerProcess(state, f'opc.tcp://127.0.0.1:{unused_tcp_port}', (username, password))
    server.app_uri = app_uri
    try:
        server.start()
        yield device, credential, server
    finally:
        server.stop()
        artifact_dir = os.getenv('GDS_TEST_ARTIFACT_DIR')
        if artifact_dir and server.log_path.exists():
            destination = Path(artifact_dir)
            destination.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(server.log_path, destination / f'{request.param}-server.log')


async def connect(service):
    client = await service._create_secure_client()
    async with client:
        return await client.nodes.server_state.read_value()


def assert_trustlist_installed(device, server):
    ca = device.domain.issuing_ca
    expected = {
        authority.ca_certificate_model.get_certificate_serializer().as_der()
        for authority in ca.get_ca_chain_from_truststore()
    }
    assert {path.read_bytes() for path in server.state.trust.glob('*.der')} == expected
    assert {path.read_bytes() for path in server.state.issuer_certs.glob('*.der')} == expected
    installed_crls = [x509.load_der_x509_crl(path.read_bytes()) for path in server.state.trusted_crls.glob('*.der')]
    assert installed_crls
    return installed_crls


@pytest.mark.parametrize('workflow', ['password', 'certificate'], indirect=True)
def test_gds_push_end_to_end(workflow):
    device, previous, server = workflow
    success, message, info = asyncio.run(GdsPushService(device, insecure=True).discover_server())
    assert success, message
    assert info['endpoints'] and all(endpoint['has_server_cert'] for endpoint in info['endpoints'])
    asyncio.run(connect(GdsPushService(device)))
    success, message = asyncio.run(GdsPushService(device).update_trustlist())
    assert success, message
    assert_trustlist_installed(device, server)

    initial_server_cert = server.state.cert.read_bytes()
    OpcUaGdsPushConfig.objects.filter(device=device).update(opc_gds_push_enable_periodic_update=True)
    perform_gds_push_update(device.pk)
    device.refresh_from_db()
    issued = server.state.cert.read_bytes()
    assert issued != initial_server_cert, 'Periodic server renewal did not replace the certificate; inspect the logs'
    assert device.opc_ua_gds_push_config.opc_gds_push_last_update_scheduled_at > timezone.now()
    new_server_cert = x509.load_der_x509_certificate(issued)
    server_key = serialization.load_pem_private_key(server.state.key.read_bytes(), password=None)
    spki = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert server_key.public_key().public_bytes(*spki) == new_server_cert.public_key().public_bytes(*spki)
    assert (server.state.backup / 'previous-server.der').read_bytes() == initial_server_cert
    server.restart()
    device.refresh_from_db()
    discovered = asyncio.run(
        GdsPushService(device, insecure=True)._create_insecure_client().connect_and_get_server_endpoints()
    )
    assert discovered[0].ServerCertificate == issued
    asyncio.run(connect(GdsPushService(device)))

    # Exercise the actual scheduled task without waiting for an hourly interval.
    OpcUaGdsPushConfig.objects.filter(device=device).update(
        opc_gds_push_enable_domain_credential_renewal=True,
        opc_gds_push_domain_credential_next_renewal_at=timezone.now() - timedelta(seconds=1),
    )
    perform_gds_push_domain_credential_renewal(device.pk)
    device.refresh_from_db()
    replacement = IssuedCredentialModel.objects.filter(
        device=device,
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
    ).latest('created_at')
    assert replacement.pk != previous.pk
    assert replacement.is_valid_domain_credential()[0]
    old_client = previous.credential.get_certificate()
    new_client = replacement.credential.get_certificate()
    assert new_client.subject == old_client.subject
    assert new_client.extensions.get_extension_for_class(x509.SubjectAlternativeName) == (
        old_client.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    )
    assert new_client.public_key().public_bytes(*spki) != old_client.public_key().public_bytes(*spki)
    assert (
        RevokedCertificateModel.objects.get(certificate=previous.credential.certificate).revocation_reason
        == 'superseded'
    )
    assert device.opc_ua_gds_push_config.opc_gds_push_domain_credential_next_renewal_at > timezone.now()
    if not device.opc_ua_gds_push_config.opc_user:
        # Exact certificate authorization requires an explicit out-of-band allowlist update.
        with pytest.raises(ua.uaerrors.BadUserAccessDenied):
            asyncio.run(connect(GdsPushService(device)))
        server.state.admin.write_bytes(
            replacement.credential.get_certificate().public_bytes(serialization.Encoding.DER)
        )
        server.restart()
    asyncio.run(connect(GdsPushService(device)))
    device.domain.issuing_ca.issue_crl()
    success, message = asyncio.run(GdsPushService(device).update_trustlist())
    assert success, message
    crls = assert_trustlist_installed(device, server)
    assert previous.credential.get_certificate().serial_number in {entry.serial_number for crl in crls for entry in crl}
    asyncio.run(connect(GdsPushService(device)))

    # The same live server must reject the old identity after CRL reload.
    service = GdsPushService(device)
    cert = previous.credential.get_certificate()
    old_key_pem = previous.credential.get_private_key().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    async def old_identity():
        # Prepare the revoked identity explicitly so its rejection is tested on the server.
        with tempfile.TemporaryDirectory() as temporary:
            cert_path = Path(temporary) / 'client.der'
            key_path = Path(temporary) / 'client.pem'
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
            key_path.write_bytes(old_key_pem)
            from asyncua import Client, ua
            from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256

            client = Client(service.server_url)
            client.application_uri = service._extract_application_uri(cert)
            await client.set_security(
                SecurityPolicyBasic256Sha256,
                cert_path,
                key_path,
                server_certificate=server.state.cert,
                mode=ua.MessageSecurityMode.SignAndEncrypt,
            )
            if device.opc_ua_gds_push_config.opc_user:
                client.set_user(device.opc_ua_gds_push_config.opc_user)
                client.set_password(device.opc_ua_gds_push_config.opc_password)
            async with client:
                pytest.fail('Server accepted the revoked credential')

    with pytest.raises(ua.uaerrors.BadCertificateRevoked):
        asyncio.run(old_identity())
