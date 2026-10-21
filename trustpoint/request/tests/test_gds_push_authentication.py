# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Authentication coverage for the GDS Push client and standalone test server."""

import runpy
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest
from asyncua.crypto.permission_rules import User, UserRole

from devices.forms import ClmDeviceModelOpcUaGdsPushOnboardingForm, OpcUaGdsPushCreateForm
from request.gds_push.gds_push_service import GdsPushService


@pytest.fixture(scope='module')
def user_manager_class():
    script = Path(__file__).resolve().parents[1] / 'gds_push' / 'asyncua-gds-push-test' / 'server.py'
    return runpy.run_path(str(script))['PushUserManager']


@pytest.mark.parametrize('username,password', [('', ''), ('admin', 'secret')])
def test_certificate_admin_remains_available(user_manager_class, username, password):
    manager = user_manager_class(username, password)
    admin = User(role=UserRole.Admin, name='certificate-admin')
    manager.certificates.get_user = Mock(return_value=admin)
    server = Mock()

    assert manager.get_user(server, certificate=b'approved-client') is admin
    manager.certificates.get_user.assert_called_once_with(server, certificate=b'approved-client')


def test_unregistered_certificate_is_rejected(user_manager_class):
    manager = user_manager_class()
    assert manager.get_user(Mock(), certificate=b'unknown') is None
    assert manager.get_user(Mock()) is None


@pytest.mark.parametrize('username,password', [('admin', ''), ('', 'secret')])
def test_incomplete_server_credentials_are_rejected(user_manager_class, username, password):
    with pytest.raises(ValueError, match='Set both GDS_ADMIN_USERNAME and GDS_ADMIN_PASSWORD'):
        user_manager_class(username, password)


@pytest.mark.parametrize('username,password', [('admin', 'secret'), ('äḋmin', 'pässword')])
def test_valid_password_grants_admin(user_manager_class, username, password):
    manager = user_manager_class(username, password)
    user = manager.get_user(Mock(), username=username, password=password)
    assert user.role == UserRole.Admin
    assert user.name == username


@pytest.mark.parametrize(
    'username,password',
    [('admin', 'wrong'), ('wrong', 'secret'), ('', ''), ('admin', None), (None, 'secret')],
)
def test_invalid_credentials_do_not_fall_back_to_certificate(user_manager_class, username, password):
    manager = user_manager_class('admin', 'secret')
    manager.certificates.get_user = Mock(return_value=User(role=UserRole.Admin))
    assert manager.get_user(Mock(), username, password, certificate=b'approved-client') is None
    manager.certificates.get_user.assert_not_called()


def test_password_authentication_is_disabled_by_default(user_manager_class):
    manager = user_manager_class()
    assert manager.get_user(Mock(), 'admin', 'secret') is None


@pytest.mark.parametrize('form_class', [OpcUaGdsPushCreateForm, ClmDeviceModelOpcUaGdsPushOnboardingForm])
def test_trustpoint_credentials_are_optional(form_class):
    assert not form_class.base_fields['opc_user'].required
    assert not form_class.base_fields['opc_password'].required
    assert form_class.base_fields['opc_user'].clean('') == ''
    assert form_class.base_fields['opc_password'].clean('') == ''


@pytest.mark.asyncio
@pytest.mark.parametrize('username,password', [('', ''), ('admin', 'secret')])
async def test_secure_client_with_optional_user_credentials(username, password):
    service = GdsPushService.__new__(GdsPushService)
    service.device = Mock(opc_ua_gds_push_config=Mock(opc_user=username, opc_password=password))
    service.server_url = 'opc.tcp://localhost:4840'
    client = Mock(set_security=AsyncMock())
    module = 'request.gds_push.gds_push_service'
    with (
        patch.object(service, '_get_client_credentials', AsyncMock(return_value=(Mock(), b'key'))),
        patch.object(service, '_get_server_certificate', AsyncMock(return_value=b'server-certificate')),
        patch.object(service, '_extract_application_uri', return_value='urn:test'),
        patch.object(service, '_build_client_certificate_chain', AsyncMock(return_value=b'client-certificate')),
        patch(f'{module}.tempfile.NamedTemporaryFile'),
        patch(f'{module}.Client', return_value=client),
    ):
        assert await service._create_secure_client() is client

    client.set_security.assert_awaited_once()
    if username:
        client.set_user.assert_called_once_with(username)
        client.set_password.assert_called_once_with(password)
    else:
        client.set_user.assert_not_called()
        client.set_password.assert_not_called()


@pytest.mark.asyncio
async def test_discovery_of_encrypted_server_without_a_session(tmp_path):
    """Discover a real server advertising only encrypted, authenticated endpoints."""
    from asyncua import Server, ua

    script = Path(__file__).resolve().parents[1] / 'gds_push' / 'asyncua-gds-push-test' / 'server.py'
    namespace = runpy.run_path(str(script))
    state = namespace['PushState'](tmp_path)
    await state.setup()
    users = namespace['PushUserManager']()
    server = Server(user_manager=users)
    await server.init()
    await server.set_application_uri(namespace['APP_URI'])
    server.set_server_name('Encrypted discovery target')
    server.set_endpoint('opc.tcp://127.0.0.1:0')
    server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    await server.load_certificate(state.cert)
    await server.load_private_key(state.key)
    users.get_user = Mock(side_effect=AssertionError('Discovery must not activate a session'))

    async with server:
        service = GdsPushService.__new__(GdsPushService)
        service.server_url = f'opc.tcp://127.0.0.1:{server.bserver.port}'
        success, message, info = await service.discover_server()

    assert success, message
    assert info['server_name'] == 'Encrypted discovery target'
    assert info['endpoints']
    assert all(endpoint['security_policy'].endswith('#Basic256Sha256') for endpoint in info['endpoints'])
    assert all(endpoint['has_server_cert'] for endpoint in info['endpoints'])
    users.get_user.assert_not_called()


@pytest.mark.asyncio
async def test_certificate_update_uses_discovered_group_and_persists_matching_key(tmp_path):
    """Exercise CSR, signing, certificate upload and ApplyChanges via UA method calls."""
    import datetime

    from asyncua import Server, ua
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    script = Path(__file__).resolve().parents[1] / 'gds_push' / 'asyncua-gds-push-test' / 'server.py'
    state = runpy.run_path(str(script))['PushState'](tmp_path)
    await state.setup()
    previous_cert = state.cert.read_bytes()
    previous_key = state.key.read_bytes()
    server = Server()
    await server.init()
    config = await server.nodes.server.get_child('0:ServerConfiguration')
    group = await config.get_child(['0:CertificateGroups', '0:DefaultApplicationGroup'])
    state.application_group = group.nodeid
    for name, callback in {
        'CreateSigningRequest': state.csr,
        'UpdateCertificate': state.update_certificate,
        'ApplyChanges': state.apply_changes,
    }.items():
        server.link_method(await config.get_child(f'0:{name}'), callback)

    # Reject the type NodeId formerly hardcoded in the server and unrelated groups.
    for invalid_group in (ua.NodeId(ua.ObjectIds.CertificateGroupType), ua.NodeId(999999)):
        with pytest.raises(ua.UaStatusCodeError) as exc:
            state.check_group(invalid_group)
        assert exc.value.code == ua.StatusCodes.BadInvalidArgument

    csr_der = await config.call_method(
        '0:CreateSigningRequest', group.nodeid, ua.NodeId(ua.ObjectIds.ApplicationCertificateType), None, True, None
    )
    csr = x509.load_der_x509_csr(csr_der)
    assert csr.is_signature_valid
    assert state.pending_key is not None
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.UTC)
    signed_cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Test issuing CA')]))
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(issuer_key, hashes.SHA256())
    ).public_bytes(serialization.Encoding.DER)
    apply_required = await config.call_method(
        '0:UpdateCertificate',
        group.nodeid,
        ua.NodeId(ua.ObjectIds.ApplicationCertificateType),
        signed_cert,
        ua.Variant([], ua.VariantType.ByteString),
        '',
        b'',
    )
    assert apply_required is True
    assert state.cert.read_bytes() == previous_cert
    assert state.key.read_bytes() == previous_key
    await config.call_method('0:ApplyChanges')

    assert state.cert.read_bytes() == signed_cert
    persisted_key = serialization.load_pem_private_key(state.key.read_bytes(), password=None)
    assert persisted_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) == csr.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert (state.backup / 'previous-server.der').read_bytes() == previous_cert
    assert (state.backup / 'previous-server.pem').read_bytes() == previous_key
    assert state.pending_key is None
    assert state.pending_cert is None


@pytest.mark.asyncio
async def test_repeated_trustlist_upload_only_discovers_implemented_groups(tmp_path):
    """Repeatedly upload identical data through each advertised TrustList."""
    from asyncua import Server, ua
    from asyncua.ua.ua_binary import struct_to_binary

    script = Path(__file__).resolve().parents[1] / 'gds_push' / 'asyncua-gds-push-test' / 'server.py'
    namespace = runpy.run_path(str(script))
    state = namespace['PushState'](tmp_path)
    await state.setup()
    server = Server()
    await server.init()
    await namespace['configure_push_methods'](server, state)
    service = GdsPushService.__new__(GdsPushService)
    nodes = await service._discover_trustlist_nodes(server)
    assert [node['group_name'] for node in nodes] == ['DefaultApplicationGroup']
    groups = await service._discover_certificate_groups(server)
    assert [group['node_id'] for group in groups] == [state.application_group]

    data = ua.TrustListDataType(
        SpecifiedLists=ua.TrustListMasks.All,
        TrustedCertificates=[state.cert.read_bytes()],
    )
    for _ in range(2):
        assert await service._update_single_trustlist(nodes[0]['trustlist_node'], data)
        assert (state.pki / 'trustlist-staged.bin').read_bytes() == struct_to_binary(data)
        assert state.writes == {}
        assert state.pending_trust is None


@pytest.mark.asyncio
async def test_trustlist_install_reloads_trust_and_preserves_unselected_lists(tmp_path):
    """Check live trust changes and that an issuer certificate never implies trust."""
    from asyncua import ua
    from asyncua.crypto.truststore import TrustStore
    from asyncua.ua.ua_binary import struct_to_binary
    from cryptography import x509

    script = Path(__file__).resolve().parents[1] / 'gds_push' / 'asyncua-gds-push-test' / 'server.py'
    namespace = runpy.run_path(str(script))
    state = namespace['PushState'](tmp_path / 'old')
    replacement = namespace['PushState'](tmp_path / 'new')
    await state.setup()
    await replacement.setup()
    old_der, new_der = state.cert.read_bytes(), replacement.cert.read_bytes()
    (state.trust / 'old.der').write_bytes(old_der)
    (state.issuer_certs / 'issuer.der').write_bytes(old_der)
    state.admin.write_bytes(old_der)
    state.trust_store = TrustStore([state.trust], [state.trusted_crls, state.issuer_crls])
    await state.trust_store.load()
    old_cert, new_cert = x509.load_der_x509_certificate(old_der), x509.load_der_x509_certificate(new_der)
    assert state.trust_store.is_trusted(old_cert)
    assert not state.trust_store.is_trusted(new_cert)
    await state.install_trustlist(
        struct_to_binary(
            ua.TrustListDataType(
                SpecifiedLists=ua.TrustListMasks.TrustedCertificates,
                TrustedCertificates=[new_der],
            )
        )
    )
    assert state.trust_store.is_trusted(new_cert)
    assert not state.trust_store.is_trusted(old_cert)
    assert (state.issuer_certs / 'issuer.der').read_bytes() == old_der
    assert state.admin.read_bytes() == old_der


@pytest.mark.asyncio
async def test_invalid_trustlist_and_failed_reload_preserve_previous_trust(tmp_path):
    """Reject malformed certificate data and roll back directory replacement on reload failure."""
    from asyncua import ua
    from asyncua.ua.ua_binary import struct_to_binary

    script = Path(__file__).resolve().parents[1] / 'gds_push' / 'asyncua-gds-push-test' / 'server.py'
    state = runpy.run_path(str(script))['PushState'](tmp_path)
    await state.setup()
    original = state.trust / 'original.der'
    original.write_bytes(state.cert.read_bytes())
    bad_data = struct_to_binary(
        ua.TrustListDataType(
            SpecifiedLists=ua.TrustListMasks.TrustedCertificates,
            TrustedCertificates=[b'not-a-certificate'],
        )
    )
    with pytest.raises(ValueError):
        await state.install_trustlist(bad_data)
    assert original.read_bytes() == state.cert.read_bytes()
    state.trust_store = Mock(load=AsyncMock(side_effect=[ValueError('reload failed'), None]))
    valid_data = struct_to_binary(
        ua.TrustListDataType(
            SpecifiedLists=ua.TrustListMasks.TrustedCertificates,
            TrustedCertificates=[],
        )
    )
    with pytest.raises(ValueError, match='reload failed'):
        await state.install_trustlist(valid_data)
    assert original.read_bytes() == state.cert.read_bytes()
    assert list(state.trust.iterdir()) == [original]
    assert state.trust_store.load.await_count == 2
