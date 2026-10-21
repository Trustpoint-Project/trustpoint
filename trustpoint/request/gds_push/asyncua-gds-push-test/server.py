# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

# ruff: noqa: INP001  # Standalone development script, not an importable package.

"""Development-only OPC UA GDS Push target for Trustpoint.

Implements a subset of OPC UA Part 12 management methods using asyncua.
Run ONLY on a loopback/isolated test network; not a production OPC UA server.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import socket
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from asyncua import Server, ua  # type: ignore[import-untyped]
from asyncua.common.utils import Buffer  # type: ignore[import-untyped]
from asyncua.crypto.cert_gen import setup_self_signed_certificate  # type: ignore[import-untyped]
from asyncua.crypto.permission_rules import User, UserRole  # type: ignore[import-untyped]
from asyncua.crypto.truststore import TrustStore  # type: ignore[import-untyped]
from asyncua.crypto.validator import CertificateValidator, CertificateValidatorOptions  # type: ignore[import-untyped]
from asyncua.server.user_managers import CertificateUserManager  # type: ignore[import-untyped]
from asyncua.ua.ua_binary import struct_from_binary  # type: ignore[import-untyped]
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

LOG = logging.getLogger('gds_push_test')
BASE = Path(os.environ.get('GDS_DATA_DIR', './state')).resolve()
URL = os.environ.get('GDS_ENDPOINT', 'opc.tcp://127.0.0.1:4840/freeopcua/server/')
HOST = os.environ.get('GDS_HOSTNAME', socket.gethostname())
APP_URI = os.environ.get('GDS_APPLICATION_URI', f'urn:{HOST}:trustpoint-gds-push-test')
USERNAME = os.environ.get('GDS_ADMIN_USERNAME', 'admin')
PASSWORD = os.environ.get('GDS_ADMIN_PASSWORD', 'password')


def value(arg: Any) -> Any:
    """Unwrap an OPC UA Variant while accepting raw callback arguments."""
    return arg.Value if isinstance(arg, ua.Variant) else arg


def result(value_: Any, typ: ua.VariantType) -> ua.Variant:
    """Wrap a method result with its OPC UA wire type."""
    return ua.Variant(value_, typ)


class PushUserManager:
    """Authorize an allowlisted certificate or optional administrator credentials."""

    def __init__(self, username: str = '', password: str = '') -> None:
        """Configure optional credentials and the certificate administrator allowlist."""
        if bool(username) != bool(password):
            message = 'Set both GDS_ADMIN_USERNAME and GDS_ADMIN_PASSWORD, or leave both unset.'
            raise ValueError(message)
        self.certificates = CertificateUserManager()
        self._username = username
        self._password = password

    def get_user(
        self,
        iserver: Any,
        username: str | None = None,
        password: str | None = None,
        certificate: bytes | None = None,
    ) -> User | None:
        """Reject invalid supplied credentials; otherwise authenticate the certificate."""
        if username is not None or password is not None:
            if not self._username or username is None or password is None:
                return None
            username_matches = hmac.compare_digest(username.encode(), self._username.encode())
            password_matches = hmac.compare_digest(password.encode(), self._password.encode())
            if username_matches and password_matches:
                return User(role=UserRole.Admin, name=self._username)
            return None
        return cast('User | None', self.certificates.get_user(iserver, certificate=certificate))


class PushState:
    """Manage the test server identity and staged GDS Push updates."""

    def __init__(self, base: Path) -> None:
        """Initialize the PKI paths and pending update state."""
        self.base = base
        self.application_group: ua.NodeId | None = None
        # UaExpert-style PKI layout, rooted at <GDS_DATA_DIR>/pki.
        self.pki = base / 'pki'
        self.cert = self.pki / 'own' / 'certs' / 'server.der'
        self.key = self.pki / 'own' / 'private' / 'server.pem'
        self.trust = self.pki / 'trusted' / 'certs'
        self.trusted_crls = self.pki / 'trusted' / 'crl'
        self.issuer_certs = self.pki / 'issuers' / 'certs'
        self.issuer_crls = self.pki / 'issuers' / 'crl'
        self.rejected = self.pki / 'rejected' / 'certs'
        # Deliberately separate admin identity authorization from CA trust.
        # Admin certificate is also placed in trusted/certs for peer validation.
        self.admin = self.pki / 'trusted' / 'admin-client.der'
        self.backup = self.pki / 'own' / 'backup'
        self.pending_key: PrivateKeyTypes | None = None
        self.pending_cert: bytes | None = None
        self.pending_issuers: list[bytes] = []
        self.writes: dict[int, bytearray] = {}
        self.next_handle = 1
        self.pending_trust: bytes | None = None
        self.trust_store: TrustStore | None = None

    async def setup(self) -> None:
        """Create the PKI directories and generate the first-boot identity."""
        for directory in (
            self.cert.parent,
            self.key.parent,
            self.trust,
            self.trusted_crls,
            self.issuer_certs,
            self.issuer_crls,
            self.rejected,
            self.backup,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        if not (self.cert.exists() and self.key.exists()):
            if self.cert.exists() or self.key.exists():
                message = 'Partial server identity found; restore both cert and key'
                raise RuntimeError(message)
            await setup_self_signed_certificate(
                self.key,
                self.cert,
                APP_URI,
                HOST,
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH],
                {'organizationName': 'Trustpoint GDS Push Test'},
            )
            LOG.warning('Generated FIRST-BOOT self-signed identity at %s', self.cert)

    def check_group(self, group: ua.NodeId) -> None:
        """Require the DefaultApplicationGroup instance discovered in the address space."""
        if self.application_group is None or group != self.application_group:
            raise ua.UaStatusCodeError(ua.StatusCodes.BadInvalidArgument)

    # OPC UA defines the positional arguments for this method callback.
    async def csr(
        self,
        _parent: ua.NodeId,
        group: ua.Variant,
        _cert_type: ua.Variant,
        subject: ua.Variant,
        regenerate: ua.Variant,
        _nonce: ua.Variant,
    ) -> list[ua.Variant]:
        """Create a signing request, optionally staging a fresh private key."""
        self.check_group(value(group))
        if not bool(value(regenerate)):
            LOG.info('CSR requested without key regeneration; using existing key')
            key = serialization.load_pem_private_key(self.key.read_bytes(), password=None)
        else:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        current = x509.load_der_x509_certificate(self.cert.read_bytes())
        subject_str = value(subject)
        if subject_str:
            LOG.warning('Subject override not currently implemented: %r', subject_str)
            raise ua.UaStatusCodeError(ua.StatusCodes.BadNotSupported)
        builder = x509.CertificateSigningRequestBuilder().subject_name(current.subject)
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(APP_URI), x509.DNSName(HOST)]), critical=False
        )
        if not isinstance(
            key,
            (
                rsa.RSAPrivateKey,
                dsa.DSAPrivateKey,
                ec.EllipticCurvePrivateKey,
                ed25519.Ed25519PrivateKey,
                ed448.Ed448PrivateKey,
            ),
        ):
            raise ua.UaStatusCodeError(ua.StatusCodes.BadNotSupported)
        csr = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
        self.pending_key = key if bool(value(regenerate)) else None
        return [result(csr, ua.VariantType.ByteString)]

    # OPC UA defines the positional arguments for this method callback.
    async def update_certificate(
        self,
        _parent: ua.NodeId,
        group: ua.Variant,
        _cert_type: ua.Variant,
        cert: ua.Variant,
        issuers: ua.Variant,
        key_format: ua.Variant,
        private_key: ua.Variant,
    ) -> list[ua.Variant]:
        """Stage a certificate after checking it matches the expected private key."""
        self.check_group(value(group))
        if value(key_format) or value(private_key):
            raise ua.UaStatusCodeError(ua.StatusCodes.BadNotSupported)
        incoming = x509.load_der_x509_certificate(bytes(value(cert)))
        expected_key = self.pending_key or serialization.load_pem_private_key(self.key.read_bytes(), password=None)
        if incoming.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) != expected_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ):
            raise ua.UaStatusCodeError(ua.StatusCodes.BadSecurityChecksFailed)
        self.pending_cert = incoming.public_bytes(serialization.Encoding.DER)
        self.pending_issuers = list(value(issuers) or [])
        LOG.info('Staged new certificate: %s', incoming.subject.rfc4514_string())
        return [result(value_=True, typ=ua.VariantType.Boolean)]

    async def open_trustlist(self, _parent: ua.NodeId, mode: ua.Variant) -> list[ua.Variant]:
        """Allocate a handle for a write-and-replace trust-list upload."""
        if int(value(mode)) != int(ua.OpenFileMode.Write | ua.OpenFileMode.EraseExisting):
            raise ua.UaStatusCodeError(ua.StatusCodes.BadNotSupported)
        handle = self.next_handle
        self.next_handle += 1
        self.writes[handle] = bytearray()
        return [result(handle, ua.VariantType.UInt32)]

    async def write_trustlist(self, _parent: ua.NodeId, handle: ua.Variant, data: ua.Variant) -> list[ua.Variant]:
        """Append binary data to an open trust-list upload."""
        h = int(value(handle))
        if h not in self.writes:
            raise ua.UaStatusCodeError(ua.StatusCodes.BadInvalidArgument)
        self.writes[h].extend(bytes(value(data)))
        return []

    async def close_update(self, _parent: ua.NodeId, handle: ua.Variant) -> list[ua.Variant]:
        """Close an upload and stage its opaque trust-list bytes."""
        h = int(value(handle))
        if h not in self.writes:
            raise ua.UaStatusCodeError(ua.StatusCodes.BadInvalidArgument)
        payload = bytes(self.writes.pop(h))
        self.decode_trustlist(payload)
        self.pending_trust = payload
        LOG.info('Staged OPC UA TrustListDataType (%d bytes)', len(payload))
        return [result(value_=True, typ=ua.VariantType.Boolean)]

    def decode_trustlist(self, payload: bytes) -> list[tuple[Path, list[bytes]]]:
        """Decode and validate every selected certificate/CRL list before changing disk state."""
        data = Buffer(payload)
        trustlist = struct_from_binary(ua.TrustListDataType, data)
        if len(data) or trustlist.SpecifiedLists & ~int(ua.TrustListMasks.All):
            raise ua.UaStatusCodeError(ua.StatusCodes.BadInvalidArgument)
        updates = []
        for mask, directory, entries in (
            (ua.TrustListMasks.TrustedCertificates, self.trust, trustlist.TrustedCertificates),
            (ua.TrustListMasks.TrustedCrls, self.trusted_crls, trustlist.TrustedCrls),
            (ua.TrustListMasks.IssuerCertificates, self.issuer_certs, trustlist.IssuerCertificates),
            (ua.TrustListMasks.IssuerCrls, self.issuer_crls, trustlist.IssuerCrls),
        ):
            if trustlist.SpecifiedLists & mask:
                for entry in entries or []:
                    if directory in (self.trust, self.issuer_certs):
                        x509.load_der_x509_certificate(entry)
                    else:
                        x509.load_der_x509_crl(entry)
                updates.append((directory, list(entries or [])))
        return updates

    async def install_trustlist(self, payload: bytes) -> None:
        """Replace selected PKI directories and reload validation, restoring them on failure."""
        updates = self.decode_trustlist(payload)
        swapped: list[tuple[Path, Path]] = []
        with tempfile.TemporaryDirectory(dir=self.pki) as temporary:
            staging = Path(temporary)
            try:
                for index, (directory, entries) in enumerate(updates):
                    replacement = staging / f'new-{index}'
                    replacement.mkdir()
                    for offset, entry in enumerate(entries):
                        (replacement / f'{offset}.der').write_bytes(entry)
                    backup = staging / f'old-{index}'
                    directory.rename(backup)
                    swapped.append((directory, backup))
                    replacement.rename(directory)
                if self.trust_store is not None:
                    await self.trust_store.load()
            except Exception:
                for directory, backup in reversed(swapped):
                    if directory.exists():
                        for installed_file in directory.iterdir():
                            installed_file.unlink()
                        directory.rmdir()
                    backup.rename(directory)
                if self.trust_store is not None:
                    await self.trust_store.load()
                raise
        LOG.info('Installed TrustList and reloaded certificate validation')

    async def apply_changes(self, _parent: ua.NodeId) -> list[ua.Variant]:
        """Persist staged updates and back up the previous server identity."""
        if self.pending_cert is not None:
            # Backup identity for debugging / manual recovery.
            if self.cert.exists():
                (self.backup / 'previous-server.der').write_bytes(self.cert.read_bytes())
            if self.key.exists():
                (self.backup / 'previous-server.pem').write_bytes(self.key.read_bytes())
            self.cert.write_bytes(self.pending_cert)
            if self.pending_key is not None:
                self.key.write_bytes(
                    self.pending_key.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                    )
                )
            self.pending_cert = None
            self.pending_key = None
            LOG.warning('New certificate persisted. Restart server to activate it; secure sessions may be interrupted.')
        if self.pending_trust is not None:
            await self.install_trustlist(self.pending_trust)
            (self.pki / 'trustlist-staged.bin').write_bytes(self.pending_trust)
            self.pending_trust = None
        return []


async def configure_push_methods(server: Server, state: PushState) -> None:
    """Expose the supported application group and attach its Push method callbacks."""
    cfg = await server.nodes.server.get_child('0:ServerConfiguration')
    groups = await cfg.get_child('0:CertificateGroups')
    default_group = await groups.get_child('0:DefaultApplicationGroup')
    state.application_group = default_group.nodeid
    # asyncua creates HTTPS and user-token groups without method implementations.
    # This test target only supports application certificates and their TrustList.
    for group in await groups.get_children():
        if group.nodeid != default_group.nodeid:
            await server.delete_nodes([group], recursive=True)
    LOG.info('Supported certificate group: %s', default_group.nodeid)
    callbacks = {
        'CreateSigningRequest': state.csr,
        'UpdateCertificate': state.update_certificate,
        'ApplyChanges': state.apply_changes,
    }
    for name, callback in callbacks.items():
        method = await cfg.get_child(f'0:{name}')
        server.link_method(method, callback)
    trustlist = await default_group.get_child('0:TrustList')
    for name, callback in {
        'Open': state.open_trustlist,
        'Write': state.write_trustlist,
        'CloseAndUpdate': state.close_update,
    }.items():
        method = await trustlist.get_child(f'0:{name}')
        server.link_method(method, callback)


async def main() -> None:
    """Configure and run the development OPC UA GDS Push server."""
    users = PushUserManager(
        username=USERNAME,
        password=PASSWORD,
    )
    state = PushState(BASE)
    await state.setup()
    if state.admin.exists():
        await users.certificates.add_admin(state.admin, name='trustpoint-gds-admin')
    else:
        LOG.warning(
            'No trusted/admin-client.der found. Certificate-based admin access is unavailable; '
            'configure an admin certificate or GDS_ADMIN_USERNAME and GDS_ADMIN_PASSWORD.'
        )
    server = Server(user_manager=users)
    await server.init()
    await server.set_application_uri(APP_URI)
    server.set_endpoint(URL)
    server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    await server.load_certificate(str(state.cert))
    await server.load_private_key(str(state.key))
    trust_store = TrustStore([state.trust], [state.trusted_crls, state.issuer_crls])
    state.trust_store = trust_store
    await trust_store.load()
    # No trust-on-first-use or optional validation: explicitly trusted peer cert required.
    server.set_certificate_validator(
        CertificateValidator(
            options=CertificateValidatorOptions.TRUSTED_VALIDATION | CertificateValidatorOptions.PEER_CLIENT,
            trust_store=trust_store,
        )
    )
    await configure_push_methods(server, state)
    LOG.warning('TEST SERVER ONLY. Certificate activation requires restart; not a production OPC UA implementation.')
    async with server:
        LOG.info('Serving %s', URL)
        await asyncio.Event().wait()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
