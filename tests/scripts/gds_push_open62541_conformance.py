# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT
# ruff: noqa: INP001, S105, S603, SLF001, T201

"""Real-stack GDS Push conformance test against the open62541 CI server.

The open62541 binary must be built with UA_ENABLE_DRIVER_GDS_RECEIVER=ON and
UA_ENABLE_ENCRYPTION=MBEDTLS (or OPENSSL). Point OPEN62541_CI_SERVER at the
resulting ``ci_server`` executable.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import os
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'trustpoint'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'trustpoint.settings')

import django  # noqa: E402

django.setup()

from management.models import SecurityConfig  # noqa: E402
from request.gds_push import GdsPushService  # noqa: E402


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _full_key_usage(*, ca: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=not ca,
        content_commitment=not ca,
        key_encipherment=not ca,
        data_encipherment=not ca,
        key_agreement=False,
        key_cert_sign=ca,
        crl_sign=ca,
        encipher_only=False,
        decipher_only=False,
    )


def _generate_pki(directory: Path) -> dict[str, Any]:
    now = dt.datetime.now(dt.UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = _name('open62541 Conformance CA')
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_full_key_usage(ca=True), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(_name('Trustpoint GDS Push Conformance Client'))
        .issuer_name(ca_subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_full_key_usage(ca=False), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier('urn:trustpoint:gds:conformance-client'),
                    x509.DNSName('localhost'),
                    x509.IPAddress(ipaddress.ip_address('127.0.0.1')),
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = _name('open62541 GDS Push Conformance Server')
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(server_subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_full_key_usage(ca=False), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier('urn:open62541.unconfigured.application'),
                    x509.DNSName('localhost'),
                    x509.IPAddress(ipaddress.ip_address('127.0.0.1')),
                ]
            ),
            critical=False,
        )
        .sign(server_key, hashes.SHA256())
    )

    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_subject)
        .last_update(now)
        .next_update(now + dt.timedelta(days=30))
        .sign(ca_key, hashes.SHA256())
    )

    ca_path = directory / 'ca.der'
    server_cert_path = directory / 'server.der'
    server_key_path = directory / 'server-key.der'
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.DER))
    server_cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.DER))
    server_key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return {
        'ca_cert': ca_cert,
        'ca_path': ca_path,
        'server_cert': server_cert,
        'server_key': server_key,
        'server_cert_path': server_cert_path,
        'server_key_path': server_key_path,
        'client_cert': client_cert,
        'client_key': client_key,
        'crl_pem': crl.public_bytes(serialization.Encoding.PEM).decode(),
    }


class _Serializer:
    def __init__(self, certificate: x509.Certificate) -> None:
        self._certificate = certificate

    def as_crypto(self) -> x509.Certificate:
        return self._certificate


class _CertificateModel:
    def __init__(self, certificate: x509.Certificate) -> None:
        self._certificate = certificate

    def get_certificate_serializer(self) -> _Serializer:
        return _Serializer(self._certificate)


class _TruststoreOrderSet:
    def __init__(self, certificate_model: _CertificateModel) -> None:
        self._certificate_model = certificate_model

    def get(self, *, order: int) -> Any:
        if order != 0:
            raise _CertificateModelError
        return type('Order', (), {'certificate': self._certificate_model})()


class _CertificateModelError(Exception):
    pass


class _Truststore:
    unique_name = 'open62541 conformance server certificate'

    def __init__(self, certificate: x509.Certificate) -> None:
        self.truststoreordermodel_set = _TruststoreOrderSet(_CertificateModel(certificate))


class _CA:
    unique_name = 'open62541 Conformance CA'

    def __init__(self, certificate: x509.Certificate, crl_pem: str) -> None:
        self.ca_certificate_model = _CertificateModel(certificate)
        self.crl_pem = crl_pem

    def get_ca_chain_from_truststore(self) -> list[_CA]:
        return [self]


class _Domain:
    def __init__(self, ca: _CA) -> None:
        self.issuing_ca = ca


class _Credential:
    def __init__(self, certificate: x509.Certificate, private_key: Any) -> None:
        self.certificate = _CertificateModel(certificate)
        self._private_key = private_key

    def get_private_key(self) -> Any:
        return self._private_key


class _IssuedCredential:
    def __init__(self, credential: _Credential) -> None:
        self.credential = credential

    def is_valid_domain_credential(self) -> tuple[bool, str]:
        return True, 'Valid domain credential.'


class _ConfigManager:
    def filter(self, **_kwargs: Any) -> _ConfigManager:
        return self

    def update(self, **_kwargs: Any) -> int:
        return 1


class _Config:
    objects = _ConfigManager()
    pk = 1

    def __init__(self, port: int) -> None:
        self.opc_server_url = f'opc.tcp://127.0.0.1:{port}'
        self.opc_server_port = port
        self.opc_user = 'peter'
        self.opc_password = 'peter123'
        self.opc_trust_store = None
        self.opc_gds_push_require_crls = True
        self.opc_gds_push_max_trustlist_entries = 0
        self.opc_gds_push_max_trustlist_element_size = 0
        self.opc_gds_push_regenerate_server_key = False
        self.opc_gds_push_server_validation = 'pinned'
        self.opc_gds_push_trustlist_mode = 'managed'
        self.opc_gds_push_managed_trustlist_state: dict[str, Any] = {}
        self.opc_gds_push_additional_trust_store = None
        self.opc_gds_push_certificate_inventory: dict[str, Any] = {}


class _Device:
    common_name = 'open62541-conformance-device'
    ip_address = '127.0.0.1'

    def __init__(self, port: int, domain: _Domain) -> None:
        self.rfc_4122_uuid = uuid.uuid4()
        self.domain = domain
        self.opc_ua_gds_push_config = _Config(port)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return int(sock.getsockname()[1])


def _wait_for_port(port: int, process: subprocess.Popen[str], timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            msg = f'open62541 ci_server exited with status {process.returncode}'
            raise RuntimeError(msg)
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    msg = f'open62541 ci_server did not listen on 127.0.0.1:{port} within {timeout} seconds'
    raise TimeoutError(msg)


def main() -> int:  # noqa: PLR0911, PLR0915
    """Run the conformance test and return a process exit code."""
    binary = os.environ.get('OPEN62541_CI_SERVER')
    if not binary:
        print('OPEN62541_CI_SERVER must point to the open62541 ci_server binary', file=sys.stderr)
        return 2
    if not Path(binary).is_file():
        print(f'open62541 ci_server not found: {binary}', file=sys.stderr)
        return 2

    log_dir = Path(os.environ.get('OPEN62541_LOG_DIR', 'reports/open62541'))
    log_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix='trustpoint-open62541-') as temp_dir:
        pki = _generate_pki(Path(temp_dir))
        port = _free_port()
        log_path = log_dir / 'ci_server.log'
        raw_log_path = Path(temp_dir) / 'ci_server.raw.log'
        with raw_log_path.open('w', encoding='utf-8') as log_file:
            server = subprocess.Popen(
                [
                    binary,
                    str(port),
                    str(pki['server_cert_path']),
                    str(pki['server_key_path']),
                    str(pki['ca_path']),
                ],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
                env={**os.environ, 'UA_LOG_LEVEL': 'ERROR'},
            )
            try:
                _wait_for_port(port, server)
                ca = _CA(pki['ca_cert'], pki['crl_pem'])
                device = _Device(port, _Domain(ca))
                service: Any = GdsPushService(cast('Any', device), insecure=True)

                async def no_active_rollover() -> None:
                    return None

                service._get_active_rollover = no_active_rollover
                service.domain_credential = _IssuedCredential(_Credential(pki['client_cert'], pki['client_key']))
                service.server_truststore = _Truststore(pki['server_cert'])
                service._security_config = SecurityConfig(
                    rsa_minimum_key_size=2048,
                    not_permitted_ecc_curve_oids=[],
                    not_permitted_mldsa_variant_oids=[],
                    not_permitted_signature_algorithm_oids=[],
                    permitted_opc_ua_security_policies=[
                        'Aes256Sha256RsaPss',
                        'Aes128Sha256RsaOaep',
                        'Basic256Sha256',
                    ],
                )

                success, message = asyncio.run(service.update_trustlist())
                print(f'TrustList update: {message}')
                if not success or 'trust lists verified' not in message:
                    print(raw_log_path.read_text(encoding='utf-8', errors='replace'), file=sys.stderr)
                    return 1

                success, message, certificate = asyncio.run(service.reconcile())
                print(f'Idempotent reconciliation: {message}')
                if not success or 'No certificate or trust list update required' not in message:
                    print(raw_log_path.read_text(encoding='utf-8', errors='replace'), file=sys.stderr)
                    return 1
                if certificate is not None:
                    print('Reconciliation unexpectedly renewed a certificate', file=sys.stderr)
                    return 1

                # The ci_server example emits expected AccessControl/RBAC setup warnings.
                # Keep only error/fatal lines in the uploaded artifact; real errors still fail.
                server_log = raw_log_path.read_text(encoding='utf-8', errors='replace')
                error_lines = [
                    line for line in server_log.splitlines() if 'error/' in line.lower() or 'fatal/' in line.lower()
                ]
                if error_lines:
                    log_path.write_text(server_log, encoding='utf-8')
                    print('\n'.join(error_lines), file=sys.stderr)
                    print('open62541 logged an error during the conformance test', file=sys.stderr)
                    return 1
                log_path.write_text(
                    'No open62541 error-level messages.\n',
                    encoding='utf-8',
                )
            finally:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=10)

    print('open62541 GDS Push conformance test passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
