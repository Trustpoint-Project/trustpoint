#!/usr/bin/env python3
r"""Hardened Trustpoint endpoint agent for Linux hosts.

Trustpoint fills all ``{{ placeholder }}`` values in the rendered
``agent_setup.json`` profile before distributing it to the agent. The agent
therefore only needs the path to that rendered profile.

Flow
----
1. Read the rendered ``agent_setup.json`` profile.
2. Extract onboarding parameters, certificate request settings, and local paths.
3. Generate an RSA private key and PKCS#10 CSR using the Python cryptography API.
4. POST the CSR to Trustpoint using requests with HTTP Basic auth.
5. Save the issued certificate and chain atomically.
6. Enter the polling loop. Each poll uses the currently active domain credential
   for mTLS, executes renewal jobs, and acknowledges each job.

Key security/operational properties
-----------------------------------
* No shelling out to curl or openssl.
* No secrets are passed via process command-line arguments.
* No tempfile.mktemp usage.
* Private keys are written atomically with mode 0600.
* Certificate/key rotation is staged and committed atomically.
* Structured logging supports text or JSON output.
* systemd notification support is included when NOTIFY_SOCKET is present.
* HTTP requests use retry/backoff for transient failures.

Usage
-----
    python trustpoint_agent_hardened.py --profile agent_setup.json
    python trustpoint_agent_hardened.py --profile agent_setup.json --once
    python trustpoint_agent_hardened.py --profile agent_setup.json --log-format json

Dependencies
------------
    pip install requests cryptography
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import random
import signal
import socket
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from requests import Response, Session
from requests.auth import HTTPBasicAuth

if TYPE_CHECKING:
    from collections.abc import Mapping
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

LOG = logging.getLogger('trustpoint.agent')
STOP_REQUESTED = False

DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_INITIAL_BACKOFF_SECONDS = 2.0
DEFAULT_MAX_BACKOFF_SECONDS = 60.0
TRANSIENT_HTTP_STATUSES = {408, 425, 429, 500, 502, 503, 504}


class AgentError(RuntimeError):
    """Base exception for expected agent failures."""


class JsonFormatter(logging.Formatter):
    """Small JSON log formatter suitable for systemd/journald ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            'ts': self.formatTime(record, '%Y-%m-%dT%H:%M:%S%z'),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        if record.exc_info:
            payload['exception'] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str, log_format: str) -> None:
    handler = logging.StreamHandler()
    if log_format == 'json':
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


def _handle_stop(signum: int, _frame: object) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True
    LOG.info('received shutdown signal', extra={'signal': signum})
    sd_notify('STOPPING=1')


def install_signal_handlers() -> None:
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)


def fatal(message: str, exc: BaseException | None = None) -> NoReturn:
    if exc is not None:
        LOG.error('%s: %s', message, exc)
    else:
        LOG.error('%s', message)
    raise SystemExit(1)


def sd_notify(message: str) -> None:
    """Send a minimal sd_notify datagram when running under systemd."""
    notify_socket = os.environ.get('NOTIFY_SOCKET')
    if not notify_socket:
        return

    if notify_socket.startswith('@'):  # abstract namespace socket
        address: str | bytes = '\0' + notify_socket[1:]
    else:
        address = notify_socket

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(message.encode('utf-8'))
    except OSError as exc:
        LOG.debug('sd_notify failed: %s', exc)


@dataclass(slots=True)
class LocalStorage:
    private_key_path: Path = Path('domain_credential-key.pem')
    csr_path: Path = Path('domain_credential-csr.pem')
    tls_cert_path: Path = Path('trustpoint-tls.pem')
    certificate_path: Path = Path('domain_credential-certificate.pem')
    certificate_chain_path: Path = Path('domain_credential-chain.pem')

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> LocalStorage:
        return cls(
            private_key_path=Path(str(data.get('private_key_path', cls.private_key_path))),
            csr_path=Path(str(data.get('csr_path', cls.csr_path))),
            tls_cert_path=Path(str(data.get('tls_cert_path', cls.tls_cert_path))),
            certificate_path=Path(str(data.get('certificate_path', cls.certificate_path))),
            certificate_chain_path=Path(str(data.get('certificate_chain_path', cls.certificate_chain_path))),
        )


@dataclass(slots=True)
class AgentProfile:
    device: str
    secret: str
    tls_cert_pem: str
    base_url: str
    enrollment_path: str
    local_storage: LocalStorage
    certificate_profile: str = 'domain_credential'
    subject: str | None = None
    subject_alt_name: str | None = None
    public_key_algorithm_oid: str | None = None
    key_parameter: str | None = None  # Either key_size (RSA) or curve name (ECC)


@dataclass(slots=True)
class EnrollmentResponse:
    certificate: str
    certificate_chain: list[str] = field(default_factory=list)


@dataclass(slots=True)
class JobResult:
    profile_id: int
    success: bool
    error_message: str = ''


@dataclass(slots=True)
class ActiveCredential:
    cert_path: Path
    key_path: Path


@dataclass(slots=True)
class PollParams:
    base_url: str
    ca_cert_path: Path
    active_credential: ActiveCredential
    local_storage: LocalStorage
    request_timeout: int
    max_retries: int
    initial_backoff: float
    max_backoff: float


def read_profile(profile_path: Path) -> AgentProfile:
    try:
        raw_profile = json.loads(profile_path.read_text(encoding='utf-8'))
    except FileNotFoundError as exc:
        raise AgentError(f'profile file not found: {profile_path}') from exc
    except json.JSONDecodeError as exc:
        raise AgentError(f'profile file is not valid JSON: {profile_path}: {exc}') from exc

    profile = _expect_object(raw_profile.get('profile'), 'profile')
    onboarding = _expect_object(profile.get('onboarding'), 'profile.onboarding')
    cert_request = _expect_object(profile.get('certificate_request'), 'profile.certificate_request')
    local_storage = LocalStorage.from_mapping(_expect_object(profile.get('local_storage', {}), 'profile.local_storage'))

    device = _expect_non_empty_str(onboarding.get('device'), 'profile.onboarding.device')
    secret = _expect_non_empty_str(onboarding.get('secret'), 'profile.onboarding.secret')
    tls_cert_pem = _expect_non_empty_str(onboarding.get('tls_cert_pem'), 'profile.onboarding.tls_cert_pem')
    base_url = _expect_non_empty_str(cert_request.get('url'), 'profile.certificate_request.url').rstrip('/')
    enrollment_path = _expect_non_empty_str(cert_request.get('path'), 'profile.certificate_request.path')

    return AgentProfile(
        device=device,
        secret=secret,
        tls_cert_pem=tls_cert_pem,
        base_url=base_url,
        enrollment_path=enrollment_path,
        local_storage=local_storage,
        certificate_profile=str(cert_request.get('certificate_profile', 'domain_credential')),
        subject=_optional_str(cert_request.get('subject')),
        subject_alt_name=_optional_str(cert_request.get('subject_alt_name')),
        public_key_algorithm_oid=_optional_str(cert_request.get('public_key_algorithm_oid')),
        key_parameter=_optional_str(cert_request.get('key_parameter')),
    )


def _expect_object(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgentError(f'{field_name} must be an object')
    return value


def _expect_non_empty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AgentError(f'{field_name} must be a non-empty string')
    return value


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise AgentError(f'expected optional string, got {type(value).__name__}')
    return value or None


def join_url(base_url: str, path: str) -> str:
    if not path.startswith('/'):
        path = '/' + path
    return base_url.rstrip('/') + path


def ensure_parent(path: Path) -> None:
    parent = path.parent
    if parent and str(parent) != '.':
        parent.mkdir(parents=True, exist_ok=True)


def atomic_write_bytes(path: Path, data: bytes, mode: int) -> None:
    """Write bytes atomically to path using a temp file in the same directory."""
    ensure_parent(path)
    tmp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='wb',
            dir=str(path.parent if str(path.parent) != '' else Path()),
            prefix=f'.{path.name}.',
            suffix='.tmp',
            delete=False,
        ) as tmp:
            tmp_name = tmp.name
            os.chmod(tmp_name, mode)
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(tmp_name, path)
        tmp_name = None
        _fsync_parent(path)
    finally:
        if tmp_name:
            try:
                Path(tmp_name).unlink(missing_ok=True)
            except OSError:
                LOG.warning('failed to remove temporary file %s', tmp_name)


def atomic_write_text(path: Path, text: str, mode: int = 0o644) -> None:
    atomic_write_bytes(path, text.encode('utf-8'), mode)


def _fsync_parent(path: Path) -> None:
    if os.name != 'posix':
        return
    parent = path.parent if str(path.parent) else Path()
    try:
        fd = os.open(parent, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def generate_private_key(
    key_path: Path,
    public_key_algorithm_oid: str | None = None,
    key_parameter: str | None = None,
) -> PrivateKeyTypes:
    """Generate a private key based on the specified algorithm and parameter.

    Args:
        key_path: Path where the private key will be saved.
        public_key_algorithm_oid: OID of the public key algorithm (e.g., '1.2.840.113549.1.1.1' for RSA).
        key_parameter: For RSA: key size in bits (e.g., '2048', '3072', '4096').
                      For ECC: curve name (e.g., 'secp256r1', 'secp384r1').

    Returns:
        The generated private key (RSA or EC).
    """
    # Map OIDs to algorithm types
    rsa_oid = '1.2.840.113549.1.1.1'
    ecc_oid = '1.2.840.10045.2.1'

    # Determine which algorithm to use
    use_ecc = public_key_algorithm_oid == ecc_oid if public_key_algorithm_oid else False

    if use_ecc:
        # Generate ECC key - key_parameter is the curve name
        curve_name = (key_parameter or 'SECP256R1').upper()
        curve_map = {
            'SECP256R1': ec.SECP256R1(),
            'SECP384R1': ec.SECP384R1(),
            'SECP521R1': ec.SECP521R1(),
        }
        curve = curve_map.get(curve_name)
        if curve is None:
            LOG.warning('unsupported ECC curve %s, falling back to SECP256R1', curve_name)
            curve = ec.SECP256R1()

        LOG.info('generating ECC private key', extra={'path': str(key_path), 'curve': curve_name})
        key = ec.generate_private_key(curve)
    else:
        # Generate RSA key (default) - key_parameter is the key size
        try:
            size = int(key_parameter) if key_parameter else 2048
        except ValueError:
            LOG.warning('invalid RSA key size %r, using 2048', key_parameter)
            size = 2048
        LOG.info('generating RSA private key', extra={'path': str(key_path), 'key_size': size})
        key = rsa.generate_private_key(public_exponent=65537, key_size=size)

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    atomic_write_bytes(key_path, pem, 0o600)
    return key


def load_private_key(key_path: Path) -> PrivateKeyTypes:
    """Load a private key from a PEM file."""
    raw = key_path.read_bytes()
    key = serialization.load_pem_private_key(raw, password=None)
    return key


def generate_csr(
    key_path: Path,
    csr_path: Path,
    common_name: str = 'Trustpoint-Agent',
    subject: str | None = None,
    subject_alt_name: str | None = None,
) -> str:
    LOG.info('generating CSR', extra={'path': str(csr_path), 'subject': subject or common_name})
    key = load_private_key(key_path)
    name = parse_subject(subject, common_name)
    builder = x509.CertificateSigningRequestBuilder().subject_name(name)

    san = parse_subject_alt_name(subject_alt_name)
    if san is not None:
        builder = builder.add_extension(san, critical=False)

    csr = builder.sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('ascii')
    atomic_write_text(csr_path, csr_pem, 0o644)
    return csr_pem


def parse_subject(subject: str | None, common_name: str) -> x509.Name:
    if not subject:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    if not subject.startswith('/'):
        # Accept a plain string as CN for convenience.
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])

    oid_by_key = {
        'C': NameOID.COUNTRY_NAME,
        'ST': NameOID.STATE_OR_PROVINCE_NAME,
        'L': NameOID.LOCALITY_NAME,
        'O': NameOID.ORGANIZATION_NAME,
        'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
        'CN': NameOID.COMMON_NAME,
        'EMAILADDRESS': NameOID.EMAIL_ADDRESS,
    }

    attrs: list[x509.NameAttribute] = []
    for component in subject.strip('/').split('/'):
        if not component:
            continue
        if '=' not in component:
            raise AgentError(f'invalid subject component: {component!r}')
        key, value = component.split('=', 1)
        key = key.upper()
        oid = oid_by_key.get(key)
        if oid is None:
            raise AgentError(f'unsupported subject attribute: {key}')
        if not value:
            raise AgentError(f'empty subject attribute value for {key}')
        attrs.append(x509.NameAttribute(oid, value))

    if not attrs:
        raise AgentError('subject did not contain any attributes')
    return x509.Name(attrs)


def parse_subject_alt_name(subject_alt_name: str | None) -> x509.SubjectAlternativeName | None:
    if not subject_alt_name:
        return None

    names: list[x509.GeneralName] = []
    for raw_part in subject_alt_name.split(','):
        part = raw_part.strip()
        if not part:
            continue
        if ':' not in part:
            raise AgentError(f'invalid SAN component: {part!r}')
        kind, value = part.split(':', 1)
        kind = kind.upper()
        if kind == 'DNS':
            names.append(x509.DNSName(value))
        elif kind == 'IP':
            names.append(x509.IPAddress(ipaddress.ip_address(value)))
        elif kind in {'URI', 'URL'}:
            names.append(x509.UniformResourceIdentifier(value))
        elif kind in {'EMAIL', 'RFC822'}:
            names.append(x509.RFC822Name(value))
        else:
            raise AgentError(f'unsupported SAN type: {kind}')

    if not names:
        return None
    return x509.SubjectAlternativeName(names)


def make_session(
    ca_cert_path: Path,
    timeout: int,
    cert_pair: tuple[str, str] | None = None,
) -> Session:
    session = requests.Session()
    session.verify = str(ca_cert_path)
    if cert_pair is not None:
        session.cert = cert_pair
    session.headers.update({'User-Agent': 'trustpoint-agent/0.1'})
    # Store timeout as a dynamic attribute used by request_with_retries.
    session.trustpoint_timeout = timeout  # type: ignore[attr-defined]
    return session


def request_with_retries(
    session: Session,
    method: str,
    url: str,
    *,
    max_retries: int,
    initial_backoff: float,
    max_backoff: float,
    **kwargs: Any,
) -> Response:
    timeout = kwargs.pop('timeout', getattr(session, 'trustpoint_timeout', DEFAULT_TIMEOUT_SECONDS))
    attempt = 0
    while True:
        try:
            response = session.request(method, url, timeout=timeout, **kwargs)
        except requests.RequestException as exc:
            if attempt >= max_retries:
                raise AgentError(f'{method} {url} failed after {attempt + 1} attempt(s): {exc}') from exc
            sleep_for = _backoff_delay(attempt, initial_backoff, max_backoff)
            LOG.warning('HTTP request failed; retrying', extra={'method': method, 'url': url, 'sleep': sleep_for})
            time.sleep(sleep_for)
            attempt += 1
            continue

        if response.status_code not in TRANSIENT_HTTP_STATUSES or attempt >= max_retries:
            return response

        sleep_for = _retry_after_delay(response) or _backoff_delay(attempt, initial_backoff, max_backoff)
        LOG.warning(
            'HTTP request returned transient status; retrying',
            extra={'method': method, 'url': url, 'status': response.status_code, 'sleep': sleep_for},
        )
        time.sleep(sleep_for)
        attempt += 1


def _backoff_delay(attempt: int, initial_backoff: float, max_backoff: float) -> float:
    base = min(max_backoff, initial_backoff * (2 ** attempt))
    return base * random.uniform(0.5, 1.5)


def _retry_after_delay(response: Response) -> float | None:
    value = response.headers.get('Retry-After')
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


def require_success(response: Response, action: str) -> None:
    if 200 <= response.status_code < 300:
        return
    body = response.text[:4000]
    raise AgentError(f'{action} failed: HTTP {response.status_code}: {body}')


def response_json_object(response: Response, action: str) -> dict[str, Any]:
    content_type = response.headers.get('Content-Type', '')
    if 'json' not in content_type.lower():
        LOG.warning('response Content-Type is not JSON', extra={'action': action, 'content_type': content_type})
    try:
        data = response.json()
    except ValueError as exc:
        raise AgentError(f'{action} response is not valid JSON: {response.text[:4000]}') from exc
    if not isinstance(data, dict):
        raise AgentError(f'{action} response must be a JSON object')
    return data


def parse_enrollment_response(data: Mapping[str, Any], action: str) -> EnrollmentResponse:
    certificate = data.get('certificate')
    if not isinstance(certificate, str) or 'BEGIN CERTIFICATE' not in certificate:
        raise AgentError(f'{action} response missing valid PEM certificate')

    raw_chain = data.get('certificate_chain', [])
    if raw_chain is None:
        raw_chain = []
    if not isinstance(raw_chain, list) or not all(isinstance(item, str) for item in raw_chain):
        raise AgentError(f'{action} response field certificate_chain must be a list of PEM strings')

    for index, item in enumerate(raw_chain):
        if 'BEGIN CERTIFICATE' not in item:
            raise AgentError(f'{action} response certificate_chain[{index}] is not a PEM certificate')

    return EnrollmentResponse(certificate=certificate, certificate_chain=list(raw_chain))


def save_credentials(response: EnrollmentResponse, cert_path: Path, chain_path: Path) -> None:
    atomic_write_text(cert_path, _pem_join([response.certificate]), 0o644)
    LOG.info('certificate written', extra={'path': str(cert_path)})

    chain_material = [response.certificate, *response.certificate_chain]
    atomic_write_text(chain_path, _pem_join(chain_material), 0o644)
    LOG.info('certificate chain written', extra={'path': str(chain_path)})


def _pem_join(items: list[str]) -> str:
    return ''.join(item if item.endswith('\n') else item + '\n' for item in items)


def enroll_initial(profile: AgentProfile, args: argparse.Namespace) -> ActiveCredential:
    storage = profile.local_storage
    atomic_write_text(storage.tls_cert_path, profile.tls_cert_pem, 0o644)
    LOG.info('Trustpoint TLS trust store written', extra={'path': str(storage.tls_cert_path)})

    generate_private_key(
        storage.private_key_path,
        public_key_algorithm_oid=profile.public_key_algorithm_oid,
        key_parameter=profile.key_parameter,
    )
    csr_pem = generate_csr(
        storage.private_key_path,
        storage.csr_path,
        common_name='Trustpoint-Domain-Credential',
        subject=profile.subject,
        subject_alt_name=profile.subject_alt_name,
    )

    session = make_session(storage.tls_cert_path, args.request_timeout)
    enrollment_url = join_url(profile.base_url, profile.enrollment_path)
    LOG.info('enrolling initial certificate', extra={'url': enrollment_url, 'device': profile.device})

    response = request_with_retries(
        session,
        'POST',
        enrollment_url,
        json={'csr': csr_pem},
        auth=HTTPBasicAuth(profile.device, profile.secret),
        max_retries=args.max_retries,
        initial_backoff=args.initial_backoff,
        max_backoff=args.max_backoff,
    )
    require_success(response, 'initial enrollment')
    enrollment = parse_enrollment_response(response_json_object(response, 'initial enrollment'), 'initial enrollment')
    save_credentials(enrollment, storage.certificate_path, storage.certificate_chain_path)

    return ActiveCredential(cert_path=storage.certificate_path, key_path=storage.private_key_path)


def mtls_session(params: PollParams) -> Session:
    return make_session(
        ca_cert_path=params.ca_cert_path,
        timeout=params.request_timeout,
        cert_pair=(str(params.active_credential.cert_path), str(params.active_credential.key_path)),
    )


def cert_header_value(cert_path: Path) -> str:
    cert_pem = cert_path.read_text(encoding='utf-8')
    return urllib.parse.quote(cert_pem)


def fetch_jobs(params: PollParams, session: Session, cert_pem_urlencoded: str) -> tuple[int, list[dict[str, Any]]]:
    jobs_url = join_url(params.base_url, '/api/agents/jobs/')
    LOG.info('fetching jobs', extra={'url': jobs_url})
    response = request_with_retries(
        session,
        'GET',
        jobs_url,
        headers={'Accept': 'application/json', 'SSL-CLIENT-CERT': cert_pem_urlencoded},
        max_retries=params.max_retries,
        initial_backoff=params.initial_backoff,
        max_backoff=params.max_backoff,
    )
    require_success(response, 'job fetch')
    data = response_json_object(response, 'job fetch')

    poll_interval = data.get('poll_interval_seconds', 300)
    if not isinstance(poll_interval, int) or poll_interval < 1:
        raise AgentError('job fetch response poll_interval_seconds must be a positive integer')

    jobs = data.get('jobs', [])
    if not isinstance(jobs, list):
        raise AgentError('job fetch response jobs must be a list')
    if not all(isinstance(job, dict) for job in jobs):
        raise AgentError('each job must be an object')

    LOG.info('jobs fetched', extra={'count': len(jobs), 'poll_interval_seconds': poll_interval})
    return poll_interval, jobs


def deterministic_paths_for_job(params: PollParams, cert_profile: str) -> tuple[Path, Path, Path, Path]:
    if cert_profile == 'domain_credential':
        return (
            params.local_storage.private_key_path,
            params.local_storage.csr_path,
            params.local_storage.certificate_path,
            params.local_storage.certificate_chain_path,
        )

    # For non-domain credentials, keep deterministic names beside the configured domain key.
    base_dir = params.local_storage.private_key_path.parent
    if str(base_dir) == '':
        base_dir = Path()
    safe_profile = ''.join(ch if ch.isalnum() or ch in {'-', '_', '.'} else '_' for ch in cert_profile)
    return (
        base_dir / f'{safe_profile}-key.pem',
        base_dir / f'{safe_profile}-csr.pem',
        base_dir / f'{safe_profile}-certificate.pem',
        base_dir / f'{safe_profile}-chain.pem',
    )


def execute_renewal_job(
    params: PollParams,
    session: Session,
    job: Mapping[str, Any],
    cert_pem_urlencoded: str,
) -> JobResult:
    profile_id_raw = job.get('profile_id')
    if not isinstance(profile_id_raw, int):
        return JobResult(profile_id=0, success=False, error_message='job.profile_id must be an integer')
    profile_id = profile_id_raw

    try:
        workflow_profile = _expect_object(job.get('workflow_profile'), 'job.workflow_profile')
        cert_req = _expect_object(workflow_profile.get('certificate_request'), 'job.workflow_profile.certificate_request')
        cert_profile = str(cert_req.get('certificate_profile', 'domain_credential'))
        path = _expect_non_empty_str(cert_req.get('path'), 'job.workflow_profile.certificate_request.path')
        enroll_url = join_url(params.base_url, path)
        subject = _optional_str(cert_req.get('subject'))
        subject_alt_name = _optional_str(cert_req.get('subject_alt_name'))
        public_key_algorithm_oid = _optional_str(cert_req.get('public_key_algorithm_oid'))
        key_parameter = _optional_str(cert_req.get('key_parameter'))

        key_path, csr_path, cert_path, chain_path = deterministic_paths_for_job(params, cert_profile)

        LOG.info(
            'executing renewal job',
            extra={'profile_id': profile_id, 'certificate_profile': cert_profile, 'url': enroll_url},
        )

        # Stage into a TemporaryDirectory, then atomically commit the final files.
        # This prevents a failed renewal from corrupting the currently active credential.
        stage_parent = key_path.parent if str(key_path.parent) else Path()
        ensure_parent(stage_parent / '.keep')
        with tempfile.TemporaryDirectory(prefix=f'.trustpoint-renew-{profile_id}-', dir=str(stage_parent)) as stage_dir_raw:
            stage_dir = Path(stage_dir_raw)
            staged_key = stage_dir / key_path.name
            staged_csr = stage_dir / csr_path.name
            staged_cert = stage_dir / cert_path.name
            staged_chain = stage_dir / chain_path.name

            generate_private_key(
                staged_key,
                public_key_algorithm_oid=public_key_algorithm_oid,
                key_parameter=key_parameter,
            )
            csr_pem = generate_csr(
                staged_key,
                staged_csr,
                common_name=f'Trustpoint-{cert_profile}',
                subject=subject,
                subject_alt_name=subject_alt_name,
            )

            response = request_with_retries(
                session,
                'POST',
                enroll_url,
                json={'csr': csr_pem},
                headers={'Content-Type': 'application/json', 'SSL-CLIENT-CERT': cert_pem_urlencoded},
                max_retries=params.max_retries,
                initial_backoff=params.initial_backoff,
                max_backoff=params.max_backoff,
            )
            require_success(response, f'renewal job {profile_id}')
            enrollment = parse_enrollment_response(
                response_json_object(response, f'renewal job {profile_id}'),
                f'renewal job {profile_id}',
            )
            save_credentials(enrollment, staged_cert, staged_chain)

            # Commit order: cert/chain first, key last. For domain credential rotation,
            # the current mTLS session for this poll still holds the old credential.
            # The next poll creates a fresh session using the new cert/key paths.
            atomic_copy(staged_csr, csr_path, 0o644)
            atomic_copy(staged_cert, cert_path, 0o644)
            atomic_copy(staged_chain, chain_path, 0o644)
            atomic_copy(staged_key, key_path, 0o600)

        if cert_profile == 'domain_credential':
            params.active_credential = ActiveCredential(cert_path=cert_path, key_path=key_path)
            LOG.info('domain credential rotated', extra={'profile_id': profile_id})

        return JobResult(profile_id=profile_id, success=True)

    except Exception as exc:
        LOG.exception('renewal job failed', extra={'profile_id': profile_id})
        return JobResult(profile_id=profile_id, success=False, error_message=str(exc))


def atomic_copy(src: Path, dst: Path, mode: int) -> None:
    atomic_write_bytes(dst, src.read_bytes(), mode)


def acknowledge_job(params: PollParams, session: Session, result: JobResult, cert_pem_urlencoded: str) -> None:
    result_url = join_url(params.base_url, '/api/agents/jobs/result/')
    body = {
        'profile_id': result.profile_id,
        'success': result.success,
        'error_message': result.error_message,
    }
    response = request_with_retries(
        session,
        'POST',
        result_url,
        json=body,
        headers={'Content-Type': 'application/json', 'SSL-CLIENT-CERT': cert_pem_urlencoded},
        max_retries=params.max_retries,
        initial_backoff=params.initial_backoff,
        max_backoff=params.max_backoff,
    )
    require_success(response, f'job acknowledgement {result.profile_id}')
    ack = response_json_object(response, f'job acknowledgement {result.profile_id}')
    next_update = ack.get('next_certificate_update', 'unknown')
    if not isinstance(next_update, str):
        next_update = 'unknown'
    LOG.info('job acknowledged', extra={'profile_id': result.profile_id, 'next_certificate_update': next_update})


def poll_once(params: PollParams) -> int:
    # Build one session and one SSL-CLIENT-CERT header per poll. If a domain
    # credential is renewed during this cycle, acknowledgement still uses the
    # credential that authenticated the poll; the next cycle uses the new files.
    session = mtls_session(params)
    cert_pem_urlencoded = cert_header_value(params.active_credential.cert_path)
    poll_interval, jobs = fetch_jobs(params, session, cert_pem_urlencoded)

    for job in jobs:
        if STOP_REQUESTED:
            break
        result = execute_renewal_job(params, session, job, cert_pem_urlencoded)
        acknowledge_job(params, session, result, cert_pem_urlencoded)

    return poll_interval


def poll_loop(params: PollParams, once: bool) -> None:
    LOG.info('entering polling loop', extra={'once': once})
    sd_notify('READY=1')

    while not STOP_REQUESTED:
        try:
            poll_interval = poll_once(params)
            sd_notify('WATCHDOG=1')
        except Exception:
            LOG.exception('poll cycle failed')
            poll_interval = 60

        if once:
            return

        LOG.info('sleeping until next poll', extra={'seconds': poll_interval})
        sleep_interruptibly(poll_interval)


def sleep_interruptibly(seconds: int) -> None:
    deadline = time.monotonic() + seconds
    while not STOP_REQUESTED:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(1.0, remaining))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Bootstrap and run a hardened Trustpoint endpoint agent.')
    parser.add_argument('--profile', default='agent_setup.json', type=Path, help='Path to rendered agent_setup.json')
    parser.add_argument('--once', action='store_true', help='Perform a single poll cycle after onboarding, then exit')
    parser.add_argument('--skip-onboarding', action='store_true', help='Do not enroll; use existing local cert/key and only poll')
    parser.add_argument('--request-timeout', type=int, default=DEFAULT_TIMEOUT_SECONDS, help='HTTP request timeout in seconds')
    parser.add_argument('--max-retries', type=int, default=3, help='Maximum retries for transient HTTP/network failures')
    parser.add_argument('--initial-backoff', type=float, default=DEFAULT_INITIAL_BACKOFF_SECONDS, help='Initial retry backoff in seconds')
    parser.add_argument('--max-backoff', type=float, default=DEFAULT_MAX_BACKOFF_SECONDS, help='Maximum retry backoff in seconds')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help='Log level')
    parser.add_argument('--log-format', default='text', choices=['text', 'json'], help='Log format')
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    configure_logging(args.log_level, args.log_format)
    install_signal_handlers()

    try:
        profile = read_profile(args.profile)

        if args.skip_onboarding:
            atomic_write_text(profile.local_storage.tls_cert_path, profile.tls_cert_pem, 0o644)
            active = ActiveCredential(
                cert_path=profile.local_storage.certificate_path,
                key_path=profile.local_storage.private_key_path,
            )
            if not active.cert_path.exists() or not active.key_path.exists():
                raise AgentError('--skip-onboarding requires existing certificate and private key files')
            LOG.info('skipping onboarding and using existing local credential')
        else:
            active = enroll_initial(profile, args)

        poll_params = PollParams(
            base_url=profile.base_url,
            ca_cert_path=profile.local_storage.tls_cert_path,
            active_credential=active,
            local_storage=profile.local_storage,
            request_timeout=args.request_timeout,
            max_retries=args.max_retries,
            initial_backoff=args.initial_backoff,
            max_backoff=args.max_backoff,
        )
        poll_loop(poll_params, once=args.once)
        return 0

    except AgentError as exc:
        fatal('agent failed', exc)
    except KeyboardInterrupt:
        LOG.info('stopped by user')
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
