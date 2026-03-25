r"""Agent setup script for initial onboarding using the agent_setup.json profile.

Trustpoint fills all ``{{ placeholder }}`` values in the profile before
distributing it to the agent.  The agent therefore only needs the path to
the rendered profile file — no additional CLI arguments are required.

Flow
----
1. Read the rendered ``agent_setup.json`` profile.
2. Extract connection parameters from ``profile.onboarding`` and paths from
   ``profile.local_storage`` (all placeholders are already resolved).
3. Generate a 2048-bit RSA key pair via ``openssl genrsa``.
4. Generate a PKCS#10 CSR via ``openssl req``.
5. POST the CSR to ``profile.certificate_request.url`` +
   ``profile.certificate_request.path`` with HTTP Basic auth
   (``device`` / ``secret``) and the Trustpoint TLS trust store.
6. Write the issued certificate and chain to the configured paths.
7. Enter the polling loop: periodically call ``GET /api/agents/jobs/``
   with the newly issued domain credential (mTLS), execute each pending job
   (renew certificate via the resolved enrollment path), and acknowledge
   each job via ``POST /api/agents/jobs/result/``.

Usage::

    python agent_setup.py --profile agent_setup.json
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(message)s')
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# OpenSSL helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str]) -> None:
    """Run *cmd* via the system shell and stream output to the console.

    :param cmd: Command and arguments to execute.
    :raises subprocess.CalledProcessError: If the process exits non-zero.
    """
    log.info('  $ %s', ' '.join(cmd))
    subprocess.run(cmd, check=True)  # noqa: S603


def generate_key(key_path: str) -> None:
    """Generate a 2048-bit RSA private key and write it to *key_path*.

    :param key_path: Filesystem path where the PEM-encoded key will be saved.
    """
    log.info('\n[1/3] Generating RSA private key -> %s', key_path)
    Path(key_path).parent.mkdir(parents=True, exist_ok=True)
    _run(['openssl', 'genrsa', '-out', key_path, '2048'])


def generate_csr(key_path: str, csr_path: str, common_name: str) -> None:
    """Generate a PKCS#10 CSR signed with the key at *key_path*.

    :param key_path: Path to the PEM-encoded private key.
    :param csr_path: Filesystem path where the PEM-encoded CSR will be saved.
    :param common_name: Value for the certificate Subject CN field.
    """
    log.info('\n[2/3] Generating CSR (CN=%s) -> %s', common_name, csr_path)
    Path(csr_path).parent.mkdir(parents=True, exist_ok=True)
    _run([
        'openssl', 'req',
        '-new',
        '-key', key_path,
        '-out', csr_path,
        '-subj', f'/CN={common_name}',
    ])


# ---------------------------------------------------------------------------
# REST enrollment
# ---------------------------------------------------------------------------

@dataclass
class EnrollmentParams:
    """Groups all parameters needed for the REST enrollment request.

    :param csr_path: Path to the PEM-encoded CSR file.
    :param url: Full enrollment URL returned by Trustpoint in ``certificate_request``.
    :param device: Username for HTTP Basic auth (from ``onboarding.device``).
    :param secret: Password for HTTP Basic auth (from ``onboarding.secret``).
    :param tls_cert_path: Path to the PEM trust store for server TLS verification.
    :param output_json: Path where the JSON response body will be written.
    """

    csr_path: str
    url: str
    device: str
    secret: str
    tls_cert_path: str
    output_json: str


def enroll(params: EnrollmentParams) -> None:
    """POST the CSR to the Trustpoint REST enrollment endpoint.

    :param params: All parameters required for the enrollment request.
    """
    log.info('\n[3/3] Enrolling certificate')
    log.info('  URL  : %s', params.url)
    log.info('  User : %s', params.device)

    csr_pem = Path(params.csr_path).read_text(encoding='utf-8')

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        tmp.write(json.dumps({'csr': csr_pem}))
        body_file = tmp.name

    try:
        _run([
            'curl',
            '--user', f'{params.device}:{params.secret}',
            '--cacert', params.tls_cert_path,
            '--header', 'Content-Type: application/json',
            '--data', f'@{body_file}',
            '-o', params.output_json,
            '-w', '\nHTTP status: %{http_code}\n',
            params.url,
        ])
    finally:
        Path(body_file).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Save issued credentials
# ---------------------------------------------------------------------------

def save_credentials(response_json: str, local_storage: dict[str, str]) -> None:
    """Parse the enrollment response and write certificate files to disk.

    Expected response format::

        {
            "certificate": "<PEM>",
            "certificate_chain": ["<PEM ca1>", "<PEM ca2>", ...]
        }

    :param response_json: Path to the JSON file returned by the enrollment endpoint.
    :param local_storage: Resolved ``local_storage`` block from the profile.
    :raises SystemExit: If the response cannot be parsed or is missing expected fields.
    """
    raw = Path(response_json).read_text(encoding='utf-8')
    try:
        data: dict[str, object] = json.loads(raw)
    except json.JSONDecodeError as exc:
        log.exception('Could not parse enrollment response as JSON:\n%s', raw)
        raise SystemExit(1) from exc

    if 'certificate' not in data:
        log.error('Enrollment response missing "certificate" field:\n%s', raw)
        raise SystemExit(1)

    cert_pem: str = str(data['certificate'])
    chain: list[str] = [str(c) for c in data.get('certificate_chain', [])]  # type: ignore[union-attr]

    cert_path = local_storage.get('certificate_path', '')
    if cert_path:
        Path(cert_path).parent.mkdir(parents=True, exist_ok=True)
        Path(cert_path).write_text(cert_pem, encoding='utf-8')
        log.info('  Certificate        -> %s', cert_path)

    chain_path = local_storage.get('certificate_chain_path', '')
    if chain_path and chain:
        Path(chain_path).parent.mkdir(parents=True, exist_ok=True)
        Path(chain_path).write_text(cert_pem + ''.join(chain), encoding='utf-8')
        log.info('  Certificate chain  -> %s', chain_path)

    log.info('\nOnboarding complete.')


# ---------------------------------------------------------------------------
# Polling loop — periodic job check-in using the domain credential (mTLS)
# ---------------------------------------------------------------------------


@dataclass
class PollParams:
    """Parameters for the periodic job-polling loop.

    :param base_url: Trustpoint base URL, e.g. ``https://trustpoint.local``.
        The agent owns this value; it is taken from ``certificate_request.url``
        in the setup profile.
    :param cert_path: Path to the PEM-encoded domain-credential certificate
        used as the mTLS client certificate.
    :param key_path: Path to the matching PEM-encoded private key.
    :param ca_cert_path: Path to the Trustpoint TLS trust store (PEM) for
        server certificate verification.
    :param local_storage: Resolved ``local_storage`` block from the profile,
        used to determine where renewed credentials should be written.
    """

    base_url: str
    cert_path: str
    key_path: str
    ca_cert_path: str
    local_storage: dict[str, str] = field(default_factory=dict)


def _mtls_curl_base(params: PollParams, cert_pem_urlencoded: str) -> list[str]:
    """Return the common curl flags shared by all mTLS API calls.

    Includes the client cert/key for TLS, the CA trust store for server
    verification, and the ``SSL-CLIENT-CERT`` header so Django can
    authenticate the request via ``HTTP_SSL_CLIENT_CERT``.

    :param params: Polling configuration holding credential paths.
    :param cert_pem_urlencoded: URL-encoded PEM of the domain credential
        certificate.
    :returns: List of curl flags (without a URL or ``-o`` output path).
    """
    return [
        'curl', '--silent', '--show-error', '--fail',
        '--cert', params.cert_path,
        '--key', params.key_path,
        '--cacert', params.ca_cert_path,
        '--header', f'SSL-CLIENT-CERT: {cert_pem_urlencoded}',
    ]


@dataclass
class _JobResult:
    """Internal result of executing a single renewal job."""

    profile_id: int
    success: bool
    error_message: str = ''


def _execute_renewal_job(params: PollParams, job: dict, cert_pem_urlencoded: str) -> _JobResult:
    """Execute a single renewal job and return its result.

    Generates a fresh key and CSR, POSTs to the resolved enrollment path,
    and writes the issued certificate to disk via :func:`save_credentials`.

    :param params: Polling configuration (paths, base URL, local_storage).
    :param job: A single job dict from the ``GET /api/agents/jobs/`` response.
    :param cert_pem_urlencoded: URL-encoded domain credential PEM for the
        ``SSL-CLIENT-CERT`` header.
    :returns: A :class:`_JobResult` with ``success`` and ``error_message``.
    """
    profile_id: int = job['profile_id']
    cert_req: dict = job['workflow_profile'].get('certificate_request', {})
    cert_profile: str = cert_req.get('certificate_profile', 'domain_credential')
    enroll_url: str = params.base_url.rstrip('/') + cert_req.get('path', '')

    log.info('[job %d] Renewing "%s" via %s', profile_id, cert_profile, enroll_url)

    key_path_new: str = params.local_storage.get('private_key_path', f'{cert_profile}-key.pem')
    csr_path: str = params.local_storage.get('csr_path', f'{cert_profile}-csr.pem')
    renewal_path = tempfile.mktemp(suffix=f'-job{profile_id}.json')  # noqa: S306
    body_path = tempfile.mktemp(suffix='-csr-body.json')  # noqa: S306
    try:
        generate_key(key_path_new)
        generate_csr(key_path_new, csr_path, common_name='Trustpoint-Domain-Credential')
        csr_pem = Path(csr_path).read_text(encoding='utf-8')
        Path(body_path).write_text(json.dumps({'csr': csr_pem}), encoding='utf-8')
        _run([
            *_mtls_curl_base(params, cert_pem_urlencoded),
            '--header', 'Content-Type: application/json',
            '--data', f'@{body_path}',
            '-o', renewal_path,
            enroll_url,
        ])
        save_credentials(renewal_path, params.local_storage)
    except Exception:
        log.exception('[job %d] Renewal failed', profile_id)
        return _JobResult(profile_id, success=False, error_message=f'Renewal failed (job {profile_id})')
    else:
        return _JobResult(profile_id, success=True)
    finally:
        Path(renewal_path).unlink(missing_ok=True)
        Path(body_path).unlink(missing_ok=True)


def _acknowledge_job(params: PollParams, result_url: str, result: _JobResult, cert_pem_urlencoded: str) -> None:
    """POST the job result to Trustpoint so it can update renewal timestamps.

    :param params: Polling configuration.
    :param result_url: Full URL for ``POST /api/agents/jobs/result/``.
    :param result: The outcome of the job execution.
    :param cert_pem_urlencoded: URL-encoded domain credential PEM.
    """
    result_body = {
        'profile_id': result.profile_id,
        'success': result.success,
        'error_message': result.error_message,
    }
    ack_path = tempfile.mktemp(suffix=f'-ack{result.profile_id}.json')  # noqa: S306
    result_body_path = tempfile.mktemp(suffix=f'-result{result.profile_id}.json')  # noqa: S306
    try:
        Path(result_body_path).write_text(json.dumps(result_body), encoding='utf-8')
        _run([
            *_mtls_curl_base(params, cert_pem_urlencoded),
            '--header', 'Content-Type: application/json',
            '--data', f'@{result_body_path}',
            '-o', ack_path,
            result_url,
        ])
        ack: dict = json.loads(Path(ack_path).read_text(encoding='utf-8'))
        log.info(
            '[job %d] Acknowledged. Next renewal due: %s',
            result.profile_id,
            ack.get('next_certificate_update', 'unknown'),
        )
    finally:
        Path(ack_path).unlink(missing_ok=True)
        Path(result_body_path).unlink(missing_ok=True)


def _fetch_jobs(params: PollParams, cert_pem_urlencoded: str) -> dict:
    """Call ``GET /api/agents/jobs/`` and return the parsed response.

    :param params: Polling configuration.
    :param cert_pem_urlencoded: URL-encoded domain credential PEM.
    :returns: Parsed JSON response dict with ``jobs`` and ``poll_interval_seconds``.
    """
    jobs_url = f'{params.base_url}/api/agents/jobs/'
    log.info('\n[poll] GET %s', jobs_url)
    jobs_json_path = tempfile.mktemp(suffix='-jobs.json')  # noqa: S306
    try:
        _run([
            *_mtls_curl_base(params, cert_pem_urlencoded),
            '--header', 'Accept: application/json',
            '-o', jobs_json_path,
            jobs_url,
        ])
        return json.loads(Path(jobs_json_path).read_text(encoding='utf-8'))
    finally:
        Path(jobs_json_path).unlink(missing_ok=True)


def _poll_once(params: PollParams, cert_pem_urlencoded: str) -> int:
    """Perform one poll cycle: fetch jobs, execute each, acknowledge results.

    :param params: Polling configuration.
    :param cert_pem_urlencoded: URL-encoded PEM of the domain credential
        certificate, forwarded as the ``SSL-CLIENT-CERT`` header so Django
        can authenticate the request.
    :returns: The ``poll_interval_seconds`` value returned by Trustpoint.
    """
    result_url = f'{params.base_url}/api/agents/jobs/result/'

    jobs_response = _fetch_jobs(params, cert_pem_urlencoded)
    poll_interval: int = jobs_response.get('poll_interval_seconds', 300)
    jobs: list[dict] = jobs_response.get('jobs', [])
    log.info('[poll] %d pending job(s), next poll in %ds', len(jobs), poll_interval)

    for job in jobs:
        job_result = _execute_renewal_job(params, job, cert_pem_urlencoded)
        _acknowledge_job(params, result_url, job_result, cert_pem_urlencoded)

    return poll_interval


def poll_loop(params: PollParams) -> None:
    """Run the polling loop indefinitely, sleeping between each cycle.

    Each iteration:

    1. Reads the domain-credential certificate from disk and URL-encodes
       it for the ``SSL-CLIENT-CERT`` header.
    2. Calls :func:`_poll_once` to fetch and process all pending jobs.
    3. Sleeps for ``poll_interval_seconds`` as instructed by Trustpoint.

    :param params: Polling configuration including paths to the mTLS credentials.
    """
    log.info('\n--- Entering polling loop (Ctrl-C to stop) ---')
    while True:
        try:
            cert_pem = Path(params.cert_path).read_text(encoding='utf-8')
            cert_pem_urlencoded = urllib.parse.quote(cert_pem)
            poll_interval = _poll_once(params, cert_pem_urlencoded)
        except KeyboardInterrupt:
            log.info('\nPolling stopped by user.')
            return
        except Exception:
            log.exception('Poll cycle failed')
            poll_interval = 60  # back-off on error

        log.info('[poll] Sleeping %ds until next poll ...', poll_interval)
        time.sleep(poll_interval)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Parse CLI arguments and run the agent setup flow."""
    parser = argparse.ArgumentParser(
        description='Bootstrap a Trustpoint agent using a rendered agent_setup.json profile.',
    )
    parser.add_argument(
        '--profile',
        default='agent_setup.json',
        help='Path to the rendered agent_setup.json profile file (default: agent_setup.json).',
    )
    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Load the pre-rendered profile (all {{ }} values filled by Trustpoint)
    # ------------------------------------------------------------------
    profile_path = Path(args.profile)
    if not profile_path.exists():
        log.error('Profile file not found: %s', profile_path)
        raise SystemExit(1)

    with profile_path.open(encoding='utf-8') as fh:
        raw_profile: dict = json.load(fh)

    profile: dict = raw_profile['profile']
    onboarding: dict[str, str] = profile['onboarding']
    cert_request: dict[str, str] = profile['certificate_request']
    local_storage: dict[str, str] = profile.get('local_storage', {})

    # All values are already resolved — read directly from the profile.
    device: str = onboarding['device']
    secret: str = onboarding['secret']
    tls_cert_pem: str = onboarding['tls_cert_pem']
    enroll_url: str = cert_request['url'].rstrip('/') + cert_request['path']

    key_path: str = local_storage.get('private_key_path', 'domain_credential-key.pem')
    csr_path: str = local_storage.get('csr_path', 'domain_credential-csr.pem')
    tls_cert_path: str = local_storage.get('tls_cert_path', 'trustpoint-tls.pem')
    cert_path: str = local_storage.get('certificate_path', 'domain_credential-certificate.pem')
    response_json = tempfile.mktemp(suffix='-enrollment-response.json')  # noqa: S306

    # ------------------------------------------------------------------
    # Write the Trustpoint TLS trust store so curl can verify the server.
    # ------------------------------------------------------------------
    Path(tls_cert_path).parent.mkdir(parents=True, exist_ok=True)
    Path(tls_cert_path).write_text(tls_cert_pem, encoding='utf-8')
    log.info('TLS trust store written -> %s', tls_cert_path)

    # ------------------------------------------------------------------
    # Run the three-step onboarding flow
    # ------------------------------------------------------------------
    generate_key(key_path)
    generate_csr(key_path, csr_path, common_name='Trustpoint-Domain-Credential')
    enroll(EnrollmentParams(
        csr_path=csr_path,
        url=enroll_url,
        device=device,
        secret=secret,
        tls_cert_path=tls_cert_path,
        output_json=response_json,
    ))
    save_credentials(response_json, local_storage)
    Path(response_json).unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Enter the polling loop using the issued domain credential for mTLS.
    # The base URL is the same host the agent used for initial enrollment.
    # ------------------------------------------------------------------
    tp_base_url: str = cert_request['url'].rstrip('/')
    poll_loop(PollParams(
        base_url=tp_base_url,
        cert_path=cert_path,
        key_path=key_path,
        ca_cert_path=tls_cert_path,
        local_storage=local_storage,
    ))


if __name__ == '__main__':
    main()
