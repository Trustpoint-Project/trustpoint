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

Usage::

    python agent_setup.py --profile agent_setup.json
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass
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
    response_json = '/tmp/enrollment-response.json'  # noqa: S108

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


if __name__ == '__main__':
    main()
