"""AOKI Client for testing AOKI via CMP.

Please run from /rootdir/trustpoint with "uv run -m aoki.tests.cmp_client" for paths and imports to work.
This only works if your system OpenSSL version is 3.x.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

log = logging.getLogger('aoki.client')

# ruff: noqa: ERA001, T201

CURRENT_DIR = Path(__file__).parent.resolve()
CERTS_DIR = (CURRENT_DIR / './certs/').resolve()

class AokiClientOwnerIdCertVerificationError(Exception):
    """Exception raised when the provided Owner ID certificate is invalid or not corresponding to the IDevID."""

class AokiClientCertLoadError(Exception):
    """Exception raised when a certificate could not be loaded from the provided path."""

class AokiCmpClient:
    """AOKI-CMP Client for testing purposes."""

    idevid_subj_sn : str = '_'

    @staticmethod
    def _load_certificate(cert_path: Path) -> x509.Certificate:
        try:
            with cert_path.open('rb') as cert_file:
                return x509.load_pem_x509_certificate(cert_file.read())
        except FileNotFoundError as e:
            exc_msg = f'Certificate file not found: {cert_path}'
            raise AokiClientCertLoadError(exc_msg) from e
        except ValueError as e:
            exc_msg = f'Could not parse PEM format in certificate: {cert_path}'
            raise AokiClientCertLoadError(exc_msg) from e

    @staticmethod
    def _load_certificates(cert_path: Path) -> list[x509.Certificate]:
        try:
            with cert_path.open('rb') as cert_file:
                return x509.load_pem_x509_certificates(cert_file.read())
        except FileNotFoundError as e:
            exc_msg = f'Certificate file not found: {cert_path}'
            raise AokiClientCertLoadError(exc_msg) from e
        except ValueError as e:
            exc_msg = f'Could not parse PEM format in certificates: {cert_path}'
            raise AokiClientCertLoadError(exc_msg) from e

    def _get_idevid_owner_san_uri(self, idevid_cert: x509.Certificate) -> str:
        """Get the Owner ID SAN URI corresponding to a IDevID certificate.

        Formatted as "<idevid_subj_sn>.dev-owner.<idevid_x509_sn>.<idevid_sha256_fingerprint>.alt
        """
        try:
            sn_b = idevid_cert.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)[0].value
            idevid_subj_sn = sn_b.decode() if isinstance(sn_b, bytes) else sn_b
        except (ValueError, IndexError):
            idevid_subj_sn = '_'
        self.idevid_subj_sn = idevid_subj_sn
        idevid_x509_sn = hex(idevid_cert.serial_number)[2:].zfill(16)
        idevid_sha256_fingerprint = idevid_cert.fingerprint(hashes.SHA256()).hex()
        return f'{idevid_subj_sn}.dev-owner.{idevid_x509_sn}.{idevid_sha256_fingerprint}.alt'

    def _verify_matches_idevid_cert(self, owner_id_cert: x509.Certificate, idevid_cert: x509.Certificate) -> None:
        """Verify the Owner ID certificate is valid for the device IDevID."""
        log.info('Verifying Owner ID certificate matches IDevID certificate')
        idevid_san_uri = self._get_idevid_owner_san_uri(idevid_cert)
        log.info('IDevID SAN URI: %s', idevid_san_uri)
        for san in owner_id_cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value:
            if isinstance(san, x509.UniformResourceIdentifier) and san.value == idevid_san_uri:
                log.info('Owner ID certificate SAN URI matches IDevID certificate!')
                return
        exc_msg = 'Owner ID certificate does not match IDevID certificate.'
        raise AokiClientOwnerIdCertVerificationError(exc_msg)

    def __init__(
            self,
            server_url: str,
            cert_file: str,
            key_file: str,
            owner_truststore_file: str,
            idevid_truststore_file: str,
            *args: str, **kwargs: str
        ) -> None:
        """Initialize the AokiCmpClient."""
        self.server_url = server_url
        self.cert_file = cert_file
        self.key_file = key_file
        self.owner_truststore_file = owner_truststore_file
        self.idevid_truststore_file = idevid_truststore_file
        self.args = args
        self.kwargs = kwargs

    def onboard(self) -> None:
        """Run the AOKI-CMP Zero-Touch Device Onboarding process."""
        # Step 1: Generate a new key for the domain credential
        cmd = (
            'openssl',
            'genrsa',
            '-out', f'{CERTS_DIR}/domain_credential_key.pem',
            '2048',
        )
        subprocess.run(cmd, check=True)  # noqa: S603

        # Step 2: Execute the OpenSSL CMP command to request the domain credential
        cmd = (
            'openssl',
            'cmp',
            '-cmd', 'ir',
            '-implicit_confirm',
            '-server', self.server_url + '/.well-known/cmp/initialization/.aoki/',
            '-cert', f'{CERTS_DIR}/{self.cert_file}',
            '-key', f'{CERTS_DIR}/{self.key_file}',
            '-extracerts', f'{CERTS_DIR}/{self.idevid_truststore_file}',
            '-subject', '/CN=Trustpoint Domain Credential',
            '-newkey', f'{CERTS_DIR}/domain_credential_key.pem',
            '-certout', f'{CERTS_DIR}/dc_cert.pem',
            '-chainout', f'{CERTS_DIR}/chain_without_root.pem',
            '-extracertsout', f'{CERTS_DIR}/full_chain.pem',
            '-trusted', f'{CERTS_DIR}/{self.owner_truststore_file}',
            #'-tls_used'
        )
        print(subprocess.check_output(cmd).decode())  # noqa: S603

        # Step 3: Validate that the provided Owner ID certificate matches the IDevID certificate
        # Assuming first extraCert is the OwnerID / CMP signer cert, this is the case in the Trustpoint implementation
        owner_id_cert = self._load_certificates(CERTS_DIR / 'full_chain.pem')[0]
        idevid_cert = self._load_certificate(CERTS_DIR / self.cert_file)
        self._verify_matches_idevid_cert(owner_id_cert, idevid_cert)

        print('AOKI-CMP Client Onboarding completed successfully!')


if __name__ == '__main__':
    client = AokiCmpClient(
        server_url='http://localhost:8000', # or 'https://localhost:443' for production/Docker
        cert_file='idevid.pem',
        key_file='idevid_pk.pem',
        idevid_truststore_file='idevid_ca.pem',
        owner_truststore_file='ownerid_ca.pem',
        mdns = False, # not yet implemented
    )
    client.onboard()
