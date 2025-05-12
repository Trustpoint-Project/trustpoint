"""AOKI Client for testing purposes."""

from __future__ import annotations

import base64
import logging
from pathlib import Path

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
from est.tests.client import ESTClient

log = logging.getLogger('aoki.client')

# ruff: noqa: ERA001  # JSON example is interpreted as commented-out code

CURRENT_DIR = Path(__file__).parent.resolve()
CERTS_DIR = (CURRENT_DIR / './certs/').resolve()

HTTP_STATUS_OK = 200

class AokiClientInitResponseError(Exception):
    """Exception raised when the AOKI client initialization response is invalid."""

class AokiClientNoSupportedProtocolError(Exception):
    """Exception raised when no PKI protocol supported by this client is found in the AOKI client init response."""

class AokiClientOwnerIdCertVerificationError(Exception):
    """Exception raised when the provided Owner ID certificate is invalid or not corresponding to the IDevID."""

class AokiClientSignatureError(Exception):
    """Exception raised when signature by the Owner ID private key provided by the server could not be verified."""

class AokiClientCertLoadError(Exception):
    """Exception raised when a certificate could not be loaded from the provided path."""

class AokiClient:
    """AOKI Client for testing purposes."""

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

    @staticmethod
    def _parse_json_pem_cert(pem_str: str) -> x509.Certificate:
        """Parse a PEM certificate from a JSON string."""
        try:
            pem_bytes = pem_str.encode('utf-8')
            return x509.load_pem_x509_certificate(pem_bytes)
        except ValueError as e:
            exc_msg = f'Could not parse PEM format in certificate: {pem_str}'
            raise AokiClientCertLoadError(exc_msg) from e

    def _get_idevid_owner_san_uri(self, idevid_cert: x509.Certificate) -> str:
        """Get the Owner ID SAN URI corresponding to a IDevID certificate.

        Formatted as "<idevid_subj_sn>.aoki.owner.<idevid_x509_sn>.<idevid_sha256_fingerprint>.alt
        """
        try:
            sn_b = idevid_cert.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)[0].value
            idevid_subj_sn = sn_b.decode() if isinstance(sn_b, bytes) else sn_b
        except (ValueError, IndexError):
            idevid_subj_sn = '_'
        self.idevid_subj_sn = idevid_subj_sn
        idevid_x509_sn = hex(idevid_cert.serial_number)[2:].zfill(16)
        idevid_sha256_fingerprint = idevid_cert.fingerprint(hashes.SHA256()).hex()
        return f'{idevid_subj_sn}.aoki.owner.{idevid_x509_sn}.{idevid_sha256_fingerprint}.alt'

    def _verify_matches_idevid_cert(self, owner_id_cert: x509.Certificate, idevid_cert: x509.Certificate) -> None:
        """Verify the Owner ID certificate is valid for the device IDevID."""
        log.info('Verifying Owner ID certificate matches IDevID certificate')
        idevid_san_uri = self._get_idevid_owner_san_uri(idevid_cert)
        for san in owner_id_cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value:
            if isinstance(san, x509.UniformResourceIdentifier) and san.value == idevid_san_uri:
                log.info('Owner ID certificate SAN URI matches IDevID certificate!')
                return
        exc_msg = 'Owner ID certificate does not match IDevID certificate.'
        raise AokiClientOwnerIdCertVerificationError(exc_msg)

    def _verify_owner_id_cert(
            self, owner_id_cert: x509.Certificate, truststore: list[x509.Certificate], idevid_cert: x509.Certificate
        ) -> None:
        """Verify the Owner ID certificate against the provided truststore."""
        log.info('Verifying Owner ID certificate against truststore certificate')

        log.debug('Certificates in truststore: %s', truststore)
        store = Store(truststore)
        builder = PolicyBuilder().store(store)
        builder = builder.max_chain_depth(0)
        # TODO(Air): For now, cryptography requires the SAN extension to be present in the IDevID
        # and some other undisclosed extensions to be present in the truststore (CA) certificate
        # cryptography 45.0.0 will add the API to specify all extensions as optional (which we want)
        #builder = builder.extension_policies(
        #    ExtensionPolicy.permit_all(),
        #    ExtensionPolicy.permit_all(),
        #)
        verifier = builder.build_client_verifier()
        try:
            _verified_client = verifier.verify(owner_id_cert, []) # intermediate_cas)
        except VerificationError as e:
            # HACK: Bypass extension validation, remove when cryptography 45.0.0 is released
            # This is a somewhat dangerous hack
            # message on non-matching store is 'candidates exhausted: all candidates exhausted with no interior errors'
            if 'candidates exhausted: Certificate is missing required extension' in str(e):
                log.warning('Owner certificate bypassed extension validation')
                return self._verify_matches_idevid_cert(owner_id_cert, idevid_cert)
            exc_msg = f'Owner ID certificate verification failed: {e}'
            raise AokiClientOwnerIdCertVerificationError(exc_msg) from e
        return self._verify_matches_idevid_cert(owner_id_cert, idevid_cert)


    def __init__(
            self,
            server_url: str,
            cert_file: str,
            key_file: str,
            owner_truststore_file: str,
            *args: str, **kwargs: str
        ) -> None:
        """Initialize the AokiClient."""
        self.server_url = server_url
        self.cert_file = cert_file
        self.key_file = key_file
        self.owner_truststore_file = owner_truststore_file
        self.args = args
        self.kwargs = kwargs

    def onboard(self) -> None:
        """Run the AOKI Zero-Touch Device Onboarding process."""
        # Step 0: Owner Service discovery via mDNS

        # Step 1: AOKI initialization request
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.get(
            self.server_url + '/aoki/init',
            cert=(CERTS_DIR / self.cert_file, CERTS_DIR / self.key_file),
            verify=False, # intentionally provisionally trusted  # noqa: S501
            timeout=5,
        )
        if response.status_code != HTTP_STATUS_OK:
            log.error('AOKI init request failed (%s): %s', response.status_code, response.text)
            return
        # Step 2: Parse server response
        # We are expecting a 200 OK response with a JSON body containing the aoki initialization data.

        # Step 3: Parse the JSON body
        # We are expecting a JSON body with the following structure:
        # {
        #   "aoki-init": {
        #     "version": "1.0",
        #     "owner-id-cert": "base64encodedvalue=="
        #     "tls-truststore": "base64encodedvalue=="
        #     "enrollment-info": {
        #       "protocols": [
        #         {
        #           "protocol":"EST",
        #           "url":"https://localhost/.well-known/est/domain/domaincredential/"
        #         }
        #       ]
        #     }
        #   }
        # }
        try:
            json_data = response.json()
        except requests.exceptions.JSONDecodeError as e:
            exc_msg = f'Invalid JSON response from server. content={response.text}'
            raise AokiClientInitResponseError(exc_msg) from e

        # Get signature headers
        if 'AOKI-Signature' not in response.headers:
            exc_msg = 'AOKI-Signature header is required but missing in response headers.'
            raise AokiClientInitResponseError(exc_msg)
        if 'AOKI-Signature-Algorithm' not in response.headers:
            exc_msg = 'AOKI-Signature-Algorithm header is required but missing in response headers.'
            raise AokiClientInitResponseError(exc_msg)

        signature = response.headers['AOKI-Signature']
        signature_b = base64.b64decode(signature.encode('utf-8'))
        signature_algorithm = response.headers['AOKI-Signature-Algorithm']

        try:
            aoki_init = json_data['aoki-init']
            owner_id_cert_str = aoki_init['owner-id-cert']
            tls_truststore_str = aoki_init['tls-truststore']
            enrollment_info = aoki_init['enrollment_info']
            protocols = enrollment_info['protocols']
        except KeyError as e:
            exc_msg = f'Missing required field in AOKI initialization response: {e}'
            raise AokiClientInitResponseError(exc_msg) from e

        if not isinstance(protocols, list) or not protocols:
            exc_msg = 'enrollment-info.protocols should be a non-empty list.'
            raise AokiClientInitResponseError(exc_msg)

        for protocol in protocols:
            if not isinstance(protocol, dict) or 'protocol' not in protocol or 'url' not in protocol:
                continue
            if protocol['protocol'] != 'EST':
                continue
            est_url = protocol['url'] if protocol['url'].startswith('https://') else self.server_url + protocol['url']
            break
        else:
            exc_msg = 'No valid EST protocol definition found in AOKI initialization response.'
            raise AokiClientInitResponseError(exc_msg)

        # Step 4: Verify the Owner ID certificate against the owner truststore
        owner_id_cert = self._parse_json_pem_cert(owner_id_cert_str)
        idevid_cert = self._load_certificate(CERTS_DIR / self.cert_file)
        owner_truststore = self._load_certificates(CERTS_DIR / self.owner_truststore_file)
        self._verify_owner_id_cert(owner_id_cert, owner_truststore, idevid_cert)

        # Step 5: Verify the signature using the Owner ID public key
        owner_key = owner_id_cert.public_key()
        if not isinstance(owner_key, rsa.RSAPublicKey | ec.EllipticCurvePublicKey):
            error_message = 'Unsupported public key type for CSR signature verification.'
            raise TypeError(error_message)
        try:
            if isinstance(owner_key, rsa.RSAPublicKey):
                owner_key.verify(
                    signature=signature_b,
                    data=response.content,
                    padding=padding.PKCS1v15(),
                    algorithm=hashes.SHA256(),  # get this from the header
                )
            elif isinstance(owner_key, ec.EllipticCurvePublicKey):
                owner_key.verify(
                    signature=signature_b,
                    data=response.content,
                    signature_algorithm=ec.ECDSA(hashes.SHA256()),
                )
        except Exception as e:
            exc_msg = f'AOKI init signature verification failed: {e}'
            raise AokiClientSignatureError(exc_msg) from e

        tls_truststore = self._parse_json_pem_cert(tls_truststore_str)
        tls_truststore_path = CERTS_DIR / 'trust_store.pem'
        with tls_truststore_path.open('wb') as cert_file:
            cert_file.write(tls_truststore.public_bytes(encoding=serialization.Encoding.PEM))

        # Step 6: Enrollment
        log.info('AOKI init response verified successfully, requesting domain credential via EST...')
        est_client = ESTClient(
            est_url=est_url,
            auth_type='mutual_tls',#'both',
            domain=None,
            cert_template=None,
            username=None,#'admin',
            password=None,#'testing321',
            cert_path='/certs/idevid.pem',
            key_path='/certs/idevid_pk.pem',
            ca_cert_path=tls_truststore_path,
            out_cert_path='dc_cert.pem',
            out_key_path='dc_private_key.pem',
        )
        est_client.enroll(common_name='aokitest.example.com', serial_number=self.idevid_subj_sn, save_key=True)


if __name__ == '__main__':
    client = AokiClient(
        server_url='https://localhost:443',
        cert_file='idevid.pem',
        key_file='idevid_pk.pem',
        owner_truststore_file='ownerid_ca.pem',
        mdns = False, # not yet implemented
    )
    client.onboard()
