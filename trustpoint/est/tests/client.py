import base64
import logging
import requests
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


class ESTClient:
    def __init__(self, est_url, auth_type, domain, cert_template=None, username=None, password=None, cert_path=None,
                 key_path=None, ca_cert_path=None):
        """
        Initialize the EST client with the necessary authentication parameters.

        :param est_url: Base URL for the EST service
        :param auth_type: Authentication type ('basic', 'mutual_tls', or 'both')
        :param domain: Domain for the EST endpoint
        :param cert_template: Certificate template type
        :param username: Username for Basic Auth (if applicable)
        :param password: Password for Basic Auth (if applicable)
        :param cert_path: Client certificate path for Mutual TLS
        :param key_path: Client private key path for Mutual TLS
        :param ca_cert_path: CA certificate path for verifying the EST server
        """
        self.est_url = est_url.rstrip('/')
        self.auth_type = auth_type
        self.domain = domain
        self.cert_template = cert_template
        self.username = username
        self.password = password
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path

        self.session = requests.Session()

        logging.info("EST Client initialized with authentication type: %s", self.auth_type)

    def _get_auth(self):
        """Returns authentication parameters based on the chosen method."""
        auth = None
        cert = None

        if self.auth_type in ['basic', 'both'] and self.username and self.password:
            auth = (self.username, self.password)
            logging.info("Using Basic Authentication")

        if self.auth_type in ['mutual_tls', 'both'] and self.cert_path and self.key_path:
            cert = (self.cert_path, self.key_path)
            logging.info("Using Mutual TLS Authentication")

        return auth, cert

    def enroll(self, common_name, serial_number, save_key=True):
        """Performs EST enrollment to obtain a new certificate, with an option to store the private key."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        if save_key:
            with open("private_key.pem", "wb") as key_file:
                key_file.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            logging.info("Private key saved as 'private_key.pem'")

        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, serial_number),
        ]))

        csr = csr_builder.sign(private_key, hashes.SHA256())
        csr_der = csr.public_bytes(encoding=serialization.Encoding.DER)
        logging.info(f"CSR (DER; hex dump): {csr_der.hex()}")


        url = f"{self.est_url}/simpleenroll/{self.domain}/{self.cert_template}/"
        headers = {"Content-Type": "application/pkcs10"}
        auth, cert = self._get_auth()

        logging.info("Sending CSR to %s", url)
        response = self.session.post(url, data=csr_der, headers=headers, auth=auth, cert=cert, verify=self.ca_cert_path)

        if response.status_code == 200:
            cert_der = response.content
            cert_pem = x509.load_der_x509_certificate(cert_der).public_bytes(encoding=serialization.Encoding.PEM)
            with open("issued_cert.pem", "wb") as cert_file:
                cert_file.write(cert_pem)
            logging.info("Certificate received and saved as 'issued_cert.pem'")
        else:
            logging.error("Enrollment failed: %s", response.text)

    def reenroll(self, cert_path, key_path=None, generate_new_key=False):
        """Performs EST reenrollment using an existing certificate.

        :param cert_path: Path to the existing certificate
        :param key_path: Path to the existing private key (if using existing key)
        :param generate_new_key: Boolean to determine if a new key should be generated
        """
        with open(cert_path, "rb") as cert_file:
            existing_cert = x509.load_pem_x509_certificate(cert_file.read())

        if generate_new_key or not key_path:
            logging.info("Generating a new private key for reenrollment.")
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            with open("reenrolled_private_key.pem", "wb") as key_file:
                key_file.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            key_path = "reenrolled_private_key.pem"
        else:
            logging.info("Using the existing private key for reenrollment.")
            with open(key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(key_file.read(), password=None)

        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(existing_cert.subject)

        logging.info(f"Reenrollment CSR subject: {existing_cert.subject}")

        csr = csr_builder.sign(private_key, hashes.SHA256())
        csr_der = csr.public_bytes(encoding=serialization.Encoding.DER)
        logging.info(f"CSR (DER; hex dump): {csr_der.hex()}")

        url = f"{self.est_url}/simplereenroll/{self.domain}/{self.cert_template}/"
        headers = {"Content-Type": "application/pkcs10"}
        auth, cert = self._get_auth()

        logging.info("Sending reenrollment CSR to %s", url)
        response = self.session.post(url, data=csr_der, headers=headers, auth=auth, cert=cert, verify=self.ca_cert_path)

        if response.status_code == 200:
            cert_der = response.content
            cert_pem = x509.load_der_x509_certificate(cert_der).public_bytes(encoding=serialization.Encoding.PEM)
            with open("reenrolled_cert.pem", "wb") as cert_file:
                cert_file.write(cert_pem)
            logging.info("Reenrollment successful. Certificate saved as 'reenrolled_cert.pem'")
        else:
            logging.error("Reenrollment failed: %s", response.text)

    def get_ca_certificates(self):
        """Retrieves CA certificates from the EST /cacerts endpoint."""
        url = f"{self.est_url}/cacerts/{self.domain}/"
        auth, cert = self._get_auth()

        logging.info("Fetching CA certificates from %s", url)
        response = self.session.get(url, auth=auth, cert=cert)

        if response.status_code == 200:
            der_data = base64.b64decode(response.content) if response.headers.get("Content-Transfer-Encoding",
                                                                                  "").lower() == "base64" else response.content
            certificates = load_der_pkcs7_certificates(der_data)

            for i, cert in enumerate(certificates):
                pem = cert.public_bytes(serialization.Encoding.PEM)
                logging.info("CA Certificate %d:\n%s", i + 1, pem.decode("utf-8"))
                with open(f"ca_cert{i}.pem", "wb") as cert_file:
                    cert_file.write(pem)
        else:
            logging.error("Failed to retrieve CA certificates: %s", response.text)


if __name__ == "__main__":
    client = ESTClient(est_url="https://localhost:443/.well-known/est", auth_type="both", domain="arburg",
                       cert_template="tlsserver", username="admin", password="testing321", cert_path="cert.pem",
                       key_path="key.pem", ca_cert_path="trust_store.pem")
    client.enroll(common_name="test.example.com", serial_number="123456789", save_key=True)
    client.get_ca_certificates()
