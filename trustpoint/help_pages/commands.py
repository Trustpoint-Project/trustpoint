"""This module contains cli commands which are displayed in the help pages."""

from typing import Any

from django.utils.translation import gettext as _
from trustpoint_core import oid

from devices.views import NamedCurveMissingForEccErrorMsg
from pki.util.cert_req_converter import JSONCertRequestCommandExtractor
from trustpoint.settings import DOCKER_CONTAINER


class KeyGenCommandBuilder:
    """Gets key-generation commands."""

    @staticmethod
    def get_key_gen_command(public_key_info: oid.PublicKeyInfo, cred_number: int, key_name: str = '') -> str:
        """Gets the key generation command corresponding to the provided type.

        Args:
            public_key_info: Key type information.
            cred_number: The credential number to use.
            key_name: Custom key file name, will default to key-{ cred_number }.pem otherwise.

        Raises:
            ValueError: If the public key information is inconsistent or key type is not supported.

        Returns:
            The key generation command as string.
        """
        if not key_name:
            key_name = f'key-{cred_number}.pem'

        if public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            return f'openssl genrsa -out {key_name} {public_key_info.key_size}'

        if public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            if not public_key_info.named_curve:
                raise ValueError(NamedCurveMissingForEccErrorMsg)
            return f'openssl ecparam -name {public_key_info.named_curve.ossl_curve_name} -genkey -noout -out {key_name}'

        err_msg = _('Unsupported public key algorithm')
        raise ValueError(err_msg)


class CmpSharedSecretCommandBuilder:
    """Builds CMP shared-secret commands for different certificate profiles."""

    @staticmethod
    def get_dynamic_cert_profile_command(
        host: str, pk: int, shared_secret: str, cred_number: int, sample_request: dict[str, Any]) -> str:
        """Gets the dynamic certificate profile command.

        Args:
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./cmp/p/...
            pk: The primary key of the device in question used as Key Identifier (KID).
            shared_secret: The shared secret.
            cred_number: The credential number - counter of issued credentials.
            sample_request: The sample certificate request in JSON format.

        Returns:
            The constructed command.
        """
        profile_subject_entries = JSONCertRequestCommandExtractor.sample_request_to_openssl_subj(sample_request)
        profile_validity_days = JSONCertRequestCommandExtractor.sample_request_to_openssl_days(sample_request)
        profile_sans = JSONCertRequestCommandExtractor.sample_request_to_openssl_cmp_sans(sample_request)
        sans_line = f'-sans "{profile_sans}" \\\n' if profile_sans else ''

        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-tls_used \\\n'
            f'-server {host} \\\n'
            f'-ref {pk} \\\n'
            f'-secret pass:{shared_secret} \\\n'
            f'-subject "{profile_subject_entries}" \\\n'
            f'-days {profile_validity_days} \\\n'
            f'{sans_line}'
            f'-newkey key-{cred_number}.pem \\\n'
            f'-certout certificate-{cred_number}.pem \\\n'
            f'-chainout chain-{cred_number}.pem \\\n'
            f'-extracertsout full-chain-{cred_number}.pem'
        )

    @staticmethod
    def get_domain_credential_profile_command(host: str, pk: int, shared_secret: str) -> str:
        """Get the domain credential profile command.

        Args:
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./cmp/p/...
            pk: The primary key of the device in question used as Key Identifier (KID).
            shared_secret: The shared secret.
            domain_name: The name of the domain will be used in the file names to mitigate overriding other files.

        Returns:
            The constructed command.
        """
        return (
            'openssl cmp \\\n'
            '-cmd ir \\\n'
            '-tls_used \\\n'
            f'-server {host} \\\n'
            f'-ref {pk} \\\n'
            f'-secret pass:{shared_secret} \\\n'
            f'-subject "/CN=Trustpoint-Domain-Credential" \\\n'
            '-days 10 \\\n'
            '-newkey domain-credential-key.pem \\\n'
            '-certout domain-credential-certificate.pem \\\n'
            '-chainout domain-credential-chain.pem \\\n'
            '-extracertsout domain-credential-full-chain.pem'
        )


class EstUsernamePasswordCommandBuilder:
    """Builds EST username-password commands for different certificate profiles."""

    @staticmethod
    def get_dynamic_cert_profile_command(
        cred_number: int, sample_request: dict[str, Any]) -> str:
        """Gets the dynamic certificate profile command.

        Args:
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./cmp/p/...
            pk: The primary key of the device in question used as Key Identifier (KID).
            shared_secret: The shared secret.
            cred_number: The credential number - counter of issued credentials.
            sample_request: The sample certificate request in JSON format.

        Returns:
            The constructed command.
        """
        profile_subject_entries = JSONCertRequestCommandExtractor.sample_request_to_openssl_subj(sample_request)
        profile_sans = JSONCertRequestCommandExtractor.sample_request_to_openssl_req_sans(sample_request)
        sans_line = f'-addext "subjectAltName = {profile_sans}" \\\n' if profile_sans else ''

        return (
            'openssl req \\\n'
            '-new \\\n'
            f'-key key-{cred_number}.pem \\\n'
            '-outform DER \\\n'
            f'-out csr-{cred_number}.der \\\n'
            f'{sans_line}'
            f'-subj "{profile_subject_entries}"'
        )

    @staticmethod
    def get_curl_enroll_command(est_username: str, est_password: str, host: str, cred_number: int) -> str:
        """Get the curl enroll command.

        Args:
            est_username: The EST username to use.
            est_password:The EST password to use.
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./cmp/p/...
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.
        """
        return (
            f'curl --user "{est_username}:{est_password}" \\\n'
            f'--cacert trustpoint-tls-trust-store.pem \\\n'
            '--header "Content-Type: application/pkcs10" \\\n'
            f'--data-binary "@csr-{cred_number}.der" \\\n'
            f'-o certificate-{cred_number}.p7c \\\n'
            f'{host}'
        )

    @staticmethod
    def get_conversion_p7_pem_command(cred_number: int) -> str:
        """Get the conversion PKCS#7 (base64/PEM) to PEM command.

        Args:
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.
        """
        return (
            f'base64 -d -i certificate-{cred_number}.p7c \\\n'
            f'| openssl pkcs7 -inform DER -print_certs -out certificate-{cred_number}.pem'
        )

    @staticmethod
    def get_domain_credential_profile_command() -> str:
        """Get the domain credential profile command.

        Returns:
             The constructed command.
        """
        return (
            'openssl req \\\n'
            '-new \\\n'
            '-key domain-credential-key.pem \\\n'
            '-outform DER \\\n'
            '-out csr-domain-credential.der \\\n'
            '-subj "/CN=Trustpoint-Domain-Credential"'
        )

    @staticmethod
    def get_curl_enroll_domain_credential_command(est_username: str, est_password: str, host: str) -> str:
        """Get the curl domain credential command.

        Args:
            est_username: The EST username to use.
            est_password:The EST password to use.
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./cmp/p/...

        Returns:
            The constructed command.
        """
        return (
            f'curl --user "{est_username}:{est_password}" \\\n'
            f'--cacert trustpoint-tls-trust-store.pem \\\n'
            '--header "Content-Type: application/pkcs10" \\\n'
            f'--data-binary "@csr-domain-credential.der" \\\n'
            f'-o domain-credential-certificate.p7c \\\n'
            f'{host}'
        )

    @staticmethod
    def get_domain_credential_conversion_p7_pem_command() -> str:
        """Get the domain credential conversion base64 PKCS#7 to PEM command.

        Returns:
             The constructed command.
        """
        return (
            'base64 -d -i domain-credential-certificate.p7c \\\n'
            '| openssl pkcs7 -inform DER -print_certs -out domain-credential-certificate.pem'
        )


class CmpClientCertificateCommandBuilder:
    """Builds CMP client-certificate (domain credential auth) commands for different certificate profiles."""

    @staticmethod
    def get_dynamic_cert_profile_command(
        host: str, cred_number: int, sample_request: dict[str, Any]) -> str:
        """Gets the dynamic certificate profile command.

        Args:
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./cmp/p/...
            pk: The primary key of the device in question used as Key Identifier (KID).
            shared_secret: The shared secret.
            cred_number: The credential number - counter of issued credentials.
            sample_request: The sample certificate request in JSON format.

        Returns:
            The constructed command.
        """
        profile_subject_entries = JSONCertRequestCommandExtractor.sample_request_to_openssl_subj(sample_request)
        profile_validity_days = JSONCertRequestCommandExtractor.sample_request_to_openssl_days(sample_request)
        profile_sans = JSONCertRequestCommandExtractor.sample_request_to_openssl_cmp_sans(sample_request)
        sans_line = f'-sans "{profile_sans}" \\\n' if profile_sans else ''

        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-tls_used \\\n'
            '-trusted domain-credential-full-chain.pem \\\n'
            f'-server {host} \\\n'
            '-cert domain-credential-certificate.pem \\\n'
            '-key domain-credential-key.pem \\\n'
            f'-subject "{profile_subject_entries}" \\\n'
            f'-days {profile_validity_days} \\\n'
            f'{sans_line}'
            f'-newkey key-{cred_number}.pem \\\n'
            f'-certout certificate-{cred_number}.pem \\\n'
            f'-chainout chain-{cred_number}.pem \\\n'
            f'-extracertsout full-chain-{cred_number}.pem'
        )

    @staticmethod
    def get_idevid_domain_credential_command(host: str) -> str:
        """Gets the idevid domain credential command.

        Args:
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./cmp/p/...

        Returns:
            The constructed command.
        """
        return (
            'openssl cmp \\\n'
            '-cmd ir \\\n'
            f'-server {host} \\\n'
            '-tls_used \\\n'
            '-cert idevid.pem \\\n'
            '-key idevid.key \\\n'
            '-extracerts idevid_chain.pem \\\n'
            '-subject "/CN=Trustpoint Domain Credential" \\\n'
            '-newkey domain_credential_key.pem \\\n'
            '-certout domain_credential_cert.pem \\\n'
            '-chainout chain_without_root.pem \\\n'
            '-extracertsout full_chain.pem \\\n'
            '-srvcert issuing_ca_cert.pem'
        )


class EstClientCertificateCommandBuilder:
    """Builds EST username-password commands for different certificate profiles."""

    @staticmethod
    def get_domain_credential_profile_command() -> str:
        """Get the domain credential profile command.

        Returns:
            The constructed command.
        """
        return (
            'openssl req \\\n'
            '-new \\\n'
            '-key domain-credential-key.pem \\\n'
            '-outform DER \\\n'
            '-out csr-domain-credential.der \\\n'
            '-subj "/CN=Trustpoint-Domain-Credential"'
        )

    @staticmethod
    def get_curl_enroll_application_credential(cred_number: int, host: str) -> str:
        """Get the curl enroll application credential command.

        Args:
            cred_number: The credential number - counter of issued credentials.
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./est/...

        Returns:
            The constructed command.
        """
        return (
            'curl '
            f'--cert domain-credential-certificate.pem \\\n'
            f'--key domain-credential-key.pem \\\n'
            f'--cacert trustpoint-tls-trust-store.pem \\\n'
            '--header "Content-Type: application/pkcs10" \\\n'
            f'--data-binary "@csr-{cred_number}.der" \\\n'
            f'-o certificate-{cred_number}.p7c \\\n'
            f'{host}'
        )

    @staticmethod
    def get_idevid_gen_csr_command() -> str:
        """Gets the IDevID gen CSR command.

        Returns:
            The constructed command.
        """
        return (
            'openssl req \\\n'
            '-new \\\n'
            '-key idevid.key \\\n'
            '-outform der \\\n'
            '-out domain_credential_csr.der \\\n'
            '-subj "/CN="'
        )

    @staticmethod
    def get_idevid_enroll_domain_credential_command(host: str) -> str:
        """Gets the IDevID enroll domain credential command.

        Args:
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./est/...

        Returns:
            The constructed command.
        """
        return (
            'curl \\\n'
            '--cert idevid.pem \\\n'
            '--key idevid.key \\\n'
            '--cacert server_cert.pem \\\n'
            '--header "Content-Type: application/pkcs10" \\\n'
            '--data-binary "@domain_credential_csr.der" \\\n'
            '-o certificate.der \\\n'
            f'{host}'
        )

    @staticmethod
    def get_idevid_der_pem_conversion_command() -> str:
        """Gets the IDevID DER to PEM conversion command.

        Returns:
            The constructed command.
        """
        return 'openssl x509 \\\n-inform der \\\n-in certificate.der \\\n-out certificate.pem'

    @staticmethod
    def get_idevid_ca_certs_command(host: str) -> str:
        """Gets the IDevID ca certs command.

        Args:
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./est/...

        Returns:
            The constructed command.
        """
        return (
            'curl -X GET \\\n'
            f'"{host}" \\\n'
            '--cacert server_cert.pem \\\n'
            '-H "Accept: application/pkcs7-mime" \\\n'
            '| base64 --decode > cacerts.p7b'
        )

    @staticmethod
    def get_idevid_pkcs7_pem_conversion_command() -> str:
        """Gets the IDevID PKCS#7 to PEM conversion command.

        Returns:
            The constructed command.
        """
        return 'openssl pkcs7 \\\n-print_certs \\\n-inform DER \\\n-in cacerts.p7b \\\n-out cacerts.pem'


class AokiCmpIDevIDCommandBuilder:
    """Builds AOKI CMP commands with IDevID authentication."""

    @staticmethod
    def get_keygen_command() -> str:
        """Get the key generation command for domain credential."""
        return (
            'openssl genrsa \\\n'
            '  -out domain_credential_key.pem \\\n'
            '  2048'
        )

    @staticmethod
    def get_cmp_ir_command(host: str) -> str:
        """Get the CMP Initial Request (IR) command for AOKI with IDevID."""
        return (
            'openssl cmp \\\n'
            '  -cmd ir \\\n'
            f'  -server {host} \\\n'
            '  -cert idevid.pem \\\n'
            '  -key idevid_pk.pem \\\n'
            '  -extracerts idevid_ca.pem \\\n'
            '  -subject "/CN=Trustpoint Domain Credential" \\\n'
            '  -newkey domain-credential-key.pem \\\n'
            '  -certout domain-credential-certificate.pem \\\n'
            '  -chainout chain_without_root.pem \\\n'
            '  -extracertsout domain-credential-full-chain.pem \\\n'
            '  -trusted ownerid_ca.pem'
        )


class AokiEstIDevIDCommandBuilder:
    """Builds AOKI EST commands with IDevID authentication."""

    @staticmethod
    def get_aoki_init_command(host: str) -> str:
        """Get the AOKI initialization request command."""
        return (
            f'curl --cert idevid.pem \\\n'
            f'  --key idevid_pk.pem \\\n'
            f'  --cacert ownerid_ca.pem \\\n'
            f'  -o aoki_init_response.json \\\n'
            f'{host}/aoki/init'
        )

    @staticmethod
    def get_aoki_init_response_example() -> str:
        """Get an example AOKI initialization response JSON."""
        return """{
  "aoki-init": {
    "version": "1.0",
    "owner-id-cert": "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----",
    "tls-truststore": "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----",
    "enrollment-info": {
      "protocols": [
        {
          "protocol": "EST",
          "url": "https://127.0.0.1:443/.well-known/est/domain/domain_credential/simpleenroll"
        }
      ]
    }
  }
}"""

    @staticmethod
    def get_keygen_command() -> str:
        """Get the key generation command for domain credential."""
        return (
            'openssl genrsa \\\n'
            '  -out domain_credential_key.pem \\\n'
            '  2048'
        )

    @staticmethod
    def get_csr_command() -> str:
        """Get the CSR generation command for AOKI EST enrollment."""
        return (
            'openssl req \\\n'
            '  -new \\\n'
            '  -key domain_credential_key.pem \\\n'
            '  -outform DER \\\n'
            '  -out domain_credential.der \\\n'
            '  -subj "/CN=Trustpoint-Domain-Credential"'
        )

    @staticmethod
    def get_curl_enroll_command(host: str) -> str:
        """Get the curl EST enrollment command for AOKI with IDevID."""
        return (
            f'curl --cert domain-credential-cert.pem \\\n'
            f'  --key domain-credential-key.pem \\\n'
            f'  --cacert trust_store.pem \\\n'
            f'  --header "Content-Type: application/pkcs10" \\\n'
            f'  --data-binary "@domain_credential.der" \\\n'
            f'  -o domain_certificate.p7c \\\n'
            f'{host}'
        )


class RestUsernamePasswordCommandBuilder:
    """Builds REST API username-password commands for different certificate profiles."""

    @staticmethod
    def get_dynamic_cert_profile_command(cred_number: int, sample_request: dict[str, Any]) -> str:
        """Gets the CSR generation command for a dynamic certificate profile.

        Args:
            cred_number: The credential number - counter of issued credentials.
            sample_request: The sample certificate request in JSON format.

        Returns:
            The constructed command.
        """
        profile_subject_entries = JSONCertRequestCommandExtractor.sample_request_to_openssl_subj(sample_request)
        profile_sans = JSONCertRequestCommandExtractor.sample_request_to_openssl_req_sans(sample_request)
        sans_line = f'-addext "subjectAltName = {profile_sans}" \\\n' if profile_sans else ''

        return (
            'openssl req \\\n'
            '-new \\\n'
            f'-key key-{cred_number}.pem \\\n'
            f'-out csr-{cred_number}.pem \\\n'
            f'{sans_line}'
            f'-subj "{profile_subject_entries}"'
        )

    @staticmethod
    def get_curl_enroll_command(rest_username: str, rest_password: str, host: str, cred_number: int) -> str:
        """Get the curl enroll command.

        Args:
            rest_username: The REST username to use.
            rest_password: The REST password to use.
            host: The full REST enroll URL.
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.
        """
        return (
            f'curl --user "{rest_username}:{rest_password}" \\\n'
            '--cacert trustpoint-tls-trust-store.pem \\\n'
            '--header "Content-Type: application/json" \\\n'
            f'--data-binary @<(jq -n --arg csr "$(cat csr-{cred_number}.pem)" \'{{csr: $csr}}\') \\\n'
            f'-o certificate-{cred_number}.json \\\n'
            f'{host}'
        )

    @staticmethod
    def get_extract_cert_command(cred_number: int) -> str:
        """Get the command to extract the PEM certificate from the JSON response.

        Args:
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.
        """
        return (
            f'jq -r .certificate certificate-{cred_number}.json > certificate-{cred_number}.pem'
        )

    @staticmethod
    def get_domain_credential_csr_command() -> str:
        """Get the domain credential CSR generation command.

        Returns:
            The constructed command.
        """
        return (
            'openssl req \\\n'
            '-new \\\n'
            '-key domain-credential-key.pem \\\n'
            '-out csr-domain-credential.pem \\\n'
            '-subj "/CN=Trustpoint-Domain-Credential"'
        )

    @staticmethod
    def get_curl_enroll_domain_credential_command(rest_username: str, rest_password: str, host: str) -> str:
        """Get the curl domain credential enroll command.

        Args:
            rest_username: The REST username to use.
            rest_password: The REST password to use.
            host: The full REST enroll URL.

        Returns:
            The constructed command.
        """
        return (
            f'curl --user "{rest_username}:{rest_password}" \\\n'
            '--cacert trustpoint-tls-trust-store.pem \\\n'
            '--header "Content-Type: application/json" \\\n'
            '--data-binary @<(jq -n --arg csr "$(cat csr-domain-credential.pem)" \'{csr: $csr}\') \\\n'
            '-o domain-credential-certificate.json \\\n'
            f'{host}'
        )

    @staticmethod
    def get_extract_domain_credential_command() -> str:
        """Get the command to extract the domain credential PEM certificate from the JSON response.

        Returns:
            The constructed command.
        """
        return 'jq -r .certificate domain-credential-certificate.json > domain-credential-certificate.pem'


class RestClientCertificateCommandBuilder:
    """Builds REST API client-certificate (mTLS) commands for certificate re-enrollment."""

    @staticmethod
    def get_dynamic_cert_profile_command(cred_number: int, sample_request: dict[str, Any]) -> str:
        """Gets the CSR generation command for a dynamic certificate profile.

        Args:
            cred_number: The credential number - counter of issued credentials.
            sample_request: The sample certificate request in JSON format.

        Returns:
            The constructed command.
        """
        profile_subject_entries = JSONCertRequestCommandExtractor.sample_request_to_openssl_subj(sample_request)
        profile_sans = JSONCertRequestCommandExtractor.sample_request_to_openssl_req_sans(sample_request)
        sans_line = f'-addext "subjectAltName = {profile_sans}" \\\n' if profile_sans else ''

        return (
            'openssl req \\\n'
            '-new \\\n'
            f'-key key-{cred_number}.pem \\\n'
            f'-out csr-{cred_number}.pem \\\n'
            f'{sans_line}'
            f'-subj "{profile_subject_entries}"'
        )

    @staticmethod
    def get_curl_enroll_command(host: str, cred_number: int) -> str:
        """Get the curl enroll command using mTLS with the domain credential.

        Args:
            host: The full REST enroll URL.
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.

        Note:
            When not running inside a Docker container (i.e. the development server) nginx
            is not present to inject the ``SSL-CLIENT-CERT`` header automatically.  The curl
            command therefore URL-encodes the PEM certificate and sends it as an explicit HTTP
            header so the server-side ``ClientCertificateValidation`` can read it from
            ``META['HTTP_SSL_CLIENT_CERT']``.  In Docker/production nginx handles this
            transparently and the header must not be sent twice.
        """
        if not DOCKER_CONTAINER:
            return (
                'CERT_HEADER=$(python3 -c "import urllib.parse; '
                "print(urllib.parse.quote(open('domain-credential-certificate.pem').read()))\") \\\n"
                '&& curl \\\n'
                '--cert domain-credential-certificate.pem \\\n'
                '--key domain-credential-key.pem \\\n'
                '--cacert trustpoint-tls-trust-store.pem \\\n'
                '--header "Content-Type: application/json" \\\n'
                '--header "SSL-CLIENT-CERT: ${CERT_HEADER}" \\\n'
                f'--data-binary @<(jq -n --arg csr "$(cat csr-{cred_number}.pem)" \'{{csr: $csr}}\') \\\n'
                f'-o certificate-{cred_number}.json \\\n'
                f'{host}'
            )
        return (
            'curl \\\n'
            '--cert domain-credential-certificate.pem \\\n'
            '--key domain-credential-key.pem \\\n'
            '--cacert trustpoint-tls-trust-store.pem \\\n'
            '--header "Content-Type: application/json" \\\n'
            f'--data-binary @<(jq -n --arg csr "$(cat csr-{cred_number}.pem)" \'{{csr: $csr}}\') \\\n'
            f'-o certificate-{cred_number}.json \\\n'
            f'{host}'
        )

    @staticmethod
    def get_curl_reenroll_command(host: str, cred_number: int) -> str:
        """Get the curl re-enroll command using mTLS with the domain credential.

        Args:
            host: The full REST reenroll URL.
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.

        Note:
            Same ``SSL-CLIENT-CERT`` header logic as :meth:`get_curl_enroll_command`.
        """
        if not DOCKER_CONTAINER:
            return (
                'CERT_HEADER=$(python3 -c "import urllib.parse; '
                "print(urllib.parse.quote(open('domain-credential-certificate.pem').read()))\") \\\n"
                '&& curl \\\n'
                '--cert domain-credential-certificate.pem \\\n'
                '--key domain-credential-key.pem \\\n'
                '--cacert trustpoint-tls-trust-store.pem \\\n'
                '--header "Content-Type: application/json" \\\n'
                '--header "SSL-CLIENT-CERT: ${CERT_HEADER}" \\\n'
                f'--data-binary @<(jq -n --arg csr "$(cat csr-{cred_number}.pem)" \'{{csr: $csr}}\') \\\n'
                f'-o certificate-{cred_number}.json \\\n'
                f'{host}'
            )
        return (
            'curl \\\n'
            '--cert domain-credential-certificate.pem \\\n'
            '--key domain-credential-key.pem \\\n'
            '--cacert trustpoint-tls-trust-store.pem \\\n'
            '--header "Content-Type: application/json" \\\n'
            f'--data-binary @<(jq -n --arg csr "$(cat csr-{cred_number}.pem)" \'{{csr: $csr}}\') \\\n'
            f'-o certificate-{cred_number}.json \\\n'
            f'{host}'
        )

    @staticmethod
    def get_extract_cert_command(cred_number: int) -> str:
        """Get the command to extract the PEM certificate from the JSON response.

        Args:
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.
        """
        return f'jq -r .certificate certificate-{cred_number}.json > certificate-{cred_number}.pem'

    @staticmethod
    def get_extract_cert_chain_command(cred_number: int) -> str:
        """Get the command to extract the certificate chain from the JSON response.

        Args:
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.
        """
        return f"jq -r '.certificate_chain[]' certificate-{cred_number}.json > certificate-chain-{cred_number}.pem"
