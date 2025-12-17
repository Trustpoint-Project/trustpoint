"""This module contains cli commands which are displayed in the help pages."""

from typing import Any

from django.utils.translation import gettext as _
from trustpoint_core import oid

from devices.views import NamedCurveMissingForEccErrorMsg
from pki.util.cert_req_converter import JSONCertRequestCommandExtractor


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
            '-implicit_confirm \\\n'
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
            '-implicit_confirm \\\n'
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
        sans_line = f'-addext "subjectAltName = {profile_sans}"' if profile_sans else ''

        return (
            'openssl req \\\n'
            '-new \\\n'
            f'-key key-{cred_number}.pem \\\n'
            '-outform DER \\\n'
            f'-out csr-{cred_number}.der \\\n'
            f'-subj "{profile_subject_entries}" \\\n'
            f'{sans_line}'
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
        """Get the conversion PKCS#7 (DER) to PEM command.

        Args:
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.
        """
        return (
            f'openssl pkcs7 -in certificate-{cred_number}.p7c \\\n'
            f'-inform DER -print_certs -out  certificate-{cred_number}.pem'
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
        """Get the domain credential conversion DER to PEM command.

        Returns:
             The constructed command.
        """
        return (
            'openssl pkcs7 -in domain-credential-certificate.p7c \\\n'
            '-inform DER -print_certs -out  domain-credential-certificate.pem'
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
            '-implicit_confirm \\\n'
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
            '-implicit_confirm \\\n'
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
