"""This module contains cli commands which are displayed in the help pages."""

from devices.views import NamedCurveMissingForEccErrorMsg
from django.utils.translation import gettext as _
from trustpoint_core import oid


class KeyGenCommandBuilder:

    @staticmethod
    def get_key_gen_command(public_key_info: oid.PublicKeyInfo, cred_number: int, key_name: str = '') -> str:

        if not key_name:
            key_name = f'key-{ cred_number }.pem'

        if public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            return f'openssl genrsa -out { key_name } {public_key_info.key_size}'

        if public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            if not public_key_info.named_curve:
                raise ValueError(NamedCurveMissingForEccErrorMsg)
            return (
                f'openssl ecparam -name {public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out { key_name }'
            )

        err_msg = _('Unsupported public key algorithm')
        raise ValueError(err_msg)


class CmpSharedSecretCommandBuilder:
    """Builds CMP shared-secret commands for different certificate profiles."""

    @staticmethod
    def get_tls_client_profile_command(host: str, pk: int, shared_secret: str, cred_number: int) -> str:
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            '-tls_used \\\n'
            f'-server  { host } \\\n'
            f'-ref { pk } \\\n'
            f'-secret pass:{ shared_secret } \\\n'
            f'-subject "/CN=Trustpoint-TLS-Client-Credential-{ cred_number }" \\\n'
            '-days 10 \\\n'
            f'-newkey key-{ cred_number }.pem \\\n'
            '-certout cert.pem \\\n'
            '-chainout chain_without_root.pem \\\n'
            '-extracertsout full_chain.pem'
        )

    @staticmethod
    def get_tls_server_profile_command(host: str, pk: int, shared_secret: str, cred_number: int) -> str:
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            '-tls_used \\\n'
            f'-server { host } \\\n'
            f'-ref { pk } \\\n'
            f'-secret pass:{ shared_secret } \\\n'
            f'-subject "/CN=Trustpoint-TLS-Server-Client-Credential-{ cred_number }" \\\n'
            '-days 10 \\\n'
            '-sans "critical 127.0.0.1 ::1 localhost" \\\n'
            f'-newkey key-{ cred_number }.pem \\\n'
            '-certout cert.pem \\\n'
            '-chainout chain_without_root.pem \\\n'
            '-extracertsout full_chain.pem'
        )

    @staticmethod
    def get_opc_ua_client_profile_command(host: str, pk: int, shared_secret: str, cred_number: int) -> str:
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            '-tls_used \\\n'
            f'-server  { host } \\\n'
            f'-ref { pk } \\\n'
            f'-secret pass:{ shared_secret } \\\n'
            f'-subject "/CN=Trustpoint-OPC-UA-Client-Credential-{ cred_number }" \\\n'
            '-days 10 \\\n'
            f'-sans "critical URI:trustpoint.opc-ua-uri.de/credential-{cred_number}" \\\n'
            f'-newkey key-{ cred_number }.pem \\\n'
            '-certout cert.pem \\\n'
            '-chainout chain_without_root.pem \\\n'
            '-extracertsout full_chain.pem'
        )

    @staticmethod
    def get_opc_ua_server_profile_command(host: str, pk: int, shared_secret: str, cred_number: int) -> str:
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            '-tls_used \\\n'
            f'-server { host } \\\n'
            f'-ref { pk } \\\n'
            f'-secret pass:{ shared_secret } \\\n'
            f'-subject "/CN=Trustpoint-OPC-UA-Server-Client-Credential-{ cred_number }" \\\n'
            '-days 10 \\\n'
            f'-sans "critical 127.0.0.1 ::1 localhost URI::trustpoint.opc-ua-uri.de/credential-{cred_number}" \\\n'
            f'-newkey key-{ cred_number }.pem \\\n'
            '-certout cert.pem \\\n'
            '-chainout chain_without_root.pem \\\n'
            '-extracertsout full_chain.pem'
        )

    @staticmethod
    def get_domaincredential_profile_command(host: str, pk: int, shared_secret: str, domain_name: str) -> str:
        return (
            'openssl cmp \\\n'
            '-cmd ir \\\n'
            '-implicit_confirm \\\n'
            '-tls_used \\\n'
            f'-server { host }/.well-known/cmp/initialization/{ domain_name } \\\n'
            f'-ref { pk } \\\n'
            f'-secret pass:{ shared_secret } \\\n'
            f'-subject "/CN=Trustpoint-Domain-Credential" \\\n'
            '-days 10 \\\n'
            '-newkey domain_credential_key.pem \\\n'
            '-certout domain_credential_certificate.pem \\\n'
            '-chainout domain_credential_chain.pem \\\n'
            '-extracertsout domain_credential_full_chain.pem'
        )


class EstUsernamePasswordCommandBuilder:
    """Builds EST username-password commands for different certificate profiles."""

    @staticmethod
    def get_tls_client_profile_command(cred_number: int) -> str:
        return (
            'openssl req \\\n'
            '-new \\\n'
            f'-key key-{cred_number}.pem \\\n'
            '-outform DER \\\n'
            f'-out csr-{cred_number}.der \\\n'
            f'-subj "/CN=Trustpoint-TLS-Client-Credential-{ cred_number }"'
        )

    @staticmethod
    def get_tls_server_profile_command(cred_number: int) -> str:
        return (
            'openssl req \\\n'
            '-new \\\n'
            f'-key key-{cred_number}.pem \\\n'
            '-outform DER \\\n'
            f'-out csr-{cred_number}.der \\\n'
            f'-subj "/CN=Trustpoint-TLS-Server-Client-Credential-{ cred_number }" \\\n'
            '-addext "subjectAltName = critical, IP:127.0.0.1, IP:::1, DNS:localhost"'
        )

    @staticmethod
    def get_opc_ua_client_profile_command(cred_number: int) -> str:
        return (
            'openssl req \\\n'
            '-new \\\n'
            f'-key key-{cred_number}.pem \\\n'
            '-outform DER \\\n'
            f'-out csr-{cred_number}.der \\\n'
            f'-subj "/CN=Trustpoint-OPC-UA-Client-Credential-{ cred_number }" \\\n'
            f'-addext "subjectAltName = critical, URI:trustpoint.opc-ua-uri.de/credential-{cred_number}"'
        )

    @staticmethod
    def get_opc_ua_server_profile_command(cred_number: int) -> str:
        return (
            'openssl req \\\n'
            '-new \\\n'
            f'-key key-{cred_number}.pem \\\n'
            '-outform DER \\\n'
            f'-out csr-{cred_number}.der \\\n'
            f'-subj "/CN=Trustpoint-OPC-UA-Server-Client-Credential-{ cred_number }" \\\n'
            '-addext "subjectAltName = critical, '
            f'IP:127.0.0.1, IP:::1, DNS:localhost, URI:trustpoint.opc-ua-uri.de/credential-{cred_number}"'
        )

    @staticmethod
    def get_curl_enroll_command(est_username: str, est_password: str, host: str, domain_name: str, cred_number: int) -> str:
        return (
            f'curl --user "{ est_username }:{ est_password }" \\\n'
            f'--cacert trust-store-{ domain_name }.pem \\\n'
            '--header "Content-Type: application/pkcs10" \\\n'
            f'--data-binary "@csr-{cred_number}.der" \\\n'
            f'-o certificate-{cred_number}.der \\\n'
            f'{ host }'
        )

    @staticmethod
    def get_conversion_der_pem_command(cred_number: int) -> str:
        return (
            'openssl x509 \\\n'
            '-inform DER \\\n'
            '-outform PEM \\\n'
            f'-in certificate-{cred_number}.der \\\n'
            f'-out certificate-{cred_number}.pem'
        )


class CmpClientCertificateCommandBuilder:

    @staticmethod
    def get_tls_client_profile_command(host: str, cred_number: int) -> str:
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            '-tls_used \\\n'
            '-trusted domain_credential_full_chain.pem \\\n'
            f'-server  { host } \\\n'
            '-cert domain_credential_certificate.pem \\\n'
            '-key domain_credential_key.pem \\\n'
            f'-subject "/CN=Trustpoint-TLS-Client-Credential-{ cred_number }" \\\n'
            '-days 10 \\\n'
            f'-newkey key-{ cred_number }.pem \\\n'
            f'-certout certificate-{ cred_number }.pem \\\n'
            f'-chainout chain-{ cred_number }.pem \\\n'
            f'-extracertsout full-chain-{ cred_number }.pem'
        )

    @staticmethod
    def get_tls_server_profile_command(host: str, cred_number: int) -> str:
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            '-tls_used \\\n'
            '-trusted domain_credential_full_chain.pem \\\n'
            f'-server { host } \\\n'
            '-cert domain_credential_certificate.pem \\\n'
            '-key domain_credential_key.pem \\\n'
            f'-subject "/CN=Trustpoint-TLS-Server-Client-Credential-{ cred_number }" \\\n'
            '-days 10 \\\n'
            '-sans "critical 127.0.0.1 ::1 localhost" \\\n'
            f'-newkey key-{ cred_number }.pem \\\n'
            f'-certout certificate-{ cred_number }.pem \\\n'
            f'-chainout chain-{ cred_number }.pem \\\n'
            f'-extracertsout full-chain-{ cred_number }.pem'
        )

    @staticmethod
    def get_opc_ua_client_profile_command(host: str, cred_number: int) -> str:
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            '-tls_used \\\n'
            '-trusted domain_credential_full_chain.pem \\\n'
            f'-server  { host } \\\n'
            '-cert domain_credential_certificate.pem \\\n'
            '-key domain_credential_key.pem \\\n'
            f'-subject "/CN=Trustpoint-OPC-UA-Client-Credential-{ cred_number }" \\\n'
            '-days 10 \\\n'
            f'-sans "critical URI:trustpoint.opc-ua-uri.de/credential-{cred_number}" \\\n'
            f'-newkey key-{ cred_number }.pem \\\n'
            f'-certout certificate-{ cred_number }.pem \\\n'
            f'-chainout chain-{ cred_number }.pem \\\n'
            f'-extracertsout full-chain-{ cred_number }.pem'
        )

    @staticmethod
    def get_opc_ua_server_profile_command(host: str, cred_number: int) -> str:
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            '-tls_used \\\n'
            '-trusted domain_credential_full_chain.pem \\\n'
            f'-server { host } \\\n'
            '-cert domain_credential_certificate.pem \\\n'
            '-key domain_credential_key.pem \\\n'
            f'-subject "/CN=Trustpoint-OPC-UA-Server-Client-Credential-{ cred_number }" \\\n'
            '-days 10 \\\n'
            f'-sans "critical 127.0.0.1 ::1 localhost URI::trustpoint.opc-ua-uri.de/credential-{cred_number}" \\\n'
            f'-newkey key-{ cred_number }.pem \\\n'
            f'-certout certificate-{ cred_number }.pem \\\n'
            f'-chainout chain-{ cred_number }.pem \\\n'
            f'-extracertsout full-chain-{ cred_number }.pem'
        )
