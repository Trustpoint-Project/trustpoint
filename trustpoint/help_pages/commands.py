"""This module contains cli commands which are displayed in the help pages."""

from devices.views import NamedCurveMissingForEccErrorMsg
from django.utils.translation import gettext as _
from trustpoint_core import oid


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
    def get_tls_client_profile_command(host: str, pk: int, shared_secret: str, cred_number: int) -> str:
        """Gets the TLS-Client profile command.

        Args:
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./cmp/p/...
            pk: The primary key of the device in question used as Key Identifier (KID).
            shared_secret: The shared secret.
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.
        """
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            '-tls_used \\\n'
            f'-server  {host} \\\n'
            f'-ref {pk} \\\n'
            f'-secret pass:{shared_secret} \\\n'
            f'-subject "/CN=Trustpoint-TLS-Client-Credential-{cred_number}" \\\n'
            '-days 10 \\\n'
            f'-newkey key-{cred_number}.pem \\\n'
            f'-certout certificate-{cred_number}.pem \\\n'
            '-chainout chain-without-root.pem \\\n'
            '-extracertsout full-chain.pem'
        )

    @staticmethod
    def get_tls_server_profile_command(host: str, pk: int, shared_secret: str, cred_number: int) -> str:
        """Get the TLS-Server profile command.

        Args:
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./cmp/p/...
            pk: The primary key of the device in question used as Key Identifier (KID).
            shared_secret: The shared secret.
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.
        """
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            '-tls_used \\\n'
            f'-server {host} \\\n'
            f'-ref {pk} \\\n'
            f'-secret pass:{shared_secret} \\\n'
            f'-subject "/CN=Trustpoint-TLS-Server-Client-Credential-{cred_number}" \\\n'
            '-days 10 \\\n'
            '-sans "critical 127.0.0.1 ::1 localhost" \\\n'
            f'-newkey key-{cred_number}.pem \\\n'
            f'-certout certificate-{cred_number}.pem \\\n'
            '-chainout chain-without-root.pem \\\n'
            '-extracertsout full-chain.pem'
        )

    @staticmethod
    def get_opc_ua_client_profile_command(host: str, pk: int, shared_secret: str, cred_number: int) -> str:
        """Get the OPC-UA-Client profile command.

        Args:
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./cmp/p/...
            pk: The primary key of the device in question used as Key Identifier (KID).
            shared_secret: The shared secret.
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.
        """
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            '-tls_used \\\n'
            f'-server  {host} \\\n'
            f'-ref {pk} \\\n'
            f'-secret pass:{shared_secret} \\\n'
            f'-subject "/CN=Trustpoint-OPC-UA-Client-Credential-{cred_number}" \\\n'
            '-days 10 \\\n'
            f'-sans "critical URI:trustpoint.opc-ua-uri.de/credential-{cred_number}" \\\n'
            f'-newkey key-{cred_number}.pem \\\n'
            f'-certout certificate-{cred_number}.pem \\\n'
            '-chainout chain-without-root.pem \\\n'
            '-extracertsout full-chain.pem'
        )

    @staticmethod
    def get_opc_ua_server_profile_command(host: str, pk: int, shared_secret: str, cred_number: int) -> str:
        """Get the OPC-UA-Server profile command.

        Args:
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./cmp/p/...
            pk: The primary key of the device in question used as Key Identifier (KID).
            shared_secret: The shared secret.
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.
        """
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            '-tls_used \\\n'
            f'-server {host} \\\n'
            f'-ref {pk} \\\n'
            f'-secret pass:{shared_secret} \\\n'
            f'-subject "/CN=Trustpoint-OPC-UA-Server-Client-Credential-{cred_number}" \\\n'
            '-days 10 \\\n'
            f'-sans "critical 127.0.0.1 ::1 localhost URI::trustpoint.opc-ua-uri.de/credential-{cred_number}" \\\n'
            f'-newkey key-{cred_number}.pem \\\n'
            f'-certout certificate-{cred_number}.pem \\\n'
            '-chainout chain-without-root.pem \\\n'
            '-extracertsout full-chain.pem'
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
    def get_tls_client_profile_command(cred_number: int) -> str:
        """Get the TLS-Client profile command.

        Args:
            cred_number: The credential number - counter of issued credentials.


        Returns:
            The constructed command.
        """
        return (
            'openssl req \\\n'
            '-new \\\n'
            f'-key key-{cred_number}.pem \\\n'
            '-outform DER \\\n'
            f'-out csr-{cred_number}.der \\\n'
            f'-subj "/CN=Trustpoint-TLS-Client-Credential-{cred_number}"'
        )

    @staticmethod
    def get_tls_server_profile_command(cred_number: int) -> str:
        """Get the TLS-Server profile command.

        Args:
            cred_number: The credential number - counter of issued credentials.


        Returns:
            The constructed command.
        """
        return (
            'openssl req \\\n'
            '-new \\\n'
            f'-key key-{cred_number}.pem \\\n'
            '-outform DER \\\n'
            f'-out csr-{cred_number}.der \\\n'
            f'-subj "/CN=Trustpoint-TLS-Server-Client-Credential-{cred_number}" \\\n'
            '-addext "subjectAltName = critical, IP:127.0.0.1, IP:::1, DNS:localhost"'
        )

    @staticmethod
    def get_opc_ua_client_profile_command(cred_number: int) -> str:
        """Get the OPC-UA-Client profile command.

        Args:
            cred_number: The credential number - counter of issued credentials.


        Returns:
            The constructed command.
        """
        return (
            'openssl req \\\n'
            '-new \\\n'
            f'-key key-{cred_number}.pem \\\n'
            '-outform DER \\\n'
            f'-out csr-{cred_number}.der \\\n'
            f'-subj "/CN=Trustpoint-OPC-UA-Client-Credential-{cred_number}" \\\n'
            f'-addext "subjectAltName = critical, URI:trustpoint.opc-ua-uri.de/credential-{cred_number}"'
        )

    @staticmethod
    def get_opc_ua_server_profile_command(cred_number: int) -> str:
        """Get the OPC-UA-Server profile command.

        Args:
            cred_number: The credential number - counter of issued credentials.


        Returns:
            The constructed command.
        """
        return (
            'openssl req \\\n'
            '-new \\\n'
            f'-key key-{cred_number}.pem \\\n'
            '-outform DER \\\n'
            f'-out csr-{cred_number}.der \\\n'
            f'-subj "/CN=Trustpoint-OPC-UA-Server-Client-Credential-{cred_number}" \\\n'
            '-addext "subjectAltName = critical, '
            f'IP:127.0.0.1, IP:::1, DNS:localhost, URI:trustpoint.opc-ua-uri.de/credential-{cred_number}"'
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
            f'-o certificate-{cred_number}.der \\\n'
            f'{host}'
        )

    @staticmethod
    def get_conversion_der_pem_command(cred_number: int) -> str:
        """Get the conversion DER to PEM command.

        Args:
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.
        """
        return (
            'openssl x509 \\\n'
            '-inform DER \\\n'
            '-outform PEM \\\n'
            f'-in certificate-{cred_number}.der \\\n'
            f'-out certificate-{cred_number}.pem'
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
            f'-o domain-credential-certificate.der \\\n'
            f'{host}'
        )

    @staticmethod
    def get_domain_credential_conversion_der_pem_command() -> str:
        """Get the domain credential conversion DER to PEM command.

        Returns:
             The constructed command.
        """
        return (
            'openssl x509 \\\n'
            '-inform DER \\\n'
            '-outform PEM \\\n'
            '-in domain-credential-certificate.der \\\n'
            '-out domain-credential-certificate.pem'
        )


class CmpClientCertificateCommandBuilder:
    """Builds CMP client-certificate commands for different certificate profiles."""

    @staticmethod
    def get_tls_client_profile_command(host: str, cred_number: int) -> str:
        """Gets the TLS-Client profile command.

        Args:
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./cmp/p/...
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.
        """
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            '-tls_used \\\n'
            '-trusted domain-credential-full-chain.pem \\\n'
            f'-server  {host} \\\n'
            '-cert domain-credential-certificate.pem \\\n'
            '-key domain-credential-key.pem \\\n'
            f'-subject "/CN=Trustpoint-TLS-Client-Credential-{cred_number}" \\\n'
            '-days 10 \\\n'
            f'-newkey key-{cred_number}.pem \\\n'
            f'-certout certificate-{cred_number}.pem \\\n'
            f'-chainout chain-{cred_number}.pem \\\n'
            f'-extracertsout full-chain-{cred_number}.pem'
        )

    @staticmethod
    def get_tls_server_profile_command(host: str, cred_number: int) -> str:
        """Gets the TLS-Server profile command.

        Args:
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./cmp/p/...
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.
        """
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            '-tls_used \\\n'
            '-trusted domain-credential-full-chain.pem \\\n'
            f'-server {host} \\\n'
            '-cert domain-credential-certificate.pem \\\n'
            '-key domain-credential-key.pem \\\n'
            f'-subject "/CN=Trustpoint-TLS-Server-Client-Credential-{cred_number}" \\\n'
            '-days 10 \\\n'
            '-sans "critical 127.0.0.1 ::1 localhost" \\\n'
            f'-newkey key-{cred_number}.pem \\\n'
            f'-certout certificate-{cred_number}.pem \\\n'
            f'-chainout chain-{cred_number}.pem \\\n'
            f'-extracertsout full-chain-{cred_number}.pem'
        )

    @staticmethod
    def get_opc_ua_client_profile_command(host: str, cred_number: int) -> str:
        """Gets the OPC-UA-Client profile command.

        Args:
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./cmp/p/...
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.
        """
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            '-tls_used \\\n'
            '-trusted domain-credential-full-chain.pem \\\n'
            f'-server  {host} \\\n'
            '-cert domain-credential-certificate.pem \\\n'
            '-key domain-credential-key.pem \\\n'
            f'-subject "/CN=Trustpoint-OPC-UA-Client-Credential-{cred_number}" \\\n'
            '-days 10 \\\n'
            f'-sans "critical URI:trustpoint.opc-ua-uri.de/credential-{cred_number}" \\\n'
            f'-newkey key-{cred_number}.pem \\\n'
            f'-certout certificate-{cred_number}.pem \\\n'
            f'-chainout chain-{cred_number}.pem \\\n'
            f'-extracertsout full-chain-{cred_number}.pem'
        )

    @staticmethod
    def get_opc_ua_server_profile_command(host: str, cred_number: int) -> str:
        """Gets the OPC-UA-Server profile command.

        Args:
            host: The full host name and url path, e.g. https://127.0.0.1/.well-known./cmp/p/...
            cred_number: The credential number - counter of issued credentials.

        Returns:
            The constructed command.
        """
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            '-tls_used \\\n'
            '-trusted domain-credential-full-chain.pem \\\n'
            f'-server {host} \\\n'
            '-cert domain-credential-certificate.pem \\\n'
            '-key domain-credential-key.pem \\\n'
            f'-subject "/CN=Trustpoint-OPC-UA-Server-Client-Credential-{cred_number}" \\\n'
            '-days 10 \\\n'
            f'-sans "critical 127.0.0.1 ::1 localhost URI::trustpoint.opc-ua-uri.de/credential-{cred_number}" \\\n'
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
            f'-o certificate-{cred_number}.der \\\n'
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
