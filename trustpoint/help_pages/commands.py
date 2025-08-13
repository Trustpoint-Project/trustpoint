"""This module contains cli commands which are displayed in the help pages."""

from devices.views import NamedCurveMissingForEccErrorMsg
from trustpoint_core import oid


class KeyGenCommandBuilder:

    @staticmethod
    def get_key_gen_command(public_key_info: oid.PublicKeyInfo, file_name: str) -> str:

        if public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            return f'openssl genrsa -out key.pem {public_key_info.key_size}'

        if public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            if not public_key_info.named_curve:
                raise ValueError(NamedCurveMissingForEccErrorMsg)
            return (
                f'openssl ecparam -name {public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out {file_name}'
            )

        err_msg = _('Unsupported public key algorithm')
        raise ValueError(err_msg)


class CmpSharedSecretCommandBuilder:

    @staticmethod
    def get_tls_client_profile_command(host: str, pk: int, shared_secret: str, cred_number: int) -> str:
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            f'-server  { host } \\\n'
            '-tls_used \\\n'
            f'-ref { pk } \\\n'
            f'-secret pass:{ shared_secret } \\\n'
            f'-subject "/CN=Trustpoint-TLS-Client-Credential-{ cred_number }" \\\n'
            '-days 10 \\\n'
            '-newkey key.pem \\\n'
            '-certout cert.pem \\\n'
            '-chainout chain_without_root.pem \\\n'
            '-extracertsout full_chain.pem'
        )

    @staticmethod
    def get_tls_server_provile_command(host: str, pk: int, shared_secret: str, cred_number: int) -> str:
        return (
            'openssl cmp \\\n'
            '-cmd cr \\\n'
            '-implicit_confirm \\\n'
            f'-server { host } \\\n'
            '-tls_used \\\n'
            f'-ref { pk } \\\n'
            f'-secret pass:{ shared_secret } \\\n'
            f'-subject "/CN=Trustpoint-TLS-Server-Client-Credential-{ cred_number }" \\\n'
            '-days 10 \\\n'
            '-sans "critical 127.0.0.1 ::1 localhost" \\\n'
            '-newkey key.pem \\\n'
            '-certout cert.pem \\\n'
            '-chainout chain_without_root.pem \\\n'
            '-extracertsout full_chain.pem'
        )


# https://{{ host }}/.well-known/cmp/certification/{{ device.domain }}/tls-server/
# https://{{ host }}/.well-known/cmp/certification/{{ device.domain }}/tls-server/