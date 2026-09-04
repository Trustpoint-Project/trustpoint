# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Test cases for help_pages commands module."""

from unittest.mock import Mock

from django.test import SimpleTestCase
from trustpoint_core import oid

from ..commands import (
    AokiCmpIDevIDCommandBuilder,
    AokiEstIDevIDCommandBuilder,
    CmpClientCertificateCommandBuilder,
    CmpSharedSecretCommandBuilder,
    EstClientCertificateCommandBuilder,
    EstUsernamePasswordCommandBuilder,
    KeyGenCommandBuilder,
    RestClientCertificateCommandBuilder,
    RestUsernamePasswordCommandBuilder,
)


class KeyGenCommandBuilderTests(SimpleTestCase):
    """Test cases for KeyGenCommandBuilder."""

    def test_get_key_gen_command_rsa(self) -> None:
        """Test RSA key generation command."""
        public_key_info = oid.PublicKeyInfo(
            public_key_algorithm_oid=oid.PublicKeyAlgorithmOid.RSA,
            key_size=2048,
        )

        cmd = KeyGenCommandBuilder.get_key_gen_command(public_key_info, cred_number=1)

        assert 'openssl genrsa' in cmd
        assert '-out key-1.pem' in cmd
        assert '2048' in cmd

    def test_get_key_gen_command_rsa_custom_filename(self) -> None:
        """Test RSA key generation command with custom filename."""
        public_key_info = oid.PublicKeyInfo(
            public_key_algorithm_oid=oid.PublicKeyAlgorithmOid.RSA,
            key_size=4096,
        )

        cmd = KeyGenCommandBuilder.get_key_gen_command(
            public_key_info, cred_number=1, key_name='custom-key.pem'
        )

        assert 'openssl genrsa' in cmd
        assert '-out custom-key.pem' in cmd
        assert '4096' in cmd

    def test_get_key_gen_command_ecc(self) -> None:
        """Test ECC key generation command."""
        public_key_info = oid.PublicKeyInfo(
            public_key_algorithm_oid=oid.PublicKeyAlgorithmOid.ECC,
            named_curve=oid.NamedCurve.SECP256R1,
        )

        cmd = KeyGenCommandBuilder.get_key_gen_command(public_key_info, cred_number=2)

        assert 'openssl ecparam' in cmd
        assert '-name prime256v1' in cmd  # OpenSSL uses prime256v1 for secp256r1
        assert '-genkey' in cmd
        assert '-noout' in cmd
        assert '-out key-2.pem' in cmd

    def test_get_key_gen_command_ecc_custom_filename(self) -> None:
        """Test ECC key generation command with custom filename."""
        public_key_info = oid.PublicKeyInfo(
            public_key_algorithm_oid=oid.PublicKeyAlgorithmOid.ECC,
            named_curve=oid.NamedCurve.SECP384R1,
        )

        cmd = KeyGenCommandBuilder.get_key_gen_command(
            public_key_info, cred_number=3, key_name='ec-key.pem'
        )

        assert 'openssl ecparam' in cmd
        assert '-name secp384r1' in cmd
        assert '-out ec-key.pem' in cmd

    def test_get_key_gen_command_ecc_secp384(self) -> None:
        """Test ECC key generation command with secp384r1."""
        public_key_info = oid.PublicKeyInfo(
            public_key_algorithm_oid=oid.PublicKeyAlgorithmOid.ECC,
            named_curve=oid.NamedCurve.SECP384R1,
        )

        cmd = KeyGenCommandBuilder.get_key_gen_command(public_key_info, cred_number=1)

        assert 'openssl ecparam' in cmd
        assert '-name secp384r1' in cmd

    def test_get_key_gen_command_ecc_without_named_curve_raises(self) -> None:
        """Test ECC key generation requires a named curve."""
        public_key_info = Mock(public_key_algorithm_oid=oid.PublicKeyAlgorithmOid.ECC, named_curve=None)

        with self.assertRaises(ValueError) as cm:
            KeyGenCommandBuilder.get_key_gen_command(public_key_info, cred_number=1)

        assert 'named curve' in str(cm.exception)

    def test_get_key_gen_command_mldsa_variants(self) -> None:
        """Test post-quantum ML-DSA key generation variants."""
        expected_algorithms = {
            oid.PublicKeyAlgorithmOid.ML_DSA_44: 'ML-DSA-44',
            oid.PublicKeyAlgorithmOid.ML_DSA_65: 'ML-DSA-65',
            oid.PublicKeyAlgorithmOid.ML_DSA_87: 'ML-DSA-87',
        }

        for algorithm_oid, openssl_algorithm in expected_algorithms.items():
            public_key_info = oid.PublicKeyInfo(public_key_algorithm_oid=algorithm_oid)
            cmd = KeyGenCommandBuilder.get_key_gen_command(public_key_info, cred_number=7)

            assert f'openssl genpkey -algorithm {openssl_algorithm}' in cmd
            assert '-out key-7.pem' in cmd

    def test_get_key_gen_command_unsupported_algorithm_raises(self) -> None:
        """Test unsupported key algorithms fail explicitly."""
        public_key_info = oid.PublicKeyInfo(public_key_algorithm_oid=object())

        with self.assertRaises(ValueError) as cm:
            KeyGenCommandBuilder.get_key_gen_command(public_key_info, cred_number=1)

        assert 'Unsupported public key algorithm' in str(cm.exception)


class CmpSharedSecretCommandBuilderTests(SimpleTestCase):
    """Test cases for CmpSharedSecretCommandBuilder."""

    def test_get_domain_credential_profile_command(self) -> None:
        """Test domain credential profile command."""
        cmd = CmpSharedSecretCommandBuilder.get_domain_credential_profile_command(
            host='https://127.0.0.1/.well-known/cmp/p/test',
            pk=123,
            shared_secret='secret123',
        )

        assert 'openssl cmp' in cmd
        assert '-cmd ir' in cmd
        assert '-tls_used' in cmd
        assert '-server https://127.0.0.1/.well-known/cmp/p/test' in cmd
        assert '-ref 123' in cmd
        assert '-secret pass:secret123' in cmd
        assert '-subject "/CN=Trustpoint-Domain-Credential"' in cmd
        assert 'domain-credential-key.pem' in cmd
        assert 'domain-credential-certificate.pem' in cmd

    def test_get_dynamic_cert_profile_command(self) -> None:
        """Test dynamic certificate profile command."""
        # Use proper validity format
        sample_request = {
            'subject': {'CN': 'Test Device', 'O': 'Test Org'},
            'validity': {'days': 365},
            'subject_alternative_names': {'dns': ['device.example.com']},
        }

        cmd = CmpSharedSecretCommandBuilder.get_dynamic_cert_profile_command(
            host='https://127.0.0.1/.well-known/cmp/p/test',
            pk=456,
            shared_secret='secret456',
            cred_number=2,
            sample_request=sample_request,
        )

        assert 'openssl cmp' in cmd
        assert '-cmd cr' in cmd
        assert '-tls_used' in cmd
        assert '-server https://127.0.0.1/.well-known/cmp/p/test' in cmd
        assert '-ref 456' in cmd
        assert '-secret pass:secret456' in cmd
        assert 'key-2.pem' in cmd
        assert 'certificate-2.pem' in cmd

    def test_get_dynamic_cert_profile_command_without_sans(self) -> None:
        """Test dynamic certificate profile command without SANs."""
        sample_request = {
            'subject': {'CN': 'Test Device'},
            'validity': {'days': 180},
        }

        cmd = CmpSharedSecretCommandBuilder.get_dynamic_cert_profile_command(
            host='https://127.0.0.1/.well-known/cmp/p/test',
            pk=789,
            shared_secret='secret789',
            cred_number=3,
            sample_request=sample_request,
        )

        assert 'openssl cmp' in cmd
        assert '-ref 789' in cmd
        assert cmd is not None

    def test_get_app_cert_self_revoke_command(self) -> None:
        """Test CMP self-revocation command uses local credential files."""
        cmd = CmpSharedSecretCommandBuilder.get_app_cert_self_revoke_command(
            host='https://127.0.0.1/.well-known/cmp/p/test/revocation',
            cred_number=4,
        )

        assert '-cmd rr' in cmd
        assert '-cert certificate-4.pem' in cmd
        assert '-key key-4.pem' in cmd
        assert '-oldcert certificate-4.pem' in cmd
        assert '-revreason 0' in cmd
        assert '-trusted full-chain-4.pem' in cmd


class EstUsernamePasswordCommandBuilderTests(SimpleTestCase):
    """Test cases for EstUsernamePasswordCommandBuilder."""

    def test_get_dynamic_cert_profile_command(self) -> None:
        """Test dynamic certificate profile command."""
        sample_request = {
            'subject': {'CN': 'Test Device', 'O': 'Test Org'},
            'subject_alternative_names': {'dns': ['device.example.com']},
        }

        cmd = EstUsernamePasswordCommandBuilder.get_dynamic_cert_profile_command(
            cred_number=1,
            sample_request=sample_request,
        )

        assert 'openssl req' in cmd
        assert '-new' in cmd
        assert '-key key-1.pem' in cmd
        assert '-outform DER' in cmd
        assert '-out csr-1.der' in cmd

    def test_get_dynamic_cert_profile_command_without_sans(self) -> None:
        """Test dynamic certificate profile command without SANs."""
        sample_request = {
            'subject': {'CN': 'Test Device'},
        }

        cmd = EstUsernamePasswordCommandBuilder.get_dynamic_cert_profile_command(
            cred_number=2,
            sample_request=sample_request,
        )

        assert 'openssl req' in cmd
        assert '-key key-2.pem' in cmd
        assert '-out csr-2.der' in cmd

    def test_get_curl_enroll_command(self) -> None:
        """Test curl enroll command."""
        cmd = EstUsernamePasswordCommandBuilder.get_curl_enroll_command(
            est_username='testuser',
            est_password='testpass',
            host='https://127.0.0.1/.well-known/est/test',
            cred_number=1,
        )

        assert 'curl' in cmd
        assert 'testuser:testpass' in cmd
        assert 'https://127.0.0.1/.well-known/est/test' in cmd
        assert 'csr-1.der' in cmd

    def test_get_conversion_p7_pem_windows_command(self) -> None:
        """Test Windows PKCS#7 to PEM conversion command."""
        cmd = EstUsernamePasswordCommandBuilder.get_conversion_p7_pem_windows_command(cred_number=1)

        assert 'certutil -f -decode certificate-1.p7c certificate-1.p7b' in cmd
        assert 'openssl pkcs7 -inform DER -in certificate-1.p7b -print_certs -out certificate-1.pem' in cmd

    def test_get_curl_enroll_windows_command(self) -> None:
        """Test Windows-friendly EST curl command."""
        cmd = EstUsernamePasswordCommandBuilder.get_curl_enroll_windows_command(
            est_username='device-1',
            est_password='secret-value',
            host='https://example.test/.well-known/est/domain/app/simpleenroll',
            cred_number=5,
        )

        assert cmd.startswith('curl.exe --user "device-1:secret-value" ^')
        assert '--data-binary "@csr-5.der"' in cmd
        assert '-o certificate-5.p7c' in cmd

    def test_get_domain_credential_est_commands(self) -> None:
        """Test EST username/password domain credential command helpers."""
        csr_cmd = EstUsernamePasswordCommandBuilder.get_domain_credential_profile_command()
        enroll_cmd = EstUsernamePasswordCommandBuilder.get_curl_enroll_domain_credential_command(
            est_username='device-1',
            est_password='secret-value',
            host='https://example.test/.well-known/est/domain/domain_credential/simpleenroll/',
        )
        convert_cmd = EstUsernamePasswordCommandBuilder.get_domain_credential_conversion_p7_pem_command()

        assert '-out csr-domain-credential.der' in csr_cmd
        assert '--user "device-1:secret-value"' in enroll_cmd
        assert '@csr-domain-credential.der' in enroll_cmd
        assert 'domain-credential-certificate.p7c' in enroll_cmd
        assert 'domain-credential-certificate.pem' in convert_cmd


class CmpClientCertificateCommandBuilderTests(SimpleTestCase):
    """Test cases for CmpClientCertificateCommandBuilder."""

    def test_get_idevid_domain_credential_command(self) -> None:
        """Test idevid domain credential command."""
        cmd = CmpClientCertificateCommandBuilder.get_idevid_domain_credential_command(
            host='https://127.0.0.1/.well-known/cmp/p/test',
        )

        assert 'openssl cmp' in cmd
        assert '-cmd ir' in cmd
        assert '-tls_used' in cmd
        assert '-server https://127.0.0.1/.well-known/cmp/p/test' in cmd
        assert 'domain_credential_key.pem' in cmd
        assert 'domain_credential_cert.pem' in cmd

    def test_get_dynamic_cert_profile_command(self) -> None:
        """Test dynamic certificate profile command."""
        sample_request = {
            'subject': {'CN': 'Test Device'},
            'validity': {'days': 365},
        }

        cmd = CmpClientCertificateCommandBuilder.get_dynamic_cert_profile_command(
            host='https://127.0.0.1/.well-known/cmp/p/test',
            cred_number=1,
            sample_request=sample_request,
        )

        assert 'openssl cmp' in cmd
        assert '-cmd cr' in cmd
        assert '-tls_used' in cmd
        assert '-server https://127.0.0.1/.well-known/cmp/p/test' in cmd
        assert 'key-1.pem' in cmd
        assert 'certificate-1.pem' in cmd


class EstClientCertificateCommandBuilderTests(SimpleTestCase):
    """Test cases for EstClientCertificateCommandBuilder."""

    def test_get_domain_credential_profile_command(self) -> None:
        """Test domain credential profile command."""
        cmd = EstClientCertificateCommandBuilder.get_domain_credential_profile_command()

        assert 'openssl req' in cmd
        assert '-new' in cmd
        assert '-key domain-credential-key.pem' in cmd
        assert '-outform DER' in cmd
        assert '-out csr-domain-credential.der' in cmd

    def test_get_curl_enroll_application_credential(self) -> None:
        """Test curl enroll application credential command."""
        cmd = EstClientCertificateCommandBuilder.get_curl_enroll_application_credential(
            cred_number=1,
            host='https://127.0.0.1/.well-known/est/test',
        )

        assert 'curl' in cmd
        assert 'https://127.0.0.1/.well-known/est/test' in cmd
        assert 'csr-1.der' in cmd
        assert 'certificate-1.p7c' in cmd

    def test_get_idevid_gen_csr_command(self) -> None:
        """Test idevid gen CSR command."""
        cmd = EstClientCertificateCommandBuilder.get_idevid_gen_csr_command()

        assert 'openssl req' in cmd
        assert '-new' in cmd
        assert '-key idevid.key' in cmd
        assert '-outform der' in cmd

    def test_get_idevid_ca_certs_command(self) -> None:
        """Test idevid ca certs command."""
        cmd = EstClientCertificateCommandBuilder.get_idevid_ca_certs_command(
            host='https://127.0.0.1/.well-known/est/test/cacerts'
        )

        assert 'curl' in cmd
        assert 'https://127.0.0.1/.well-known/est/test/cacerts' in cmd

    def test_get_idevid_enroll_and_conversion_commands(self) -> None:
        """Test EST IDevID enrollment and conversion command helpers."""
        enroll_cmd = EstClientCertificateCommandBuilder.get_idevid_enroll_domain_credential_command(
            host='https://example.test/.well-known/est/domain/simpleenroll',
        )
        der_cmd = EstClientCertificateCommandBuilder.get_idevid_der_pem_conversion_command()
        pkcs7_cmd = EstClientCertificateCommandBuilder.get_idevid_pkcs7_pem_conversion_command()

        assert '--cert idevid.pem' in enroll_cmd
        assert '--key idevid.key' in enroll_cmd
        assert '@domain_credential_csr.der' in enroll_cmd
        assert 'openssl x509' in der_cmd
        assert '-inform der' in der_cmd
        assert 'openssl pkcs7' in pkcs7_cmd
        assert '-in cacerts.p7b' in pkcs7_cmd


class AokiCmpIDevIDCommandBuilderTests(SimpleTestCase):
    """Test cases for AOKI CMP command builders."""

    def test_get_keygen_command(self) -> None:
        """Test AOKI CMP domain credential key generation."""
        cmd = AokiCmpIDevIDCommandBuilder.get_keygen_command()

        assert 'openssl genrsa' in cmd
        assert 'domain_credential_key.pem' in cmd
        assert '2048' in cmd

    def test_get_cmp_ir_command(self) -> None:
        """Test AOKI CMP initial request command."""
        cmd = AokiCmpIDevIDCommandBuilder.get_cmp_ir_command('https://example.test/cmp/init')

        assert '-cmd ir' in cmd
        assert '-server https://example.test/cmp/init' in cmd
        assert '-cert idevid.pem' in cmd
        assert '-trusted ownerid_ca.pem' in cmd


class AokiEstIDevIDCommandBuilderTests(SimpleTestCase):
    """Test cases for AOKI EST command builders."""

    def test_get_aoki_init_command_and_response_example(self) -> None:
        """Test AOKI EST initialization command and response sample."""
        cmd = AokiEstIDevIDCommandBuilder.get_aoki_init_command('https://example.test')
        response_example = AokiEstIDevIDCommandBuilder.get_aoki_init_response_example('domain_credential_custom')

        assert 'curl --cert idevid.pem' in cmd
        assert 'https://example.test/aoki/init' in cmd
        assert '"protocol": "EST"' in response_example
        assert 'domain_credential_custom/simpleenroll' in response_example

    def test_get_est_enrollment_commands(self) -> None:
        """Test AOKI EST key, CSR, and enrollment commands."""
        key_cmd = AokiEstIDevIDCommandBuilder.get_keygen_command()
        csr_cmd = AokiEstIDevIDCommandBuilder.get_csr_command()
        enroll_cmd = AokiEstIDevIDCommandBuilder.get_curl_enroll_command('https://example.test/est/enroll')

        assert 'domain_credential_key.pem' in key_cmd
        assert '-outform DER' in csr_cmd
        assert '-out domain_credential.der' in csr_cmd
        assert '--cert domain-credential-cert.pem' in enroll_cmd
        assert '@domain_credential.der' in enroll_cmd


class RestUsernamePasswordCommandBuilderTests(SimpleTestCase):
    """Test cases for REST username/password command builders."""

    def test_get_dynamic_cert_profile_command_with_sans(self) -> None:
        """Test REST CSR generation for application certificates."""
        sample_request = {
            'subject': {'CN': 'Device 1'},
            'extensions': {
                'subject_alternative_name': {
                    'dns_names': ['device.example.test'],
                },
            },
        }

        cmd = RestUsernamePasswordCommandBuilder.get_dynamic_cert_profile_command(
            cred_number=3,
            sample_request=sample_request,
        )

        assert 'openssl req' in cmd
        assert '-key key-3.pem' in cmd
        assert '-out csr-3.pem' in cmd
        assert 'subjectAltName' in cmd

    def test_get_rest_enroll_and_extract_commands(self) -> None:
        """Test REST username/password enrollment helpers."""
        enroll_cmd = RestUsernamePasswordCommandBuilder.get_curl_enroll_command(
            rest_username='device-1',
            rest_password='secret-value',
            host='https://example.test/rest/domain/profile/enroll/',
            cred_number=3,
        )
        extract_cmd = RestUsernamePasswordCommandBuilder.get_extract_cert_command(cred_number=3)

        assert '--user "device-1:secret-value"' in enroll_cmd
        assert 'Content-Type: application/json' in enroll_cmd
        assert 'csr-3.pem' in enroll_cmd
        assert 'certificate-3.json' in enroll_cmd
        assert extract_cmd == 'jq -r .certificate certificate-3.json > certificate-3.pem'

    def test_get_domain_credential_rest_commands(self) -> None:
        """Test REST username/password domain credential helpers."""
        csr_cmd = RestUsernamePasswordCommandBuilder.get_domain_credential_csr_command()
        enroll_cmd = RestUsernamePasswordCommandBuilder.get_curl_enroll_domain_credential_command(
            rest_username='device-1',
            rest_password='secret-value',
            host='https://example.test/rest/domain/domain_credential/enroll/',
        )
        extract_cmd = RestUsernamePasswordCommandBuilder.get_extract_domain_credential_command()

        assert 'csr-domain-credential.pem' in csr_cmd
        assert '--user "device-1:secret-value"' in enroll_cmd
        assert 'domain-credential-certificate.json' in enroll_cmd
        assert extract_cmd.endswith('domain-credential-certificate.pem')


class RestClientCertificateCommandBuilderTests(SimpleTestCase):
    """Test cases for REST mTLS command builders."""

    def test_get_dynamic_cert_profile_command_without_sans(self) -> None:
        """Test REST mTLS CSR generation without SANs."""
        cmd = RestClientCertificateCommandBuilder.get_dynamic_cert_profile_command(
            cred_number=6,
            sample_request={'subject': {'CN': 'Device 6'}},
        )

        assert '-key key-6.pem' in cmd
        assert '-out csr-6.pem' in cmd
        assert 'subjectAltName' not in cmd

    def test_get_curl_enroll_and_reenroll_commands_include_dev_header(self) -> None:
        """Test REST mTLS curl commands include the development client-cert header."""
        enroll_cmd = RestClientCertificateCommandBuilder.get_curl_enroll_command(
            host='https://example.test/rest/domain/profile/enroll/',
            cred_number=6,
        )
        reenroll_cmd = RestClientCertificateCommandBuilder.get_curl_reenroll_command(
            host='https://example.test/rest/domain/profile/reenroll/',
            cred_number=6,
        )

        assert 'SSL-CLIENT-CERT: ${CERT_HEADER}' in enroll_cmd
        assert 'certificate-6.json' in enroll_cmd
        assert 'https://example.test/rest/domain/profile/enroll/' in enroll_cmd
        assert 'SSL-CLIENT-CERT: ${CERT_HEADER}' in reenroll_cmd
        assert 'https://example.test/rest/domain/profile/reenroll/' in reenroll_cmd

    def test_get_extract_response_commands(self) -> None:
        """Test REST mTLS JSON extraction commands."""
        assert RestClientCertificateCommandBuilder.get_extract_cert_command(8) == (
            'jq -r .certificate certificate-8.json > certificate-8.pem'
        )
        assert RestClientCertificateCommandBuilder.get_extract_cert_chain_command(8) == (
            "jq -r '.certificate_chain[]' certificate-8.json > certificate-chain-8.pem"
        )