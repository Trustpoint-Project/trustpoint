"""Test cases for help_pages commands module."""

from django.test import SimpleTestCase
from trustpoint_core import oid

from ..commands import (
    CmpClientCertificateCommandBuilder,
    CmpSharedSecretCommandBuilder,
    EstClientCertificateCommandBuilder,
    EstUsernamePasswordCommandBuilder,
    KeyGenCommandBuilder,
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
        assert '-implicit_confirm' in cmd
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
        assert '-implicit_confirm' in cmd
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


class CmpClientCertificateCommandBuilderTests(SimpleTestCase):
    """Test cases for CmpClientCertificateCommandBuilder."""

    def test_get_idevid_domain_credential_command(self) -> None:
        """Test idevid domain credential command."""
        cmd = CmpClientCertificateCommandBuilder.get_idevid_domain_credential_command(
            host='https://127.0.0.1/.well-known/cmp/p/test',
        )

        assert 'openssl cmp' in cmd
        assert '-cmd ir' in cmd
        assert '-implicit_confirm' in cmd
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
        assert '-implicit_confirm' in cmd
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
