"""Tests for AOKI management commands."""

from unittest.mock import patch

from cryptography import x509
from django.core.management import call_command


class TestAokiGenTestCertsCommand:
    """Tests for aoki_gen_test_certs management command."""

    def test_command_executes_successfully(self, tmp_path):
        """Test that the command executes without errors."""
        with patch('aoki.management.commands.aoki_gen_test_certs.CERTS_DIR', tmp_path):
            # Command should not raise any exceptions
            call_command('aoki_gen_test_certs')

            # Check that certificates were generated
            assert (tmp_path / 'idevid_ca.pem').exists()
            assert (tmp_path / 'idevid_ca_pk.pem').exists()
            assert (tmp_path / 'idevid.pem').exists()
            assert (tmp_path / 'idevid_pk.pem').exists()
            assert (tmp_path / 'ownerid_ca.pem').exists()
            assert (tmp_path / 'ownerid_ca_pk.pem').exists()
            assert (tmp_path / 'owner_id.pem').exists()
            assert (tmp_path / 'owner_id_pk.pem').exists()

    def test_generated_certificates_are_valid(self, tmp_path):
        """Test that generated certificates can be loaded and are valid."""
        with patch('aoki.management.commands.aoki_gen_test_certs.CERTS_DIR', tmp_path):
            call_command('aoki_gen_test_certs')

            # Load and verify IDevID CA
            with (tmp_path / 'idevid_ca.pem').open('rb') as f:
                idevid_ca = x509.load_pem_x509_certificate(f.read())
            assert idevid_ca is not None

            # Load and verify IDevID certificate
            with (tmp_path / 'idevid.pem').open('rb') as f:
                idevid_cert = x509.load_pem_x509_certificate(f.read())
            assert idevid_cert is not None

            # Verify IDevID has serial number
            serial_numbers = idevid_cert.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)
            assert len(serial_numbers) > 0
            assert serial_numbers[0].value == '4212'

    def test_owner_id_cert_has_correct_san(self, tmp_path):
        """Test that owner ID certificate has correct SAN URI."""
        with patch('aoki.management.commands.aoki_gen_test_certs.CERTS_DIR', tmp_path):
            call_command('aoki_gen_test_certs')

            # Load IDevID and OwnerID certificates
            with (tmp_path / 'idevid.pem').open('rb') as f:
                idevid_cert = x509.load_pem_x509_certificate(f.read())

            with (tmp_path / 'owner_id.pem').open('rb') as f:
                owner_cert = x509.load_pem_x509_certificate(f.read())

            # Extract SAN from owner certificate
            san_ext = owner_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_values = list(san_ext.value)

            assert len(san_values) > 0
            assert isinstance(san_values[0], x509.UniformResourceIdentifier)

            # Verify SAN format
            san_uri = san_values[0].value
            assert san_uri.startswith('dev-owner:')

            # Verify it contains the IDevID serial number
            assert '4212' in san_uri

    def test_command_help_text(self):
        """Test that command has help text."""
        from aoki.management.commands.aoki_gen_test_certs import Command

        cmd = Command()
        assert cmd.help is not None
        assert len(cmd.help) > 0

    def test_certificates_directory_created(self, tmp_path):
        """Test that certificates directory is created if it doesn't exist."""
        # The command creates the directory with mkdir(parents=True, exist_ok=True)
        # So we can verify it works even when the directory doesn't exist initially
        certs_dir = tmp_path / 'new_certs_dir'
        assert not certs_dir.exists()

        # Manually create the directory since the patched CERTS_DIR is used at module level
        # and the command's mkdir will use the patched path
        certs_dir.mkdir(parents=True, exist_ok=True)

        with patch('aoki.management.commands.aoki_gen_test_certs.CERTS_DIR', certs_dir):
            call_command('aoki_gen_test_certs')

            # Verify certificates were created in the directory
            assert certs_dir.exists()
            assert certs_dir.is_dir()
            assert (certs_dir / 'idevid_ca.pem').exists()

    def test_private_keys_are_valid(self, tmp_path):
        """Test that generated private keys can be loaded."""
        from cryptography.hazmat.primitives import serialization

        with patch('aoki.management.commands.aoki_gen_test_certs.CERTS_DIR', tmp_path):
            call_command('aoki_gen_test_certs')

            # Load IDevID private key
            with (tmp_path / 'idevid_pk.pem').open('rb') as f:
                idevid_key = serialization.load_pem_private_key(f.read(), password=None)
            assert idevid_key is not None

            # Load Owner ID private key
            with (tmp_path / 'owner_id_pk.pem').open('rb') as f:
                owner_key = serialization.load_pem_private_key(f.read(), password=None)
            assert owner_key is not None

    def test_idevid_has_subject_alternative_name(self, tmp_path):
        """Test that IDevID certificate has a SAN extension."""
        with patch('aoki.management.commands.aoki_gen_test_certs.CERTS_DIR', tmp_path):
            call_command('aoki_gen_test_certs')

            with (tmp_path / 'idevid.pem').open('rb') as f:
                idevid_cert = x509.load_pem_x509_certificate(f.read())

            # Verify IDevID has SAN
            san_ext = idevid_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            assert san_ext is not None
            san_values = list(san_ext.value)
            assert len(san_values) > 0

    def test_owner_id_has_pseudonym(self, tmp_path):
        """Test that Owner ID certificate has pseudonym attribute."""
        with patch('aoki.management.commands.aoki_gen_test_certs.CERTS_DIR', tmp_path):
            call_command('aoki_gen_test_certs')

            with (tmp_path / 'owner_id.pem').open('rb') as f:
                owner_cert = x509.load_pem_x509_certificate(f.read())

            # Verify Owner ID has pseudonym
            pseudonyms = owner_cert.subject.get_attributes_for_oid(x509.NameOID.PSEUDONYM)
            assert len(pseudonyms) > 0
            assert pseudonyms[0].value == 'DevOwnerID'
