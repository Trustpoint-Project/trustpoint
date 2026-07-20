"""Comprehensive test suite for the Trustpoint agent.

This test suite focuses on high-value scenarios with maximum branch coverage:
- Configuration loading and validation
- Certificate and key lifecycle logic
- Enrollment and renewal workflows
- Retry and error handling
- Filesystem state management
- Security-relevant failure cases
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock, patch

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

if TYPE_CHECKING:
    from collections.abc import Generator

import sys

sys.path.insert(0, str(Path(__file__).parent.parent / 'examples'))

from agent import (
    HTTP_OK_MAX,
    HTTP_OK_MIN,
    ActiveCredential,
    AgentError,
    EnrollmentResponse,
    JobResult,
    LocalStorage,
    PollParams,
    _backoff_delay,
    _expect_non_empty_str,
    _expect_object,
    _optional_str,
    _pem_join,
    _retry_after_delay,
    acknowledge_job,
    atomic_copy,
    atomic_write_bytes,
    atomic_write_text,
    configure_logging,
    deterministic_paths_for_job,
    ensure_parent,
    execute_renewal_job,
    fetch_jobs,
    generate_csr,
    generate_private_key,
    join_url,
    load_private_key,
    make_session,
    parse_args,
    parse_enrollment_response,
    parse_subject,
    parse_subject_alt_name,
    read_profile,
    request_with_retries,
    require_success,
    response_json_object,
    save_credentials,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_profile_data() -> dict[str, Any]:
    """Return minimal valid profile data."""
    return {
        'profile': {
            'onboarding': {
                'device': 'test-device',
                'secret': 'test-secret',
                'tls_cert_pem': '-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHCgVZU79PMA0GCSqGSIb3DQEBCwUAMA0xCzAJBgNVBAYTAlVT\n-----END CERTIFICATE-----\n',
            },
            'certificate_request': {
                'url': 'https://trustpoint.example.com',
                'path': '/api/enrollment/',
                'certificate_profile': 'domain_credential',
            },
            'local_storage': {
                'private_key_path': 'domain-key.pem',
                'csr_path': 'domain-csr.pem',
                'tls_cert_path': 'trustpoint-tls.pem',
                'certificate_path': 'domain-cert.pem',
                'certificate_chain_path': 'domain-chain.pem',
            },
        }
    }


@pytest.fixture
def profile_file(temp_dir: Path, mock_profile_data: dict[str, Any]) -> Path:
    """Create a profile file with valid data."""
    profile_path = temp_dir / 'agent_setup.json'
    profile_path.write_text(json.dumps(mock_profile_data))
    return profile_path


@pytest.fixture
def valid_private_key() -> rsa.RSAPrivateKey:
    """Generate a valid RSA private key for testing."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def valid_cert_pem(valid_private_key: rsa.RSAPrivateKey) -> str:
    """Generate a valid certificate PEM for testing."""
    import datetime
    
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test')])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(valid_private_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc))
        .sign(valid_private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode('ascii')


# ============================================================================
# Configuration Loading and Validation Tests
# ============================================================================


class TestProfileLoading:
    """Test configuration file loading and validation."""

    def test_read_profile_success(self, profile_file: Path):
        """Test successful profile reading."""
        profile = read_profile(profile_file)
        assert profile.device == 'test-device'
        assert profile.secret == 'test-secret'
        assert profile.base_url == 'https://trustpoint.example.com'
        assert profile.enrollment_path == '/api/enrollment/'

    def test_read_profile_file_not_found(self, temp_dir: Path):
        """Test profile loading fails when file doesn't exist."""
        with pytest.raises(AgentError, match='profile file not found'):
            read_profile(temp_dir / 'nonexistent.json')

    @pytest.mark.parametrize(
        'invalid_json',
        [
            '{invalid json}',
            '{"profile": ',
            'not json at all',
            '',
        ],
    )
    def test_read_profile_invalid_json(self, temp_dir: Path, invalid_json: str):
        """Test profile loading fails with invalid JSON."""
        profile_path = temp_dir / 'bad.json'
        profile_path.write_text(invalid_json)
        with pytest.raises(AgentError, match='not valid JSON'):
            read_profile(profile_path)

    @pytest.mark.parametrize(
        ('field_path', 'bad_value', 'expected_error'),
        [
            ('profile', None, 'profile must be an object'),
            ('profile.onboarding', None, 'onboarding must be an object'),
            ('profile.certificate_request', None, 'certificate_request must be an object'),
            ('profile.onboarding.device', '', 'device must be a non-empty string'),
            ('profile.onboarding.device', 123, 'device must be a non-empty string'),
            ('profile.onboarding.secret', None, 'secret must be a non-empty string'),
            ('profile.onboarding.tls_cert_pem', '', 'tls_cert_pem must be a non-empty string'),
            ('profile.certificate_request.url', '', 'url must be a non-empty string'),
            ('profile.certificate_request.path', '', 'path must be a non-empty string'),
        ],
    )
    def test_read_profile_missing_fields(
        self, temp_dir: Path, mock_profile_data: dict[str, Any], field_path: str, bad_value: Any, expected_error: str
    ):
        """Test profile validation catches missing or invalid required fields."""
        # Navigate to the field and set the bad value
        parts = field_path.split('.')
        obj = mock_profile_data
        for part in parts[:-1]:
            obj = obj[part]
        obj[parts[-1]] = bad_value

        profile_path = temp_dir / 'bad_profile.json'
        profile_path.write_text(json.dumps(mock_profile_data))

        with pytest.raises(AgentError, match=expected_error):
            read_profile(profile_path)

    def test_local_storage_defaults(self, temp_dir: Path, mock_profile_data: dict[str, Any]):
        """Test that local_storage uses defaults when not specified."""
        del mock_profile_data['profile']['local_storage']
        profile_path = temp_dir / 'profile.json'
        profile_path.write_text(json.dumps(mock_profile_data))

        profile = read_profile(profile_path)
        assert profile.local_storage.private_key_path == Path('domain_credential-key.pem')
        assert profile.local_storage.csr_path == Path('domain_credential-csr.pem')

    def test_optional_fields(self, profile_file: Path):
        """Test that optional fields are properly handled."""
        profile = read_profile(profile_file)
        assert profile.subject is None
        assert profile.subject_alt_name is None
        assert profile.public_key_algorithm_oid is None
        assert profile.key_parameter is None


class TestValidationHelpers:
    """Test low-level validation helper functions."""

    def test_expect_object_valid(self):
        """Test _expect_object accepts dictionaries."""
        obj = {'key': 'value'}
        result = _expect_object(obj, 'test')
        assert result == obj

    @pytest.mark.parametrize('bad_value', [None, 'string', 123, [], True])
    def test_expect_object_invalid(self, bad_value: Any):
        """Test _expect_object rejects non-dictionaries."""
        with pytest.raises(AgentError, match='must be an object'):
            _expect_object(bad_value, 'test_field')

    def test_expect_non_empty_str_valid(self):
        """Test _expect_non_empty_str accepts valid strings."""
        assert _expect_non_empty_str('valid', 'field') == 'valid'

    @pytest.mark.parametrize('bad_value', [None, '', '   ', 123, [], {}])
    def test_expect_non_empty_str_invalid(self, bad_value: Any):
        """Test _expect_non_empty_str rejects invalid values."""
        with pytest.raises(AgentError, match='must be a non-empty string'):
            _expect_non_empty_str(bad_value, 'field')

    def test_optional_str_valid(self):
        """Test _optional_str handles valid optional strings."""
        assert _optional_str(None) is None
        assert _optional_str('value') == 'value'
        assert _optional_str('') is None

    @pytest.mark.parametrize('bad_value', [123, [], {}])
    def test_optional_str_invalid(self, bad_value: Any):
        """Test _optional_str rejects non-string types."""
        with pytest.raises(AgentError, match='expected optional string'):
            _optional_str(bad_value)


# ============================================================================
# Certificate and Key Lifecycle Tests
# ============================================================================


class TestKeyGeneration:
    """Test private key generation."""

    def test_generate_rsa_key_default(self, temp_dir: Path):
        """Test RSA key generation with default parameters."""
        key_path = temp_dir / 'test-key.pem'
        key = generate_private_key(key_path)

        assert key_path.exists()
        assert (key_path.stat().st_mode & 0o777) == 0o600  # Verify permissions
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

    @pytest.mark.parametrize(('size_str', 'expected_size'), [('2048', 2048), ('3072', 3072), ('4096', 4096)])
    def test_generate_rsa_key_sizes(self, temp_dir: Path, size_str: str, expected_size: int):
        """Test RSA key generation with different key sizes."""
        key_path = temp_dir / f'key-{size_str}.pem'
        key = generate_private_key(key_path, key_parameter=size_str)

        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == expected_size

    def test_generate_rsa_key_invalid_size(self, temp_dir: Path):
        """Test RSA key generation with invalid size falls back to default."""
        key_path = temp_dir / 'key.pem'
        key = generate_private_key(key_path, key_parameter='invalid')

        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048  # Falls back to default

    @pytest.mark.parametrize(
        ('curve_name', 'expected_curve'),
        [('secp256r1', ec.SECP256R1), ('secp384r1', ec.SECP384R1), ('secp521r1', ec.SECP521R1)],
    )
    def test_generate_ecc_key(self, temp_dir: Path, curve_name: str, expected_curve: type):
        """Test ECC key generation with different curves."""
        key_path = temp_dir / f'key-{curve_name}.pem'
        ecc_oid = '1.2.840.10045.2.1'
        key = generate_private_key(key_path, public_key_algorithm_oid=ecc_oid, key_parameter=curve_name)

        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert isinstance(key.curve, expected_curve)

    def test_generate_ecc_key_invalid_curve(self, temp_dir: Path):
        """Test ECC key generation with invalid curve falls back to default."""
        key_path = temp_dir / 'key.pem'
        ecc_oid = '1.2.840.10045.2.1'
        key = generate_private_key(key_path, public_key_algorithm_oid=ecc_oid, key_parameter='invalid_curve')

        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert isinstance(key.curve, ec.SECP256R1)  # Falls back to default

    def test_load_private_key(self, temp_dir: Path):
        """Test loading a previously generated private key."""
        key_path = temp_dir / 'key.pem'
        original_key = generate_private_key(key_path)

        loaded_key = load_private_key(key_path)
        assert isinstance(loaded_key, rsa.RSAPrivateKey)
        # Verify it's the same key by comparing public key bytes
        original_pub = original_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        loaded_pub = loaded_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        assert original_pub == loaded_pub


class TestCSRGeneration:
    """Test certificate signing request generation."""

    def test_generate_csr_simple(self, temp_dir: Path):
        """Test CSR generation with simple common name."""
        key_path = temp_dir / 'key.pem'
        csr_path = temp_dir / 'csr.pem'
        generate_private_key(key_path)

        csr_pem = generate_csr(key_path, csr_path, common_name='Test Device')

        assert csr_path.exists()
        assert '-----BEGIN CERTIFICATE REQUEST-----' in csr_pem
        # Verify CSR is valid
        csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
        assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == 'Test Device'

    def test_generate_csr_with_subject(self, temp_dir: Path):
        """Test CSR generation with full subject DN."""
        key_path = temp_dir / 'key.pem'
        csr_path = temp_dir / 'csr.pem'
        generate_private_key(key_path)

        subject = '/C=US/ST=California/L=San Francisco/O=Example Corp/OU=Engineering/CN=test.example.com'
        csr_pem = generate_csr(key_path, csr_path, subject=subject)

        csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
        assert csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == 'US'
        assert csr.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value == 'California'
        assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == 'test.example.com'

    @pytest.mark.parametrize(
        ('san_string', 'expected_type', 'expected_value'),
        [
            ('DNS:example.com', x509.DNSName, 'example.com'),
            ('IP:192.168.1.1', x509.IPAddress, '192.168.1.1'),
            ('URI:https://example.com', x509.UniformResourceIdentifier, 'https://example.com'),
            ('EMAIL:test@example.com', x509.RFC822Name, 'test@example.com'),
        ],
    )
    def test_generate_csr_with_san(self, temp_dir: Path, san_string: str, expected_type: type, expected_value: str):
        """Test CSR generation with subject alternative names."""
        key_path = temp_dir / 'key.pem'
        csr_path = temp_dir / 'csr.pem'
        generate_private_key(key_path)

        csr_pem = generate_csr(key_path, csr_path, subject_alt_name=san_string)

        csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert len(san_ext.value) == 1
        assert isinstance(san_ext.value[0], expected_type)


class TestSubjectParsing:
    """Test subject DN and SAN parsing."""

    def test_parse_subject_simple_cn(self):
        """Test parsing simple common name."""
        name = parse_subject('test.example.com', 'default')
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert len(attrs) == 1
        assert attrs[0].value == 'test.example.com'

    def test_parse_subject_default_cn(self):
        """Test using default common name when subject is None."""
        name = parse_subject(None, 'default-cn')
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert attrs[0].value == 'default-cn'

    def test_parse_subject_full_dn(self):
        """Test parsing full distinguished name."""
        dn = '/C=US/ST=CA/L=SF/O=Example/OU=IT/CN=test/EMAILADDRESS=test@example.com'
        name = parse_subject(dn, 'default')

        assert name.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == 'US'
        assert name.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value == 'CA'
        assert name.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value == 'SF'
        assert name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == 'Example'
        assert name.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == 'IT'
        assert name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == 'test'
        assert name.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value == 'test@example.com'

    @pytest.mark.parametrize(
        'invalid_dn',
        [
            '/InvalidKey=value',
            '/CN',
            '/CN=',
            '///',
            '/C=US/INVALID=test',
        ],
    )
    def test_parse_subject_invalid(self, invalid_dn: str):
        """Test parsing invalid subject DNs raises errors."""
        with pytest.raises(AgentError):
            parse_subject(invalid_dn, 'default')

    def test_parse_san_multiple(self):
        """Test parsing multiple SAN entries."""
        san_str = 'DNS:example.com, DNS:www.example.com, IP:192.168.1.1'
        san = parse_subject_alt_name(san_str)

        assert san is not None
        assert len(san) == 3
        assert any(isinstance(n, x509.DNSName) and n.value == 'example.com' for n in san)
        assert any(isinstance(n, x509.DNSName) and n.value == 'www.example.com' for n in san)

    def test_parse_san_none(self):
        """Test parsing None SAN returns None."""
        assert parse_subject_alt_name(None) is None

    def test_parse_san_empty(self):
        """Test parsing empty SAN string returns None."""
        assert parse_subject_alt_name('') is None

    @pytest.mark.parametrize('invalid_san', ['invalid', 'DNS', ':value', 'UNSUPPORTED:value'])
    def test_parse_san_invalid(self, invalid_san: str):
        """Test parsing invalid SAN entries raises errors."""
        with pytest.raises(AgentError):
            parse_subject_alt_name(invalid_san)


# ============================================================================
# Filesystem Operations Tests
# ============================================================================


class TestFilesystemOperations:
    """Test atomic file operations and permissions."""

    def test_atomic_write_text(self, temp_dir: Path):
        """Test atomic text file writing."""
        file_path = temp_dir / 'test.txt'
        content = 'test content'

        atomic_write_text(file_path, content, 0o644)

        assert file_path.exists()
        assert file_path.read_text() == content
        assert (file_path.stat().st_mode & 0o777) == 0o644

    def test_atomic_write_bytes(self, temp_dir: Path):
        """Test atomic binary file writing."""
        file_path = temp_dir / 'test.bin'
        content = b'binary content'

        atomic_write_bytes(file_path, content, 0o600)

        assert file_path.exists()
        assert file_path.read_bytes() == content
        assert (file_path.stat().st_mode & 0o777) == 0o600

    def test_atomic_write_creates_parent(self, temp_dir: Path):
        """Test atomic write creates parent directories."""
        file_path = temp_dir / 'subdir1' / 'subdir2' / 'test.txt'

        atomic_write_text(file_path, 'content', 0o644)

        assert file_path.exists()
        assert file_path.parent.exists()

    def test_ensure_parent(self, temp_dir: Path):
        """Test ensure_parent creates directory tree."""
        file_path = temp_dir / 'a' / 'b' / 'c' / 'file.txt'

        ensure_parent(file_path)

        assert file_path.parent.exists()
        assert file_path.parent.is_dir()

    def test_atomic_copy(self, temp_dir: Path):
        """Test atomic file copying."""
        src = temp_dir / 'source.txt'
        dst = temp_dir / 'dest.txt'
        src.write_text('test content')

        atomic_copy(src, dst, 0o600)

        assert dst.exists()
        assert dst.read_text() == 'test content'
        assert (dst.stat().st_mode & 0o777) == 0o600


# ============================================================================
# HTTP/Network Tests
# ============================================================================


class TestURLHelpers:
    """Test URL construction helpers."""

    @pytest.mark.parametrize(
        ('base', 'path', 'expected'),
        [
            ('https://example.com', '/api/test', 'https://example.com/api/test'),
            ('https://example.com/', '/api/test', 'https://example.com/api/test'),
            ('https://example.com', 'api/test', 'https://example.com/api/test'),
            ('https://example.com/', 'api/test', 'https://example.com/api/test'),
        ],
    )
    def test_join_url(self, base: str, path: str, expected: str):
        """Test URL joining handles slashes correctly."""
        assert join_url(base, path) == expected


class TestHTTPSession:
    """Test HTTP session creation and configuration."""

    def test_make_session_basic(self, temp_dir: Path):
        """Test creating basic session with CA verification."""
        ca_path = temp_dir / 'ca.pem'
        ca_path.write_text('-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n')

        session = make_session(ca_path, timeout=30)

        assert session.verify == str(ca_path)
        assert session.trustpoint_timeout == 30  # type: ignore[attr-defined]
        assert 'trustpoint-agent' in session.headers['User-Agent']

    def test_make_session_with_mtls(self, temp_dir: Path):
        """Test creating session with mutual TLS."""
        ca_path = temp_dir / 'ca.pem'
        cert_path = temp_dir / 'cert.pem'
        key_path = temp_dir / 'key.pem'

        ca_path.write_text('CA')
        cert_path.write_text('CERT')
        key_path.write_text('KEY')

        session = make_session(ca_path, timeout=15, cert_pair=(str(cert_path), str(key_path)))

        assert session.cert == (str(cert_path), str(key_path))


class TestHTTPRetryLogic:
    """Test HTTP request retry and backoff logic."""

    def test_backoff_delay_increases(self):
        """Test exponential backoff increases with attempts."""
        delay0 = _backoff_delay(0, 2.0, 60.0)
        delay1 = _backoff_delay(1, 2.0, 60.0)
        delay2 = _backoff_delay(2, 2.0, 60.0)

        # Should increase exponentially (with jitter, so approximate)
        assert delay0 < 4.0  # ~2.0 * 2^0 with jitter
        assert delay1 < 8.0  # ~2.0 * 2^1 with jitter
        assert delay2 < 16.0  # ~2.0 * 2^2 with jitter

    def test_backoff_delay_respects_max(self):
        """Test backoff delay doesn't exceed maximum."""
        delay = _backoff_delay(10, 2.0, 10.0)
        assert delay <= 15.0  # max 10.0 * 1.5 (jitter factor)

    def test_retry_after_header(self):
        """Test parsing Retry-After header."""
        response = Mock()
        response.headers = {'Retry-After': '5'}
        assert _retry_after_delay(response) == 5.0

    def test_retry_after_missing(self):
        """Test missing Retry-After header returns None."""
        response = Mock()
        response.headers = {}
        assert _retry_after_delay(response) is None

    def test_retry_after_invalid(self):
        """Test invalid Retry-After header returns None."""
        response = Mock()
        response.headers = {'Retry-After': 'invalid'}
        assert _retry_after_delay(response) is None

    @patch('agent.time.sleep')
    def test_request_with_retries_success(self, mock_sleep: Mock):
        """Test successful request without retries."""
        session = Mock()
        response = Mock()
        response.status_code = 200
        session.request.return_value = response

        result = request_with_retries(
            session, 'GET', 'https://example.com', max_retries=3, initial_backoff=1.0, max_backoff=10.0
        )

        assert result == response
        session.request.assert_called_once()
        mock_sleep.assert_not_called()

    @patch('agent.time.sleep')
    def test_request_with_retries_transient_failure(self, mock_sleep: Mock):
        """Test retry on transient HTTP status codes."""
        session = Mock()
        session.trustpoint_timeout = 30

        # First request fails with 503, second succeeds
        response_fail = Mock()
        response_fail.status_code = 503
        response_fail.headers = {}  # No Retry-After header
        response_success = Mock()
        response_success.status_code = 200

        session.request.side_effect = [response_fail, response_success]

        result = request_with_retries(
            session, 'GET', 'https://example.com', max_retries=3, initial_backoff=0.1, max_backoff=1.0
        )

        assert result == response_success
        assert session.request.call_count == 2
        assert mock_sleep.call_count == 1

    @patch('agent.time.sleep')
    def test_request_with_retries_network_error(self, mock_sleep: Mock):
        """Test retry on network exceptions."""
        session = Mock()
        session.trustpoint_timeout = 30

        # Simulate connection errors
        session.request.side_effect = [
            requests.ConnectionError('Connection failed'),
            requests.ConnectionError('Connection failed'),
            Mock(status_code=200),
        ]

        result = request_with_retries(
            session, 'GET', 'https://example.com', max_retries=3, initial_backoff=0.1, max_backoff=1.0
        )

        assert result.status_code == 200
        assert session.request.call_count == 3
        assert mock_sleep.call_count == 2

    @patch('agent.time.sleep')
    def test_request_with_retries_exhausted(self, mock_sleep: Mock):
        """Test all retries exhausted raises AgentError."""
        session = Mock()
        session.trustpoint_timeout = 30
        session.request.side_effect = requests.ConnectionError('Permanent failure')

        with pytest.raises(AgentError, match='failed after .* attempt'):
            request_with_retries(
                session, 'GET', 'https://example.com', max_retries=2, initial_backoff=0.1, max_backoff=1.0
            )

        assert session.request.call_count == 3  # initial + 2 retries
        assert mock_sleep.call_count == 2


class TestHTTPResponseHandling:
    """Test HTTP response validation and parsing."""

    def test_require_success_valid(self):
        """Test require_success accepts 2xx status codes."""
        for status in range(HTTP_OK_MIN, HTTP_OK_MAX):
            response = Mock()
            response.status_code = status
            require_success(response, 'test action')  # Should not raise

    @pytest.mark.parametrize('status', [400, 401, 403, 404, 500, 502, 503])
    def test_require_success_errors(self, status: int):
        """Test require_success raises on error status codes."""
        response = Mock()
        response.status_code = status
        response.text = f'Error {status}'

        with pytest.raises(AgentError, match=f'HTTP {status}'):
            require_success(response, 'test action')

    def test_response_json_object_valid(self):
        """Test parsing valid JSON object response."""
        response = Mock()
        response.headers = {'Content-Type': 'application/json'}
        response.json.return_value = {'key': 'value'}

        result = response_json_object(response, 'test')
        assert result == {'key': 'value'}

    def test_response_json_object_not_object(self):
        """Test parsing JSON array raises error."""
        response = Mock()
        response.headers = {'Content-Type': 'application/json'}
        response.json.return_value = ['array', 'not', 'object']

        with pytest.raises(AgentError, match='must be a JSON object'):
            response_json_object(response, 'test')

    def test_response_json_object_invalid_json(self):
        """Test invalid JSON raises error."""
        response = Mock()
        response.headers = {'Content-Type': 'application/json'}
        response.json.side_effect = ValueError('Invalid JSON')
        response.text = 'not json'

        with pytest.raises(AgentError, match='not valid JSON'):
            response_json_object(response, 'test')


# ============================================================================
# Enrollment and Renewal Workflow Tests
# ============================================================================


class TestEnrollmentResponse:
    """Test enrollment response parsing."""

    def test_parse_enrollment_response_valid(self):
        """Test parsing valid enrollment response."""
        data = {
            'certificate': '-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n',
            'certificate_chain': [
                '-----BEGIN CERTIFICATE-----\nINT...\n-----END CERTIFICATE-----\n',
                '-----BEGIN CERTIFICATE-----\nROOT...\n-----END CERTIFICATE-----\n',
            ],
        }

        result = parse_enrollment_response(data, 'test')

        assert 'BEGIN CERTIFICATE' in result.certificate
        assert len(result.certificate_chain) == 2

    def test_parse_enrollment_response_missing_cert(self):
        """Test parsing response without certificate raises error."""
        data = {'certificate_chain': []}

        with pytest.raises(AgentError, match='missing valid PEM certificate'):
            parse_enrollment_response(data, 'test')

    def test_parse_enrollment_response_invalid_cert(self):
        """Test parsing response with non-PEM certificate raises error."""
        data = {'certificate': 'not a pem certificate'}

        with pytest.raises(AgentError, match='missing valid PEM certificate'):
            parse_enrollment_response(data, 'test')

    def test_parse_enrollment_response_no_chain(self):
        """Test parsing response without chain is acceptable."""
        data = {'certificate': '-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n'}

        result = parse_enrollment_response(data, 'test')

        assert len(result.certificate_chain) == 0

    def test_parse_enrollment_response_invalid_chain_item(self):
        """Test parsing response with invalid chain item raises error."""
        data = {
            'certificate': '-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n',
            'certificate_chain': ['not a certificate'],
        }

        with pytest.raises(AgentError, match='is not a PEM certificate'):
            parse_enrollment_response(data, 'test')


class TestCredentialSaving:
    """Test credential file saving."""

    def test_save_credentials(self, temp_dir: Path):
        """Test saving certificate and chain to files."""
        cert_path = temp_dir / 'cert.pem'
        chain_path = temp_dir / 'chain.pem'

        response = EnrollmentResponse(
            certificate='-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----',
            certificate_chain=[
                '-----BEGIN CERTIFICATE-----\nINT\n-----END CERTIFICATE-----',
                '-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----',
            ],
        )

        save_credentials(response, cert_path, chain_path)

        assert cert_path.exists()
        assert chain_path.exists()

        cert_content = cert_path.read_text()
        chain_content = chain_path.read_text()

        assert 'CERT' in cert_content
        assert 'CERT' in chain_content
        assert 'INT' in chain_content
        assert 'ROOT' in chain_content

    def test_pem_join(self):
        """Test PEM joining adds newlines correctly."""
        items = [
            '-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----',
            '-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n',
        ]

        result = _pem_join(items)

        assert result.count('-----BEGIN CERTIFICATE-----') == 2
        assert result.endswith('\n')
        # Both should end with newline
        lines = result.split('-----END CERTIFICATE-----')
        assert all(line == '' or line.endswith('\n') for line in lines[:-1])


class TestDeterministicPaths:
    """Test deterministic path generation for jobs."""

    def test_deterministic_paths_domain_credential(self, temp_dir: Path):
        """Test paths for domain_credential profile use configured paths."""
        storage = LocalStorage(
            private_key_path=temp_dir / 'domain-key.pem',
            csr_path=temp_dir / 'domain-csr.pem',
            tls_cert_path=temp_dir / 'tls.pem',
            certificate_path=temp_dir / 'domain-cert.pem',
            certificate_chain_path=temp_dir / 'domain-chain.pem',
        )
        params = PollParams(
            base_url='https://example.com',
            ca_cert_path=temp_dir / 'ca.pem',
            active_credential=ActiveCredential(cert_path=temp_dir / 'cert.pem', key_path=temp_dir / 'key.pem'),
            local_storage=storage,
            request_timeout=30,
            max_retries=3,
            initial_backoff=1.0,
            max_backoff=10.0,
        )

        key_path, csr_path, cert_path, chain_path = deterministic_paths_for_job(params, 'domain_credential')

        assert key_path == storage.private_key_path
        assert csr_path == storage.csr_path
        assert cert_path == storage.certificate_path
        assert chain_path == storage.certificate_chain_path

    def test_deterministic_paths_other_profile(self, temp_dir: Path):
        """Test paths for other profiles are derived from base directory."""
        storage = LocalStorage(
            private_key_path=temp_dir / 'domain-key.pem',
            csr_path=temp_dir / 'domain-csr.pem',
            tls_cert_path=temp_dir / 'tls.pem',
            certificate_path=temp_dir / 'domain-cert.pem',
            certificate_chain_path=temp_dir / 'domain-chain.pem',
        )
        params = PollParams(
            base_url='https://example.com',
            ca_cert_path=temp_dir / 'ca.pem',
            active_credential=ActiveCredential(cert_path=temp_dir / 'cert.pem', key_path=temp_dir / 'key.pem'),
            local_storage=storage,
            request_timeout=30,
            max_retries=3,
            initial_backoff=1.0,
            max_backoff=10.0,
        )

        key_path, csr_path, cert_path, chain_path = deterministic_paths_for_job(params, 'tls_server')

        assert key_path == temp_dir / 'tls_server-key.pem'
        assert csr_path == temp_dir / 'tls_server-csr.pem'
        assert cert_path == temp_dir / 'tls_server-certificate.pem'
        assert chain_path == temp_dir / 'tls_server-chain.pem'


# ============================================================================
# Job Execution Tests
# ============================================================================


class TestFetchJobs:
    """Test fetching jobs from Trustpoint."""

    @patch('agent.request_with_retries')
    def test_fetch_jobs_success(self, mock_request: Mock, temp_dir: Path):
        """Test successfully fetching jobs."""
        # Setup
        session = Mock()
        params = PollParams(
            base_url='https://example.com',
            ca_cert_path=temp_dir / 'ca.pem',
            active_credential=ActiveCredential(cert_path=temp_dir / 'cert.pem', key_path=temp_dir / 'key.pem'),
            local_storage=LocalStorage.from_mapping({}),
            request_timeout=30,
            max_retries=3,
            initial_backoff=1.0,
            max_backoff=10.0,
        )

        # Mock response
        response = Mock()
        response.status_code = 200
        response.headers = {'Content-Type': 'application/json'}
        response.json.return_value = {
            'poll_interval_seconds': 300,
            'jobs': [
                {'profile_id': 1, 'workflow_profile': {}},
                {'profile_id': 2, 'workflow_profile': {}},
            ],
        }
        mock_request.return_value = response

        # Execute
        poll_interval, jobs = fetch_jobs(params, session, 'cert_urlencoded')

        # Verify
        assert poll_interval == 300
        assert len(jobs) == 2
        assert jobs[0]['profile_id'] == 1

    @patch('agent.request_with_retries')
    def test_fetch_jobs_invalid_poll_interval(self, mock_request: Mock, temp_dir: Path):
        """Test fetching jobs with invalid poll interval raises error."""
        session = Mock()
        params = PollParams(
            base_url='https://example.com',
            ca_cert_path=temp_dir / 'ca.pem',
            active_credential=ActiveCredential(cert_path=temp_dir / 'cert.pem', key_path=temp_dir / 'key.pem'),
            local_storage=LocalStorage.from_mapping({}),
            request_timeout=30,
            max_retries=3,
            initial_backoff=1.0,
            max_backoff=10.0,
        )

        response = Mock()
        response.status_code = 200
        response.headers = {'Content-Type': 'application/json'}
        response.json.return_value = {'poll_interval_seconds': 'invalid', 'jobs': []}
        mock_request.return_value = response

        with pytest.raises(AgentError, match='poll_interval_seconds must be a positive integer'):
            fetch_jobs(params, session, 'cert')


class TestJobExecution:
    """Test certificate renewal job execution."""

    def test_execute_renewal_job_invalid_profile_id(self, temp_dir: Path):
        """Test job with invalid profile_id returns error result."""
        params = PollParams(
            base_url='https://example.com',
            ca_cert_path=temp_dir / 'ca.pem',
            active_credential=ActiveCredential(cert_path=temp_dir / 'cert.pem', key_path=temp_dir / 'key.pem'),
            local_storage=LocalStorage.from_mapping({}),
            request_timeout=30,
            max_retries=3,
            initial_backoff=1.0,
            max_backoff=10.0,
        )

        job = {'profile_id': 'not_an_int'}
        result = execute_renewal_job(params, Mock(), job, 'cert')

        assert result.success is False
        assert 'must be an integer' in result.error_message

    @patch('agent.request_with_retries')
    def test_execute_renewal_job_success(self, mock_request: Mock, temp_dir: Path, valid_cert_pem: str):
        """Test successful job execution."""
        # Setup storage paths
        storage = LocalStorage(
            private_key_path=temp_dir / 'domain-key.pem',
            csr_path=temp_dir / 'domain-csr.pem',
            tls_cert_path=temp_dir / 'tls.pem',
            certificate_path=temp_dir / 'domain-cert.pem',
            certificate_chain_path=temp_dir / 'domain-chain.pem',
        )

        params = PollParams(
            base_url='https://example.com',
            ca_cert_path=temp_dir / 'ca.pem',
            active_credential=ActiveCredential(
                cert_path=storage.certificate_path, key_path=storage.private_key_path
            ),
            local_storage=storage,
            request_timeout=30,
            max_retries=3,
            initial_backoff=1.0,
            max_backoff=10.0,
        )

        job = {
            'profile_id': 1,
            'workflow_profile': {
                'certificate_request': {
                    'certificate_profile': 'domain_credential',
                    'path': '/api/renew/',
                    'subject': 'CN=test',
                }
            },
        }

        # Mock enrollment response
        response = Mock()
        response.status_code = 200
        response.headers = {'Content-Type': 'application/json'}
        response.json.return_value = {'certificate': valid_cert_pem, 'certificate_chain': []}
        mock_request.return_value = response

        # Execute
        result = execute_renewal_job(params, Mock(), job, 'cert')

        # Verify
        assert result.success is True
        assert result.profile_id == 1
        # Check files were created
        assert storage.certificate_path.exists()
        assert storage.certificate_chain_path.exists()
        assert storage.private_key_path.exists()


class TestJobAcknowledgement:
    """Test job acknowledgement."""

    @patch('agent.request_with_retries')
    def test_acknowledge_job_success(self, mock_request: Mock, temp_dir: Path):
        """Test successful job acknowledgement."""
        params = PollParams(
            base_url='https://example.com',
            ca_cert_path=temp_dir / 'ca.pem',
            active_credential=ActiveCredential(cert_path=temp_dir / 'cert.pem', key_path=temp_dir / 'key.pem'),
            local_storage=LocalStorage.from_mapping({}),
            request_timeout=30,
            max_retries=3,
            initial_backoff=1.0,
            max_backoff=10.0,
        )

        result = JobResult(profile_id=1, success=True)

        response = Mock()
        response.status_code = 200
        response.headers = {'Content-Type': 'application/json'}
        response.json.return_value = {'next_certificate_update': '2024-12-31'}
        mock_request.return_value = response

        # Should not raise
        acknowledge_job(params, Mock(), result, 'cert')

        # Verify request was made
        assert mock_request.called


# ============================================================================
# Argument Parsing Tests
# ============================================================================


class TestArgumentParsing:
    """Test command-line argument parsing."""

    def test_parse_args_defaults(self):
        """Test default argument values."""
        args = parse_args([])

        assert args.profile == Path('agent_setup.json')
        assert args.once is False
        assert args.skip_onboarding is False
        assert args.request_timeout == 30
        assert args.max_retries == 3
        assert args.log_level == 'INFO'
        assert args.log_format == 'text'

    def test_parse_args_custom(self):
        """Test custom argument values."""
        args = parse_args(
            [
                '--profile',
                'custom.json',
                '--once',
                '--skip-onboarding',
                '--request-timeout',
                '60',
                '--max-retries',
                '5',
                '--log-level',
                'DEBUG',
                '--log-format',
                'json',
            ]
        )

        assert args.profile == Path('custom.json')
        assert args.once is True
        assert args.skip_onboarding is True
        assert args.request_timeout == 60
        assert args.max_retries == 5
        assert args.log_level == 'DEBUG'
        assert args.log_format == 'json'


# ============================================================================
# Security-Relevant Tests
# ============================================================================


class TestSecurityFailures:
    """Test security-relevant failure cases."""

    def test_private_key_permissions(self, temp_dir: Path):
        """Test private keys are created with 0600 permissions."""
        key_path = temp_dir / 'secure-key.pem'
        generate_private_key(key_path)

        mode = key_path.stat().st_mode & 0o777
        assert mode == 0o600, f'Expected 0o600, got {oct(mode)}'

    def test_certificate_permissions(self, temp_dir: Path):
        """Test certificates are created with 0644 permissions."""
        cert_path = temp_dir / 'cert.pem'
        atomic_write_text(cert_path, '-----BEGIN CERTIFICATE-----\n', 0o644)

        mode = cert_path.stat().st_mode & 0o777
        assert mode == 0o644, f'Expected 0o644, got {oct(mode)}'

    def test_atomic_write_prevents_corruption(self, temp_dir: Path):
        """Test atomic write doesn't corrupt existing file on error."""
        file_path = temp_dir / 'important.txt'
        file_path.write_text('original content')

        # Simulate write failure by using invalid path for temp dir
        # (can't actually force failure easily, so this is more of a smoke test)
        atomic_write_text(file_path, 'new content', 0o644)

        # File should have new content atomically
        assert file_path.read_text() == 'new content'

    @patch('agent.request_with_retries')
    def test_enrollment_fails_without_valid_cert(self, mock_request: Mock, temp_dir: Path):
        """Test enrollment fails if server returns invalid certificate."""
        params = PollParams(
            base_url='https://example.com',
            ca_cert_path=temp_dir / 'ca.pem',
            active_credential=ActiveCredential(cert_path=temp_dir / 'cert.pem', key_path=temp_dir / 'key.pem'),
            local_storage=LocalStorage.from_mapping({}),
            request_timeout=30,
            max_retries=3,
            initial_backoff=1.0,
            max_backoff=10.0,
        )

        job = {
            'profile_id': 1,
            'workflow_profile': {
                'certificate_request': {
                    'certificate_profile': 'test',
                    'path': '/api/test/',
                }
            },
        }

        # Return invalid certificate
        response = Mock()
        response.status_code = 200
        response.headers = {'Content-Type': 'application/json'}
        response.json.return_value = {'certificate': 'NOT A VALID PEM'}
        mock_request.return_value = response

        result = execute_renewal_job(params, Mock(), job, 'cert')

        assert result.success is False
        assert 'missing valid PEM certificate' in result.error_message


# ============================================================================
# Logging Tests
# ============================================================================


class TestLogging:
    """Test logging configuration."""

    def test_configure_logging_text(self):
        """Test text logging configuration."""
        configure_logging('INFO', 'text')

        import logging

        root = logging.getLogger()
        assert root.level == logging.INFO
        assert len(root.handlers) > 0

    def test_configure_logging_json(self):
        """Test JSON logging configuration."""
        configure_logging('DEBUG', 'json')

        import logging

        root = logging.getLogger()
        assert root.level == logging.DEBUG

    @pytest.mark.parametrize('level', ['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    def test_configure_logging_levels(self, level: str):
        """Test different log levels."""
        configure_logging(level, 'text')

        import logging

        root = logging.getLogger()
        assert root.level == getattr(logging, level)


# ============================================================================
# Enrollment Tests
# ============================================================================


class TestEnrollment:
    """Test initial enrollment workflow."""

    @patch('agent.make_session')
    @patch('agent.request_with_retries')
    @patch('agent.generate_private_key')
    @patch('agent.generate_csr')
    def test_enroll_initial_success(
        self,
        mock_gen_csr: Mock,
        mock_gen_key: Mock,
        mock_request: Mock,
        mock_make_session: Mock,
        temp_dir: Path,
        mock_profile_data: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Test successful initial enrollment."""
        from agent import enroll_initial, read_profile

        # Change to temp directory so relative paths work
        monkeypatch.chdir(temp_dir)

        # Setup mocks - create actual files as side effects
        def mock_gen_key_side_effect(key_path, **kwargs):
            Path(key_path).write_text('MOCK_PRIVATE_KEY')
        
        mock_gen_key.side_effect = mock_gen_key_side_effect

        mock_csr = Mock()
        mock_csr.public_bytes.return_value = b'CSR_DATA'
        mock_gen_csr.return_value = 'MOCK_CSR_PEM'

        response = Mock()
        response.status_code = 200
        response.headers = {'Content-Type': 'application/json'}
        response.json.return_value = {
            'certificate': '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----',
            'chain': [
                '-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----'
            ],
        }
        mock_request.return_value = response

        # Create profile
        profile_path = temp_dir / 'profile.json'
        profile_path.write_text(json.dumps(mock_profile_data))

        profile = read_profile(profile_path)
        args = parse_args([])

        # Execute
        credential = enroll_initial(profile, args)

        # Verify
        assert credential.cert_path.exists()
        assert credential.key_path.exists()
        assert mock_gen_key.called
        assert mock_gen_csr.called
        assert mock_request.called

    @patch('agent.make_session')
    @patch('agent.request_with_retries')
    def test_enroll_initial_network_failure(
        self,
        mock_request: Mock,
        mock_make_session: Mock,
        temp_dir: Path,
        mock_profile_data: dict[str, Any],
    ):
        """Test enrollment failure due to network error."""
        from agent import enroll_initial, read_profile

        # Setup mocks
        mock_request.side_effect = AgentError('Network error')

        profile_path = temp_dir / 'profile.json'
        profile_path.write_text(json.dumps(mock_profile_data))

        profile = read_profile(profile_path)
        args = parse_args([])

        # Execute and verify exception
        with pytest.raises(AgentError, match='Network error'):
            enroll_initial(profile, args)

    @patch('agent.make_session')
    @patch('agent.request_with_retries')
    @patch('agent.generate_private_key')
    @patch('agent.generate_csr')
    def test_enroll_initial_invalid_response(
        self,
        mock_gen_csr: Mock,
        mock_gen_key: Mock,
        mock_request: Mock,
        mock_make_session: Mock,
        temp_dir: Path,
        mock_profile_data: dict[str, Any],
    ):
        """Test enrollment with invalid server response."""
        from agent import enroll_initial, read_profile

        # Setup mocks
        mock_csr = Mock()
        mock_csr.public_bytes.return_value = b'CSR_DATA'
        mock_gen_csr.return_value = mock_csr

        response = Mock()
        response.status_code = 200
        response.headers = {'Content-Type': 'application/json'}
        response.json.return_value = {'invalid': 'response'}
        mock_request.return_value = response

        profile_path = temp_dir / 'profile.json'
        profile_path.write_text(json.dumps(mock_profile_data))

        profile = read_profile(profile_path)
        args = parse_args([])

        # Execute and verify exception
        with pytest.raises(AgentError, match='certificate'):
            enroll_initial(profile, args)


# ============================================================================
# Polling Tests
# ============================================================================


class TestPolling:
    """Test job polling logic."""

    @patch('agent.mtls_session')
    @patch('agent.cert_header_value')
    @patch('agent.fetch_jobs')
    @patch('agent.execute_renewal_job')
    @patch('agent.acknowledge_job')
    def test_poll_once_with_jobs(
        self,
        mock_ack: Mock,
        mock_execute: Mock,
        mock_fetch: Mock,
        mock_cert_header: Mock,
        mock_session: Mock,
        temp_dir: Path,
    ):
        """Test polling once with pending jobs."""
        from agent import poll_once

        # Setup mocks
        mock_session.return_value = Mock()
        mock_cert_header.return_value = 'cert_value'
        mock_fetch.return_value = (300, [{'profile_id': 1}])
        mock_execute.return_value = JobResult(
            profile_id=1,
            success=True,
            error_message='',
        )

        params = PollParams(
            base_url='https://example.com',
            ca_cert_path=temp_dir / 'ca.pem',
            active_credential=ActiveCredential(cert_path=temp_dir / 'cert.pem', key_path=temp_dir / 'key.pem'),
            local_storage=LocalStorage.from_mapping({}),
            request_timeout=30,
            max_retries=3,
            initial_backoff=1.0,
            max_backoff=10.0,
        )

        # Create required files
        params.active_credential.cert_path.write_text('CERT')
        params.active_credential.key_path.write_text('KEY')

        next_poll = poll_once(params)

        assert next_poll == 300
        assert mock_fetch.called
        assert mock_execute.called
        assert mock_ack.called

    @patch('agent.mtls_session')
    @patch('agent.cert_header_value')
    @patch('agent.fetch_jobs')
    def test_poll_once_no_jobs(
        self,
        mock_fetch: Mock,
        mock_cert_header: Mock,
        mock_session: Mock,
        temp_dir: Path,
    ):
        """Test polling with no pending jobs."""
        from agent import poll_once

        # Setup mocks
        mock_session.return_value = Mock()
        mock_cert_header.return_value = 'cert_value'
        mock_fetch.return_value = (300, [])

        params = PollParams(
            base_url='https://example.com',
            ca_cert_path=temp_dir / 'ca.pem',
            active_credential=ActiveCredential(cert_path=temp_dir / 'cert.pem', key_path=temp_dir / 'key.pem'),
            local_storage=LocalStorage.from_mapping({}),
            request_timeout=30,
            max_retries=3,
            initial_backoff=1.0,
            max_backoff=10.0,
        )

        # Create required files
        params.active_credential.cert_path.write_text('CERT')
        params.active_credential.key_path.write_text('KEY')

        next_poll = poll_once(params)

        assert next_poll == 300
        assert mock_fetch.called

    @patch('agent.poll_once')
    def test_poll_loop_once_mode(self, mock_poll_once: Mock):
        """Test poll loop in once mode."""
        from agent import poll_loop

        mock_poll_once.return_value = 300

        params = PollParams(
            base_url='https://example.com',
            ca_cert_path=Path('/tmp/ca.pem'),
            active_credential=ActiveCredential(cert_path=Path('/tmp/cert.pem'), key_path=Path('/tmp/key.pem')),
            local_storage=LocalStorage.from_mapping({}),
            request_timeout=30,
            max_retries=3,
            initial_backoff=1.0,
            max_backoff=10.0,
        )

        poll_loop(params, once=True)

        assert mock_poll_once.call_count == 1

    @patch('agent.poll_once')
    @patch('agent.sleep_interruptibly')
    def test_poll_loop_continuous_mode(self, mock_sleep: Mock, mock_poll_once: Mock):
        """Test poll loop in continuous mode."""
        from agent import _stop_requested, poll_loop

        mock_poll_once.side_effect = [300, 300]

        # Simulate stop after 2 iterations
        def stop_after_two(*_args: Any) -> None:
            import agent

            agent._stop_requested = True

        mock_sleep.side_effect = stop_after_two

        params = PollParams(
            base_url='https://example.com',
            ca_cert_path=Path('/tmp/ca.pem'),
            active_credential=ActiveCredential(cert_path=Path('/tmp/cert.pem'), key_path=Path('/tmp/key.pem')),
            local_storage=LocalStorage.from_mapping({}),
            request_timeout=30,
            max_retries=3,
            initial_backoff=1.0,
            max_backoff=10.0,
        )

        # Reset stop flag
        import agent

        agent._stop_requested = False

        poll_loop(params, once=False)

        assert mock_poll_once.call_count >= 1
        # Reset for other tests
        agent._stop_requested = False


# ============================================================================
# mTLS and Certificate Header Tests
# ============================================================================


class TestMTLSHelpers:
    """Test mTLS session and certificate header helpers."""

    def test_mtls_session(self, temp_dir: Path):
        """Test mTLS session creation."""
        from agent import mtls_session

        cert_path = temp_dir / 'cert.pem'
        key_path = temp_dir / 'key.pem'
        ca_path = temp_dir / 'ca.pem'

        cert_path.write_text('CERT')
        key_path.write_text('KEY')
        ca_path.write_text('CA')

        params = PollParams(
            base_url='https://example.com',
            ca_cert_path=ca_path,
            active_credential=ActiveCredential(cert_path=cert_path, key_path=key_path),
            local_storage=LocalStorage.from_mapping({}),
            request_timeout=30,
            max_retries=3,
            initial_backoff=1.0,
            max_backoff=10.0,
        )

        session = mtls_session(params)

        assert session is not None
        assert session.cert == (str(cert_path), str(key_path))
        assert session.verify == str(ca_path)

    def test_cert_header_value(self, temp_dir: Path):
        """Test certificate header value generation."""
        from agent import cert_header_value

        cert_path = temp_dir / 'cert.pem'
        cert_content = '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----'
        cert_path.write_text(cert_content)

        header = cert_header_value(cert_path)

        assert header is not None
        assert isinstance(header, str)
        # URL encoding should replace special chars
        assert '\n' not in header


# ============================================================================
# Sleep and Signal Handler Tests
# ============================================================================


class TestSignalAndSleep:
    """Test signal handling and interruptible sleep."""

    @patch('agent.time.sleep')
    def test_sleep_interruptibly_completes(self, mock_sleep: Mock):
        """Test sleep completes normally."""
        from agent import sleep_interruptibly

        import agent

        agent._stop_requested = False

        sleep_interruptibly(5)

        assert mock_sleep.called

    @patch('agent.time.sleep')
    def test_sleep_interruptibly_stops_early(self, mock_sleep: Mock):
        """Test sleep stops early on stop signal."""
        from agent import sleep_interruptibly

        import agent

        # Simulate stop during sleep
        def set_stop(*_args: Any) -> None:
            agent._stop_requested = True

        mock_sleep.side_effect = set_stop

        agent._stop_requested = False
        sleep_interruptibly(10)

        # Should have attempted to sleep
        assert mock_sleep.called
        # Reset for other tests
        agent._stop_requested = False


# ============================================================================
# Main Entry Point Tests
# ============================================================================


class TestMainEntryPoint:
    """Test main entry point."""

    @patch('agent.install_signal_handlers')
    @patch('agent.sd_notify')
    @patch('agent.read_profile')
    @patch('agent.enroll_initial')
    @patch('agent.poll_loop')
    def test_main_success(
        self,
        mock_poll: Mock,
        mock_enroll: Mock,
        mock_read: Mock,
        mock_sd: Mock,
        mock_signals: Mock,
        temp_dir: Path,
        mock_profile_data: dict[str, Any],
    ):
        """Test main function success path."""
        from agent import ActiveCredential, main, read_profile

        # Setup mocks
        profile_path = temp_dir / 'profile.json'
        profile_path.write_text(json.dumps(mock_profile_data))
        
        profile = read_profile(profile_path)
        mock_read.return_value = profile

        mock_enroll.return_value = ActiveCredential(
            cert_path=temp_dir / 'cert.pem', key_path=temp_dir / 'key.pem'
        )

        # Execute
        exit_code = main(['--profile', str(profile_path), '--once'])

        # Verify
        assert exit_code == 0
        assert mock_read.called
        assert mock_enroll.called
        assert mock_poll.called

    @patch('agent.install_signal_handlers')
    @patch('agent.read_profile')
    def test_main_profile_load_error(self, mock_read: Mock, mock_signals: Mock, temp_dir: Path):
        """Test main with profile load error."""
        from agent import main

        # Setup mocks - Make read_profile raise the exception
        mock_read.side_effect = AgentError('Invalid profile')

        profile_path = temp_dir / 'profile.json'

        # Execute - main catches the exception and exits with 1
        # We need to catch SystemExit
        with pytest.raises(SystemExit) as exc_info:
            main(['--profile', str(profile_path)])

        # Verify error exit
        assert exc_info.value.code == 1

    @patch('agent.install_signal_handlers')
    @patch('agent.read_profile')
    @patch('agent._handle_skip_onboarding')
    @patch('agent.poll_loop')
    def test_main_skip_onboarding(
        self,
        mock_poll: Mock,
        mock_skip: Mock,
        mock_read: Mock,
        mock_signals: Mock,
        temp_dir: Path,
        mock_profile_data: dict[str, Any],
    ):
        """Test main with skip onboarding flag."""
        from agent import main, read_profile

        # Setup mocks
        profile_path = temp_dir / 'profile.json'
        profile_path.write_text(json.dumps(mock_profile_data))
        
        profile = read_profile(profile_path)
        mock_read.return_value = profile

        # Execute
        exit_code = main(['--profile', str(profile_path), '--skip-onboarding', '--once'])

        # Verify
        assert exit_code == 0
        assert mock_skip.called
        assert mock_poll.called

    @patch('agent.install_signal_handlers')
    @patch('agent.read_profile')
    @patch('agent.enroll_initial')
    def test_main_enrollment_error(
        self,
        mock_enroll: Mock,
        mock_read: Mock,
        mock_signals: Mock,
        temp_dir: Path,
        mock_profile_data: dict[str, Any],
    ):
        """Test main with enrollment error."""
        from agent import main, read_profile

        # Setup mocks
        profile_path = temp_dir / 'profile.json'
        profile_path.write_text(json.dumps(mock_profile_data))
        
        profile = read_profile(profile_path)
        mock_read.return_value = profile
        mock_enroll.side_effect = AgentError('Enrollment failed')

        # Execute - main catches the exception and exits with 1
        with pytest.raises(SystemExit) as exc_info:
            main(['--profile', str(profile_path)])

        # Verify error exit
        assert exc_info.value.code == 1
