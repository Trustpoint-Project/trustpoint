"""Tests for pki.filters module."""

from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.test import RequestFactory
from django.utils import timezone

from pki.filters import CertificateFilter, TruststoreFilter
from pki.models import CertificateModel
from pki.models.certificate import RevokedCertificateModel
from pki.models.truststore import TruststoreModel


def _create_certificate(
    rsa_private_key: rsa.RSAPrivateKey,
    common_name: str,
    not_valid_before,
    not_valid_after,
) -> CertificateModel:
    """Create and persist a certificate model for filter tests."""
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'DE'),
    ])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(rsa_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=rsa_private_key, algorithm=hashes.SHA256())
    )
    return CertificateModel.save_certificate(certificate)


@pytest.mark.django_db
class TestTruststoreFilter:
    """Test the TruststoreFilter class."""

    @pytest.fixture
    def truststore_instances(self):
        """Create test truststore instances."""
        # Create truststores with different intended usages
        ts1 = TruststoreModel.objects.create(
            unique_name='test_truststore_1',
            intended_usage=TruststoreModel.IntendedUsage.TLS
        )
        ts2 = TruststoreModel.objects.create(
            unique_name='test_truststore_2',
            intended_usage=TruststoreModel.IntendedUsage.IDEVID
        )
        ts3 = TruststoreModel.objects.create(
            unique_name='another_truststore',
            intended_usage=TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN
        )
        return [ts1, ts2, ts3]

    def test_filter_by_unique_name_exact_match(self, truststore_instances):
        """Test filtering by exact unique name."""
        request_factory = RequestFactory()
        request = request_factory.get('/?unique_name=test_truststore_1')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 1
        assert filterset.qs.first().unique_name == 'test_truststore_1'

    def test_filter_by_unique_name_icontains(self, truststore_instances):
        """Test case-insensitive substring filtering by unique name."""
        request_factory = RequestFactory()
        request = request_factory.get('/?unique_name=test')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 2
        unique_names = [ts.unique_name for ts in filterset.qs]
        assert 'test_truststore_1' in unique_names
        assert 'test_truststore_2' in unique_names

    def test_filter_by_unique_name_case_insensitive(self, truststore_instances):
        """Test that unique_name filtering is case-insensitive."""
        request_factory = RequestFactory()
        request = request_factory.get('/?unique_name=TEST')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 2

    def test_filter_by_intended_usage(self, truststore_instances):
        """Test filtering by intended usage."""
        request_factory = RequestFactory()
        request = request_factory.get(f'/?intended_usage={TruststoreModel.IntendedUsage.TLS}')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 1
        assert filterset.qs.first().intended_usage == TruststoreModel.IntendedUsage.TLS

    def test_filter_by_issuing_ca_chain_usage(self, truststore_instances):
        """Test filtering by ISSUING_CA_CHAIN intended usage."""
        request_factory = RequestFactory()
        request = request_factory.get(f'/?intended_usage={TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN}')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 1
        assert filterset.qs.first().intended_usage == TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN
        assert filterset.qs.first().unique_name == 'another_truststore'

    def test_combined_filters(self, truststore_instances):
        """Test combining unique_name and intended_usage filters."""
        request_factory = RequestFactory()
        request = request_factory.get(f'/?unique_name=another&intended_usage={TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN}')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 1
        assert filterset.qs.first().unique_name == 'another_truststore'
        assert filterset.qs.first().intended_usage == TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN

    def test_combined_filters_no_match(self, truststore_instances):
        """Test combining filters that don't match anything."""
        request_factory = RequestFactory()
        request = request_factory.get(f'/?unique_name=test&intended_usage={TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN}')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 0

    def test_no_filters(self, truststore_instances):
        """Test that no filters returns all truststores."""
        request_factory = RequestFactory()
        request = request_factory.get('/')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 3

    def test_empty_filters(self, truststore_instances):
        """Test that empty filter values don't filter anything."""
        request_factory = RequestFactory()
        request = request_factory.get('/?unique_name=&intended_usage=')
        filterset = TruststoreFilter(request.GET, queryset=TruststoreModel.objects.all())

        assert filterset.qs.count() == 3

    def test_filter_form_attributes(self, truststore_instances):
        """Test that form widgets have correct CSS classes."""
        filterset = TruststoreFilter(queryset=TruststoreModel.objects.all())
        
        # Check that unique_name field has the correct widget class
        assert 'form-control' in filterset.form.fields['unique_name'].widget.attrs['class']
        
        # Check that intended_usage field has the correct widget class
        assert 'form-select' in filterset.form.fields['intended_usage'].widget.attrs['class']


@pytest.mark.django_db
class TestCertificateFilter:
    """Test the CertificateFilter class."""

    @pytest.fixture
    def certificate_instances(self, rsa_private_key: rsa.RSAPrivateKey):
        """Create certificates covering the visible certificate-state filters."""
        now = timezone.now()
        active = _create_certificate(
            rsa_private_key,
            'active-cert',
            now - timedelta(days=5),
            now + timedelta(days=60),
        )
        expiring = _create_certificate(
            rsa_private_key,
            'expiring-cert',
            now - timedelta(days=5),
            now + timedelta(days=10),
        )
        expired = _create_certificate(
            rsa_private_key,
            'expired-cert',
            now - timedelta(days=60),
            now - timedelta(days=1),
        )
        not_yet_valid = _create_certificate(
            rsa_private_key,
            'future-cert',
            now + timedelta(days=2),
            now + timedelta(days=60),
        )
        revoked = _create_certificate(
            rsa_private_key,
            'revoked-cert',
            now - timedelta(days=5),
            now + timedelta(days=60),
        )
        RevokedCertificateModel.objects.create(certificate=revoked)
        return {
            'active': active,
            'expiring': expiring,
            'expired': expired,
            'not_yet_valid': not_yet_valid,
            'revoked': revoked,
        }

    def test_filter_by_common_name(self, certificate_instances):
        """Common-name search should filter certificates case-insensitively."""
        del certificate_instances
        request = RequestFactory().get('/?common_name=expiring')
        filterset = CertificateFilter(request.GET, queryset=CertificateModel.objects.all())

        assert list(filterset.qs.values_list('common_name', flat=True)) == ['expiring-cert']

    def test_filter_by_status_ok(self, certificate_instances):
        """OK status should include both long-lived and soon-expiring valid certificates."""
        request = RequestFactory().get('/?status=ok')
        filterset = CertificateFilter(request.GET, queryset=CertificateModel.objects.all())

        assert set(filterset.qs) == {
            certificate_instances['active'],
            certificate_instances['expiring'],
        }

    def test_filter_by_status_revoked(self, certificate_instances):
        """Revoked status should include revoked certificates regardless of validity window."""
        request = RequestFactory().get('/?status=revoked')
        filterset = CertificateFilter(request.GET, queryset=CertificateModel.objects.all())

        assert set(filterset.qs) == {certificate_instances['revoked']}

    def test_filter_by_expiry_window_within_30_days(self, certificate_instances):
        """Expiry window should narrow valid certificates by horizon."""
        request = RequestFactory().get('/?status=ok&expiry_window=30_days')
        filterset = CertificateFilter(request.GET, queryset=CertificateModel.objects.all())

        assert set(filterset.qs) == {certificate_instances['expiring']}

    def test_filter_by_self_signed(self, certificate_instances):
        """Self-signed filter should keep the generated self-signed certificates."""
        del certificate_instances
        request = RequestFactory().get('/?is_self_signed=true')
        filterset = CertificateFilter(request.GET, queryset=CertificateModel.objects.all())

        assert filterset.qs.count() == CertificateModel.objects.count()

    def test_filter_form_attributes(self):
        """Certificate filter widgets should use the compact table-filter styling."""
        filterset = CertificateFilter(queryset=CertificateModel.objects.all())

        assert 'form-control' in filterset.form.fields['common_name'].widget.attrs['class']
        assert 'form-select' in filterset.form.fields['status'].widget.attrs['class']
        assert 'form-select' in filterset.form.fields['expiry_window'].widget.attrs['class']
        assert 'form-select' in filterset.form.fields['is_self_signed'].widget.attrs['class']
