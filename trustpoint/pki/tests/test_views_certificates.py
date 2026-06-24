"""Tests for PKI certificate views."""


from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.http import Http404
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone
from trustpoint_core.archiver import ArchiveFormat
from trustpoint_core.serializer import CertificateFormat

from pki.models import CertificateModel
from pki.models.certificate import RevokedCertificateModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from pki.views.certificates import (
    CertificatesRedirectView,
    IssuingCaCertificateDownloadView,
    CertificateDetailView,
    CertificateDownloadView,
    CertificateMultipleDownloadView,
    CertificateTableView,
    TlsServerCertificateDownloadView,
)


def _create_certificate(
    rsa_private_key: rsa.RSAPrivateKey,
    common_name: str,
    not_valid_before,
    not_valid_after,
) -> CertificateModel:
    """Create and persist a certificate model for certificate table tests."""
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
class TestCertificatesRedirectView:
    """Test suite for CertificatesRedirectView."""

    def test_redirect_view_pattern_name(self):
        """Test that the redirect view has correct pattern name."""
        view = CertificatesRedirectView()
        assert view.pattern_name == 'pki:certificates'
        assert view.permanent is False


@pytest.mark.django_db
class TestCertificateTableView:
    """Test suite for CertificateTableView."""

    @pytest.fixture
    def certificate_instances(self, rsa_private_key: rsa.RSAPrivateKey):
        """Create certificates that cover the visible certificate-state filters."""
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

    def test_table_view_renders(self, rf: RequestFactory, admin_user):
        """Test that the certificate table view renders successfully."""
        request = rf.get(reverse('pki:certificates'))
        request.user = admin_user
        
        view = CertificateTableView.as_view()
        response = view(request)
        
        assert response.status_code == 200

    def test_table_view_context_data(self, rf: RequestFactory, admin_user):
        """Test that context data is properly set."""
        request = rf.get(reverse('pki:certificates'))
        request.user = admin_user
        
        view = CertificateTableView()
        view.request = request
        view.kwargs = {}
        view.object_list = view.get_queryset()
        context = view.get_context_data()
        
        assert 'page_category' in context
        assert context['page_category'] == 'pki'
        assert 'page_name' in context
        assert context['page_name'] == 'certificates'
        assert 'certificates' in context

    def test_table_view_pagination(self, rf: RequestFactory, admin_user):
        """Test that pagination is configured."""
        request = rf.get(reverse('pki:certificates'))
        request.user = admin_user
        
        view = CertificateTableView()
        view.request = request
        
        assert view.paginate_by is not None
        assert view.default_sort_param == 'common_name'

    def test_table_view_with_multiple_sort_parameters_redirects(
        self,
        admin_client,
    ) -> None:
        """Multiple sort parameters should collapse to the first one."""
        url = reverse('pki:certificates') + '?sort=common_name&sort=created_at'
        response = admin_client.get(url)

        assert response.status_code == 302
        assert 'sort=common_name' in response.url

    def test_status_and_expiry_window_filters_are_preselected(
        self,
        admin_client,
        certificate_instances,
    ) -> None:
        """Status and expiry filters should stay selected and narrow the table."""
        url = reverse('pki:certificates') + '?status=ok&expiry_window=30_days'
        response = admin_client.get(url)

        assert response.status_code == 200
        assert response.context['filter'].form['status'].value() == 'ok'
        assert response.context['filter'].form['expiry_window'].value() == '30_days'
        assert response.context['filters_active'] is True
        assert certificate_instances['expiring'] in response.context['object_list']
        assert certificate_instances['active'] not in response.context['object_list']
        assert certificate_instances['revoked'] not in response.context['object_list']
        expiring_certificate = next(
            certificate
            for certificate in response.context['object_list']
            if certificate.pk == certificate_instances['expiring'].pk
        )
        assert expiring_certificate.table_status == 'OK'

    def test_sorting_by_certificate_status_uses_annotation(
        self,
        admin_client,
        certificate_instances,
    ) -> None:
        """Status sorting should use the annotated database field instead of the Python property."""
        del certificate_instances
        url = reverse('pki:certificates') + '?sort=certificate_status_sort'
        response = admin_client.get(url)

        assert response.status_code == 200


@pytest.mark.django_db
class TestCertificateDetailView:
    """Test suite for CertificateDetailView."""

    def test_detail_view_get_context_data(self, rf: RequestFactory, admin_user, issuing_ca_instance):
        """Test get_context_data includes subject and issuer entries."""
        issuing_ca = issuing_ca_instance['issuing_ca']
        
        # Use the certificate from the issuing CA's credential
        cert_model = issuing_ca.credential.certificate
        
        request = rf.get('')
        request.user = admin_user
        
        view = CertificateDetailView()
        view.request = request
        view.kwargs = {'pk': cert_model.pk}
        view.object = cert_model
        
        context = view.get_context_data()
        
        assert 'cert' in context
        assert 'subject_entries' in context
        assert 'issuer_entries' in context
        assert 'ip_addresses' in context
        assert isinstance(context['subject_entries'], list)
        assert isinstance(context['issuer_entries'], list)

    def test_detail_view_ip_addresses_in_san(self, rf: RequestFactory, admin_user, issuing_ca_instance):
        """Test that IP addresses from SAN are extracted."""
        issuing_ca = issuing_ca_instance['issuing_ca']
        
        # Use the existing certificate - just test that ip_addresses key exists
        cert_model = issuing_ca.credential.certificate
        
        request = rf.get('')
        request.user = admin_user
        
        view = CertificateDetailView()
        view.request = request
        view.kwargs = {'pk': cert_model.pk}
        view.object = cert_model
        
        context = view.get_context_data()
        
        # ip_addresses list should exist (may be empty for this cert)
        assert 'ip_addresses' in context
        assert isinstance(context['ip_addresses'], list)


@pytest.mark.django_db
class TestIssuingCaCertificateDownloadView:
    """Test suite for IssuingCaCertificateDownloadView."""

    def test_download_certificate_as_pem(self, rf: RequestFactory, admin_user, issuing_ca_instance):
        """Test downloading certificate as PEM."""
        issuing_ca = issuing_ca_instance['issuing_ca']

        
        # Use the certificate from the issuing CA
        cert_model = issuing_ca.credential.certificate
        
        request = rf.get('')
        request.user = admin_user
        
        view = IssuingCaCertificateDownloadView()
        view.kwargs = {'pk': cert_model.pk}
        
        response = view.get(request, pk=str(cert_model.pk))
        
        assert response.status_code == 200
        assert response['Content-Type'] == CertificateFormat.PEM.mime_type
        assert 'attachment' in response['Content-Disposition']
        assert 'issuing_ca_cert.pem' in response['Content-Disposition']
        assert b'-----BEGIN CERTIFICATE-----' in response.content

    def test_download_raises_404_without_pk(self, rf: RequestFactory, admin_user):
        """Test that Http404 is raised when pk is None."""
        request = rf.get('')
        request.user = admin_user
        
        view = IssuingCaCertificateDownloadView()
        
        with pytest.raises(Http404):
            view.get(request, pk=None)


@pytest.mark.django_db
class TestCertificateDownloadView:
    """Test suite for CertificateDownloadView."""

    def test_download_summary_without_format(self, client, admin_user, issuing_ca_instance):
        """Test that download summary is displayed when no format is provided."""
        issuing_ca = issuing_ca_instance['issuing_ca']

        
        # Use the certificate from the issuing CA
        cert_model = issuing_ca.credential.certificate
        
        client.force_login(admin_user)
        
        response = client.get(f'/pki/certificates/download/{cert_model.pk}/')
        
        assert response.status_code == 200

    def test_download_certificate_pem(self, rf: RequestFactory, admin_user, issuing_ca_instance):
        """Test downloading certificate in PEM format."""
        issuing_ca = issuing_ca_instance['issuing_ca']

        
        # Use the certificate from the issuing CA
        cert_model = issuing_ca.credential.certificate
        
        request = rf.get('')
        request.user = admin_user
        
        view = CertificateDownloadView()
        view.kwargs = {'pk': cert_model.pk, 'file_format': 'pem'}
        
        response = view.get(request, pk=str(cert_model.pk), file_format='pem')
        
        assert response.status_code == 200
        assert response['Content-Type'] == CertificateFormat.PEM.mime_type
        assert 'attachment' in response['Content-Disposition']
        assert b'-----BEGIN CERTIFICATE-----' in response.content

    def test_download_certificate_der(self, rf: RequestFactory, admin_user, issuing_ca_instance):
        """Test downloading certificate in DER format."""
        issuing_ca = issuing_ca_instance['issuing_ca']

        
        # Use the certificate from the issuing CA
        cert_model = issuing_ca.credential.certificate
        
        request = rf.get('')
        request.user = admin_user
        
        view = CertificateDownloadView()
        view.kwargs = {'pk': cert_model.pk, 'file_format': 'der'}
        
        response = view.get(request, pk=str(cert_model.pk), file_format='der')
        
        assert response.status_code == 200
        assert response['Content-Type'] == CertificateFormat.DER.mime_type
        assert 'attachment' in response['Content-Disposition']

    def test_download_with_custom_filename(self, rf: RequestFactory, admin_user, issuing_ca_instance):
        """Test downloading with custom filename."""
        issuing_ca = issuing_ca_instance['issuing_ca']

        
        # Use the certificate from the issuing CA
        cert_model = issuing_ca.credential.certificate
        
        request = rf.get('')
        request.user = admin_user
        
        view = CertificateDownloadView()
        view.kwargs = {'pk': cert_model.pk, 'file_format': 'pem', 'file_name': 'my_cert.pem'}
        
        response = view.get(request, pk=str(cert_model.pk), file_format='pem')
        
        assert response.status_code == 200
        assert 'my_cert.pem' in response['Content-Disposition']

    def test_download_uses_common_name_for_filename(self, rf: RequestFactory, admin_user, issuing_ca_instance):
        """Test that common name is used for filename when available."""
        issuing_ca = issuing_ca_instance['issuing_ca']

        
        # Use the certificate from the issuing CA
        cert_model = issuing_ca.credential.certificate
        
        request = rf.get('')
        request.user = admin_user
        
        view = CertificateDownloadView()
        view.kwargs = {'pk': cert_model.pk, 'file_format': 'pem'}
        
        response = view.get(request, pk=str(cert_model.pk), file_format='pem')
        
        assert response.status_code == 200
        # Common name should be sanitized and used in filename
        assert '.pem' in response['Content-Disposition']

    def test_download_invalid_format_raises_404(self, rf: RequestFactory, admin_user, issuing_ca_instance):
        """Test that invalid format raises Http404."""
        issuing_ca = issuing_ca_instance['issuing_ca']

        # Use the certificate from the issuing CA
        cert_model = issuing_ca.credential.certificate
        
        request = rf.get('')
        request.user = admin_user
        
        view = CertificateDownloadView()
        view.kwargs = {'pk': cert_model.pk, 'file_format': 'invalid_format'}
        
        with pytest.raises(Http404):
            view.get(request, pk=str(cert_model.pk), file_format='invalid_format')

    def test_download_raises_404_without_pk(self, rf: RequestFactory, admin_user):
        """Test that Http404 is raised when pk is None."""
        request = rf.get('')
        request.user = admin_user
        
        view = CertificateDownloadView()
        
        with pytest.raises(Http404):
            view.get(request, pk=None)


@pytest.mark.django_db
class TestCertificateMultipleDownloadView:
    """Test suite for CertificateMultipleDownloadView."""

    def test_get_context_data_includes_pks_path(self, rf: RequestFactory, admin_user, issuing_ca_instance):
        """Test that pks_path is included in context data."""
        issuing_ca = issuing_ca_instance['issuing_ca']

        
        # Use the certificate from the issuing CA
        cert1 = issuing_ca.credential.certificate
        cert2 = issuing_ca.credential.certificate
        
        request = rf.get('')
        request.user = admin_user
        
        view = CertificateMultipleDownloadView()
        view.request = request
        view.kwargs = {'pks': f'{cert1.pk}/{cert2.pk}'}
        view.object_list = view.get_queryset()
        
        context = view.get_context_data()
        
        assert 'pks_path' in context
        assert context['pks_path'] == f'{cert1.pk}/{cert2.pk}'

    def test_download_multiple_certificates_as_zip(self, rf: RequestFactory, admin_user, issuing_ca_instance):
        """Test downloading single certificate as ZIP archive (multiple download view)."""
        issuing_ca = issuing_ca_instance['issuing_ca']
        
        # Use the certificate from the issuing CA
        cert1 = issuing_ca.credential.certificate
        
        request = rf.get('')
        request.user = admin_user
        
        view = CertificateMultipleDownloadView()
        view.kwargs = {'pks': str(cert1.pk)}
        
        response = view.get(
            request, 
            pks=str(cert1.pk),
            file_format='pem',
            archive_format='zip'
        )
        
        assert response.status_code == 200
        assert response['Content-Type'] == ArchiveFormat.ZIP.mime_type
        assert 'certificates.zip' in response['Content-Disposition']

    def test_download_multiple_certificates_as_tar_gz(self, rf: RequestFactory, admin_user, issuing_ca_instance):
        """Test downloading single certificate as TAR.GZ archive (multiple download view)."""
        issuing_ca = issuing_ca_instance['issuing_ca']

        # Use the certificate from the issuing CA
        cert1 = issuing_ca.credential.certificate

        request = rf.get('')
        request.user = admin_user

        view = CertificateMultipleDownloadView()
        view.kwargs = {'pks': str(cert1.pk)}

        response = view.get(
            request,
            pks=str(cert1.pk),
            file_format='pem',
            archive_format='tar_gz'
        )
        
        assert response.status_code == 200
        assert response['Content-Type'] == ArchiveFormat.TAR_GZ.mime_type
        assert 'certificates.tar.gz' in response['Content-Disposition']

    def test_download_summary_without_formats(self, client, admin_user, issuing_ca_instance, credential_instance):
        """Test that download summary is displayed when formats are not provided."""
        issuing_ca = issuing_ca_instance['issuing_ca']
        
        # Use two different certificates
        cert1 = issuing_ca.credential.certificate
        cert2 = credential_instance['credential'].certificate
        
        client.force_login(admin_user)
        
        # URL pattern requires at least 2 PKs: pattern is ([0-9]+/)+[0-9]+
        # Note: URL is /certificates/download/ not /certificates/download-multiple/
        response = client.get(f'/pki/certificates/download/{cert1.pk}/{cert2.pk}/')
        
        assert response.status_code == 200

    def test_download_raises_404_without_pks(self, rf: RequestFactory, admin_user):
        """Test that Http404 is raised when pks is None."""
        request = rf.get('')
        request.user = admin_user
        
        view = CertificateMultipleDownloadView()
        
        with pytest.raises(Http404):
            view.get(request, pks=None)

    def test_download_raises_404_for_invalid_pks(self, rf: RequestFactory, admin_user):
        """Test that Http404 is raised when some pks don't exist."""
        request = rf.get('')
        request.user = admin_user
        
        view = CertificateMultipleDownloadView()
        view.kwargs = {'pks': '99999/88888'}
        
        with pytest.raises(Http404):
            view.get(request, pks='99999/88888', file_format='pem', archive_format='zip')

    def test_download_invalid_file_format_raises_404(self, rf: RequestFactory, admin_user, issuing_ca_instance):
        """Test that invalid file format raises Http404."""
        issuing_ca = issuing_ca_instance['issuing_ca']
        
        # Use the certificate from the issuing CA
        cert1 = issuing_ca.credential.certificate
        
        request = rf.get('')
        request.user = admin_user
        
        view = CertificateMultipleDownloadView()
        view.kwargs = {'pks': str(cert1.pk)}
        
        with pytest.raises(Http404):
            view.get(request, pks=str(cert1.pk), file_format='invalid', archive_format='zip')

    def test_download_invalid_archive_format_raises_404(self, rf: RequestFactory, admin_user, issuing_ca_instance):
        """Test that invalid archive format raises Http404."""
        issuing_ca = issuing_ca_instance['issuing_ca']
        
        # Use the certificate from the issuing CA
        cert1 = issuing_ca.credential.certificate
        
        request = rf.get('')
        request.user = admin_user
        
        view = CertificateMultipleDownloadView()
        view.kwargs = {'pks': str(cert1.pk)}
        
        with pytest.raises(Http404):
            view.get(request, pks=str(cert1.pk), file_format='pem', archive_format='invalid')


@pytest.mark.django_db
class TestTlsServerCertificateDownloadView:
    """Test suite for TlsServerCertificateDownloadView."""

    def test_download_tls_server_certificate(self, rf: RequestFactory, admin_user, tls_client_credential_instance):
        """Test downloading the TLS server certificate."""
        # Create active TLS server credential using the issued credential
        issued_cred = tls_client_credential_instance['issued_credential']
        ActiveTrustpointTlsServerCredentialModel.objects.update_or_create(
            id=1,
            defaults={'credential': issued_cred.credential}
        )
        
        request = rf.get('')
        request.user = admin_user
        
        view = TlsServerCertificateDownloadView()
        
        response = view.get(request)
        
        assert response.status_code == 200
        assert response['Content-Type'] == CertificateFormat.PEM.mime_type
        assert 'server_cert.pem' in response['Content-Disposition']
        assert b'-----BEGIN CERTIFICATE-----' in response.content

    def test_download_raises_404_when_no_tls_cert(self, rf: RequestFactory, admin_user):
        """Test that Http404 is raised when no TLS certificate is configured."""
        # Ensure no TLS certificate exists
        ActiveTrustpointTlsServerCredentialModel.objects.all().delete()
        
        request = rf.get('')
        request.user = admin_user
        
        view = TlsServerCertificateDownloadView()
        
        with pytest.raises(Http404, match='No TLS server certificate available'):
            view.get(request)
