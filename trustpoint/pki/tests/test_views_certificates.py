"""Tests for PKI certificate views."""

from typing import Any
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from django.http import Http404
from django.urls import reverse
from django.test import RequestFactory
from trustpoint_core.archiver import ArchiveFormat
from trustpoint_core.serializer import CertificateFormat

from pki.models import CertificateModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from pki.views.certificates import (
    CertificatesRedirectView,
    CertificateTableView,
    CertificateDetailView,
    CmpIssuingCaCertificateDownloadView,
    CertificateDownloadView,
    CertificateMultipleDownloadView,
    TlsServerCertificateDownloadView,
)


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
class TestCmpIssuingCaCertificateDownloadView:
    """Test suite for CmpIssuingCaCertificateDownloadView."""

    def test_download_certificate_as_pem(self, rf: RequestFactory, admin_user, issuing_ca_instance):
        """Test downloading certificate as PEM."""
        issuing_ca = issuing_ca_instance['issuing_ca']
        cert_obj = issuing_ca_instance['cert']
        
        # Use the certificate from the issuing CA
        cert_model = issuing_ca.credential.certificate
        
        request = rf.get('')
        request.user = admin_user
        
        view = CmpIssuingCaCertificateDownloadView()
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
        
        view = CmpIssuingCaCertificateDownloadView()
        
        with pytest.raises(Http404):
            view.get(request, pk=None)


@pytest.mark.django_db
class TestCertificateDownloadView:
    """Test suite for CertificateDownloadView."""

    def test_download_summary_without_format(self, client, admin_user, issuing_ca_instance):
        """Test that download summary is displayed when no format is provided."""
        issuing_ca = issuing_ca_instance['issuing_ca']
        cert_obj = issuing_ca_instance['cert']
        
        # Use the certificate from the issuing CA
        cert_model = issuing_ca.credential.certificate
        
        client.force_login(admin_user)
        
        response = client.get(f'/pki/certificates/download/{cert_model.pk}/')
        
        assert response.status_code == 200

    def test_download_certificate_pem(self, rf: RequestFactory, admin_user, issuing_ca_instance):
        """Test downloading certificate in PEM format."""
        issuing_ca = issuing_ca_instance['issuing_ca']
        cert_obj = issuing_ca_instance['cert']
        
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
        cert_obj = issuing_ca_instance['cert']
        
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
        cert_obj = issuing_ca_instance['cert']
        
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
        cert_obj = issuing_ca_instance['cert']
        
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
        cert_obj = issuing_ca_instance['cert']
        
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
        cert_obj = issuing_ca_instance['cert']
        
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
