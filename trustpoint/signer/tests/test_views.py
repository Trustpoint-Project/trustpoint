"""Tests for signer.views module."""

from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.hashes import SHA256
from django.contrib.messages import get_messages
from django.http import HttpRequest
from django.test import RequestFactory
from django.urls import reverse
from trustpoint_core.serializer import CertificateSerializer, CredentialSerializer, PrivateKeySerializer

from management.models import KeyStorageConfig
from signer.models import SignedMessageModel, SignerModel
from signer.views import (
    SignedMessagesListView,
    SignerAddFileImportFileTypeSelectView,
    SignerAddFileImportPkcs12View,
    SignerAddFileImportSeparateFilesView,
    SignerAddMethodSelectView,
    SignerBulkDeleteConfirmView,
    SignerConfigView,
    SignerTableView,
    SignHashSuccessView,
    SignHashView,
)


@pytest.fixture
def key_storage_config():
    """Create a software key storage configuration."""
    return KeyStorageConfig.objects.create(storage_type='software')


@pytest.fixture
def sample_signer(key_storage_config):
    """Create a sample signer for testing."""
    from datetime import datetime, timedelta, timezone as dt_timezone

    # Generate RSA key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Create certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Test Signer'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, 'Test Organization'),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(dt_timezone.utc))
        .not_valid_after(datetime.now(dt_timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, SHA256())
    )

    # Create credential serializer
    pk_serializer = PrivateKeySerializer(private_key)
    cert_serializer = CertificateSerializer(cert)
    cred_serializer = CredentialSerializer.from_serializers(
        private_key_serializer=pk_serializer,
        certificate_serializer=cert_serializer,
    )

    return SignerModel.create_new_signer('test-signer', cred_serializer)


@pytest.fixture
def request_factory():
    """Create a RequestFactory instance."""
    return RequestFactory()


@pytest.mark.django_db
class TestSignerTableView:
    """Test cases for SignerTableView."""

    def test_view_uses_correct_template(self, request_factory):
        """Test view uses correct template."""
        view = SignerTableView()
        assert view.template_name == 'signer/signers.html'

    def test_view_context_object_name(self, request_factory):
        """Test view has correct context object name."""
        view = SignerTableView()
        assert view.context_object_name == 'signers'

    def test_view_uses_correct_model(self, request_factory):
        """Test view uses SignerModel."""
        view = SignerTableView()
        assert view.model == SignerModel

    def test_view_lists_signers(self, request_factory, sample_signer):
        """Test view lists all signers."""
        request = request_factory.get(reverse('signer:signer_list'))
        view = SignerTableView.as_view()
        response = view(request)

        assert response.status_code == 200


@pytest.mark.django_db
class TestSignerAddMethodSelectView:
    """Test cases for SignerAddMethodSelectView."""

    def test_view_uses_correct_template(self):
        """Test view uses correct template."""
        view = SignerAddMethodSelectView()
        assert view.template_name == 'signer/add/method_select.html'

    def test_form_valid_redirects_to_file_import(self, request_factory):
        """Test form_valid redirects to file import."""
        from signer.forms import SignerAddMethodSelectForm

        request = request_factory.post(reverse('signer:signer-add-method_select'))
        view = SignerAddMethodSelectView()
        view.request = request

        form = SignerAddMethodSelectForm(data={'method_select': 'local_file_import'})
        assert form.is_valid()

        response = view.form_valid(form)
        assert response.status_code == 302
        assert 'file-import' in response.url or 'file_import' in response.url


@pytest.mark.django_db
class TestSignerAddFileImportFileTypeSelectView:
    """Test cases for SignerAddFileImportFileTypeSelectView."""

    def test_view_uses_correct_template(self):
        """Test view uses correct template."""
        view = SignerAddFileImportFileTypeSelectView()
        assert view.template_name == 'signer/add/file_type_select.html'

    def test_form_valid_pkcs12_redirects(self, request_factory):
        """Test form_valid redirects to PKCS#12 import."""
        from signer.forms import SignerAddFileTypeSelectForm

        request = request_factory.post(reverse('signer:signer-add-file_import-file_type_select'))
        view = SignerAddFileImportFileTypeSelectView()
        view.request = request

        form = SignerAddFileTypeSelectForm(data={'method_select': 'pkcs_12'})
        assert form.is_valid()

        response = view.form_valid(form)
        assert response.status_code == 302
        assert 'pkcs12' in response.url

    def test_form_valid_other_redirects(self, request_factory):
        """Test form_valid redirects to separate files import."""
        from signer.forms import SignerAddFileTypeSelectForm

        request = request_factory.post(reverse('signer:signer-add-file_import-file_type_select'))
        view = SignerAddFileImportFileTypeSelectView()
        view.request = request

        form = SignerAddFileTypeSelectForm(data={'method_select': 'other'})
        assert form.is_valid()

        response = view.form_valid(form)
        assert response.status_code == 302
        assert 'separate-files' in response.url or 'separate_files' in response.url


@pytest.mark.django_db
class TestSignerAddFileImportPkcs12View:
    """Test cases for SignerAddFileImportPkcs12View."""

    def test_view_uses_correct_template(self):
        """Test view uses correct template."""
        view = SignerAddFileImportPkcs12View()
        assert view.template_name == 'signer/add/file_import.html'

    def test_view_success_url(self):
        """Test view has correct success URL."""
        view = SignerAddFileImportPkcs12View()
        assert view.success_url == reverse('signer:signer_list')


@pytest.mark.django_db
class TestSignerAddFileImportSeparateFilesView:
    """Test cases for SignerAddFileImportSeparateFilesView."""

    def test_view_uses_correct_template(self):
        """Test view uses correct template."""
        view = SignerAddFileImportSeparateFilesView()
        assert view.template_name == 'signer/add/file_import.html'

    def test_view_success_url(self):
        """Test view has correct success URL."""
        view = SignerAddFileImportSeparateFilesView()
        assert view.success_url == reverse('signer:signer_list')


@pytest.mark.django_db
class TestSignerConfigView:
    """Test cases for SignerConfigView."""

    def test_view_uses_correct_template(self):
        """Test view uses correct template."""
        view = SignerConfigView()
        assert view.template_name == 'signer/signer_config.html'

    def test_view_context_object_name(self):
        """Test view has correct context object name."""
        view = SignerConfigView()
        assert view.context_object_name == 'signer'

    def test_view_only_allows_get(self):
        """Test view only allows GET requests."""
        view = SignerConfigView()
        assert view.http_method_names == ('get',)

    def test_view_displays_signer_details(self, request_factory, sample_signer):
        """Test view displays signer details."""
        request = request_factory.get(reverse('signer:signer-config', kwargs={'pk': sample_signer.pk}))
        view = SignerConfigView.as_view()
        response = view(request, pk=sample_signer.pk)

        assert response.status_code == 200


@pytest.mark.django_db
class TestSignedMessagesListView:
    """Test cases for SignedMessagesListView."""

    def test_view_uses_correct_template(self):
        """Test view uses correct template."""
        view = SignedMessagesListView()
        assert view.template_name == 'signer/signed_messages.html'

    def test_view_context_object_name(self):
        """Test view has correct context object name."""
        view = SignedMessagesListView()
        assert view.context_object_name == 'signed_messages'

    def test_view_filters_by_signer(self, request_factory, sample_signer):
        """Test view filters signed messages by signer."""
        # Create signed messages
        SignedMessageModel.objects.create(signer=sample_signer, hash_value='abc123', signature='sig123')
        SignedMessageModel.objects.create(signer=sample_signer, hash_value='def456', signature='sig456')

        view = SignedMessagesListView()
        view.kwargs = {'pk': sample_signer.pk}
        queryset = view.get_queryset()

        assert queryset.count() == 2
        assert all(msg.signer == sample_signer for msg in queryset)

    def test_view_orders_by_created_at_desc(self, request_factory, sample_signer):
        """Test view orders signed messages by created_at descending."""
        msg1 = SignedMessageModel.objects.create(signer=sample_signer, hash_value='first', signature='sig1')
        msg2 = SignedMessageModel.objects.create(signer=sample_signer, hash_value='second', signature='sig2')

        view = SignedMessagesListView()
        view.kwargs = {'pk': sample_signer.pk}
        queryset = view.get_queryset()

        # Most recent first
        assert list(queryset)[0].pk == msg2.pk
        assert list(queryset)[1].pk == msg1.pk


@pytest.mark.django_db
class TestSignerBulkDeleteConfirmView:
    """Test cases for SignerBulkDeleteConfirmView."""

    def test_view_uses_correct_template(self):
        """Test view uses correct template."""
        view = SignerBulkDeleteConfirmView()
        assert view.template_name == 'signer/confirm_delete.html'

    def test_view_uses_correct_model(self):
        """Test view uses SignerModel."""
        view = SignerBulkDeleteConfirmView()
        assert view.model == SignerModel

    def test_view_success_url(self):
        """Test view has correct success URL."""
        view = SignerBulkDeleteConfirmView()
        assert view.success_url == reverse('signer:signer_list')


@pytest.mark.django_db
class TestSignHashView:
    """Test cases for SignHashView."""

    def test_view_uses_correct_template(self):
        """Test view uses correct template."""
        view = SignHashView()
        assert view.template_name == 'signer/sign_hash.html'

    def test_view_success_url(self):
        """Test view has correct success URL."""
        view = SignHashView()
        assert view.success_url == reverse('signer:signer_list')

    @patch('signer.views.SignerModel.objects')
    def test_form_valid_signs_hash_with_rsa(self, mock_objects, request_factory, sample_signer):
        """Test form_valid successfully signs hash with RSA key."""
        from signer.forms import SignHashForm

        # Create request with session
        request = request_factory.post(reverse('signer:sign_hash'))
        request.session = {}
        request._messages = Mock()

        view = SignHashView()
        view.request = request

        # Valid SHA256 hash (64 hex chars)
        valid_hash = 'a' * 64

        form = SignHashForm()
        form.cleaned_data = {'signer': sample_signer, 'hash_value': valid_hash}

        with patch.object(sample_signer.credential, 'get_private_key') as mock_get_key:
            # Generate a real RSA key for signing
            from cryptography.hazmat.primitives.asymmetric import rsa

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            mock_get_key.return_value = private_key

            response = view.form_valid(form)

            assert response.status_code == 302
            assert 'success' in response.url  # Check that signed message was created
            assert SignedMessageModel.objects.filter(signer=sample_signer).exists()

    def test_form_valid_stores_signature_in_session(self, request_factory, sample_signer):
        """Test form_valid stores signature data in session."""
        from signer.forms import SignHashForm

        request = request_factory.post(reverse('signer:sign_hash'))
        request.session = {}
        request._messages = Mock()

        view = SignHashView()
        view.request = request

        valid_hash = 'a' * 64

        form = SignHashForm()
        form.cleaned_data = {'signer': sample_signer, 'hash_value': valid_hash}

        with patch.object(sample_signer.credential, 'get_private_key') as mock_get_key:
            from cryptography.hazmat.primitives.asymmetric import rsa

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            mock_get_key.return_value = private_key

            view.form_valid(form)

            assert 'last_signature' in request.session
            signature_data = request.session['last_signature']
            assert 'signer_name' in signature_data
            assert 'hash_algorithm' in signature_data
            assert 'hash_value' in signature_data
            assert 'signature' in signature_data

    def test_form_valid_handles_signing_error(self, request_factory, sample_signer):
        """Test form_valid handles signing errors gracefully."""
        from signer.forms import SignHashForm

        request = request_factory.post(reverse('signer:sign_hash'))
        request.session = {}
        request._messages = Mock()

        view = SignHashView()
        view.request = request

        form = SignHashForm()
        form.cleaned_data = {'signer': sample_signer, 'hash_value': 'a' * 64}

        with patch.object(sample_signer.credential, 'get_private_key') as mock_get_key:
            mock_get_key.side_effect = Exception('Signing failed')

            response = view.form_valid(form)

            # Should return form_invalid response
            assert response.status_code == 200


@pytest.mark.django_db
class TestSignHashSuccessView:
    """Test cases for SignHashSuccessView."""

    def test_view_uses_correct_template(self):
        """Test view uses correct template."""
        view = SignHashSuccessView()
        assert view.template_name == 'signer/sign_hash_success.html'

    def test_get_displays_signature_from_session(self, request_factory):
        """Test GET displays signature data from session."""
        from django.contrib.messages.storage.fallback import FallbackStorage

        request = request_factory.get(reverse('signer:sign_hash_success'))
        request.session = {
            'last_signature': {
                'signer_name': 'test-signer',
                'hash_algorithm': 'SHA256',
                'hash_value': 'a' * 64,
                'signature': 'b' * 128,
            }
        }
        # Use Django's message storage for template rendering
        request._messages = FallbackStorage(request)

        view = SignHashSuccessView()
        response = view.get(request)

        assert response.status_code == 200
        # Session data should be removed after retrieval
        assert 'last_signature' not in request.session

    def test_get_redirects_without_signature_data(self, request_factory):
        """Test GET redirects when no signature data in session."""
        request = request_factory.get(reverse('signer:sign_hash_success'))
        request.session = {}
        request._messages = Mock()

        view = SignHashSuccessView()
        response = view.get(request)

        assert response.status_code == 302
        assert 'sign-hash' in response.url or 'sign_hash' in response.url

    def test_get_context_data_includes_page_category(self):
        """Test get_context_data includes context_page_category."""
        view = SignHashSuccessView()
        context = view.get_context_data()

        assert 'context_page_category' in context
        assert context['context_page_category'] == 'signer'
