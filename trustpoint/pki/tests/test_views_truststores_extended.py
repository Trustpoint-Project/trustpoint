# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for truststore detail, download and deletion views."""

from __future__ import annotations

from http import HTTPStatus

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse

from pki.forms.truststores import TruststoreAddForm
from pki.models.truststore import TruststoreModel
from pki.util.x509 import CertificateGenerator

pytestmark = pytest.mark.django_db

User = get_user_model()


@pytest.fixture
def authenticated_client() -> Client:
    """Return a logged-in client."""
    client = Client()
    client.force_login(User.objects.create_user(username='ts-user', password='ts-pass-123'))  # noqa: S106
    return client


@pytest.fixture
def truststore() -> TruststoreModel:
    """Return a stored truststore holding a real CA chain."""
    root, root_key = CertificateGenerator.create_root_ca('TS Root', path_length=2)
    intermediate, _ = CertificateGenerator.create_issuing_ca(root_key, 'TS Root', 'TS Intermediate')
    return TruststoreAddForm.save_trust_store(
        unique_name='view-truststore',
        intended_usage=TruststoreModel.IntendedUsage.GENERIC,
        certificates=[intermediate, root],
    )


class TestTruststoreDetailView:
    """Truststore detail rendering."""

    def test_detail_lists_subject_and_issuer_entries(
        self, authenticated_client: Client, truststore: TruststoreModel
    ) -> None:
        """The detail context exposes decoded subject and issuer attributes."""
        response = authenticated_client.get(
            reverse('pki:truststore-detail', kwargs={'pk': truststore.pk})
        )

        assert response.status_code == HTTPStatus.OK
        cert_context = response.context['cert_context']
        assert len(cert_context) == 2
        first = cert_context[0]
        assert first['subject_entries']
        assert all('name' in entry and 'value' in entry for entry in first['subject_entries'])
        assert all('oid' in entry for entry in first['issuer_entries'])

    def test_unknown_truststore_returns_404(self, authenticated_client: Client) -> None:
        """An unknown truststore id yields a 404."""
        response = authenticated_client.get(reverse('pki:truststore-detail', kwargs={'pk': 999999}))

        assert response.status_code == HTTPStatus.NOT_FOUND


class TestTruststoreDownloadView:
    """Single truststore downloads."""

    def test_summary_page_is_rendered_without_format(
        self, authenticated_client: Client, truststore: TruststoreModel
    ) -> None:
        """Without a format the download summary page is shown."""
        response = authenticated_client.get(
            reverse('pki:truststore-download', kwargs={'pk': truststore.pk})
        )

        assert response.status_code == HTTPStatus.OK

    def test_pem_download_contains_every_certificate(
        self, authenticated_client: Client, truststore: TruststoreModel
    ) -> None:
        """A PEM download returns all stored certificates."""
        response = authenticated_client.get(
            reverse(
                'pki:truststore-file-download',
                kwargs={'pk': truststore.pk, 'file_format': 'pem'},
            )
        )

        assert response.status_code == HTTPStatus.OK
        assert response.content.count(b'BEGIN CERTIFICATE') == 2
        assert 'attachment; filename="truststore.pem"' in response['Content-Disposition']

    def test_unknown_format_returns_404(
        self, authenticated_client: Client, truststore: TruststoreModel
    ) -> None:
        """An unsupported file format is rejected."""
        response = authenticated_client.get(
            reverse(
                'pki:truststore-file-download',
                kwargs={'pk': truststore.pk, 'file_format': 'badformat'},
            )
        )

        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_downloaded_bundle_contains_no_private_keys(
        self, authenticated_client: Client, truststore: TruststoreModel
    ) -> None:
        """Trust bundles never contain private key material."""
        response = authenticated_client.get(
            reverse(
                'pki:truststore-file-download',
                kwargs={'pk': truststore.pk, 'file_format': 'pem'},
            )
        )

        assert b'PRIVATE KEY' not in response.content


class TestTruststoreMultipleDownloadView:
    """Archived downloads of several truststores."""

    @pytest.fixture
    def second_truststore(self) -> TruststoreModel:
        """Return a second stored truststore."""
        root, _ = CertificateGenerator.create_root_ca('Second TS Root')
        return TruststoreAddForm.save_trust_store(
            unique_name='second-truststore',
            intended_usage=TruststoreModel.IntendedUsage.GENERIC,
            certificates=[root],
        )

    def test_summary_page_exposes_selected_pks(
        self, authenticated_client: Client, truststore: TruststoreModel, second_truststore: TruststoreModel
    ) -> None:
        """The summary page keeps the selected primary keys for later links."""
        pks = f'{truststore.pk}/{second_truststore.pk}'
        response = authenticated_client.get(
            reverse('pki:truststores-download', kwargs={'pks': pks})
        )

        assert response.status_code == HTTPStatus.OK
        assert response.context['pks_path'] == pks

    def test_zip_archive_is_returned(
        self, authenticated_client: Client, truststore: TruststoreModel, second_truststore: TruststoreModel
    ) -> None:
        """Selected truststores are archived for download."""
        response = authenticated_client.get(
            reverse(
                'pki:truststores-file-download',
                kwargs={
                    'pks': f'{truststore.pk}/{second_truststore.pk}',
                    'file_format': 'pem',
                    'archive_format': 'zip',
                },
            )
        )

        assert response.status_code == HTTPStatus.OK
        assert 'truststores.zip' in response['Content-Disposition']
        assert response.content.startswith(b'PK')

    def test_unknown_primary_key_returns_404(
        self, authenticated_client: Client, truststore: TruststoreModel
    ) -> None:
        """A selection containing an unknown truststore is rejected."""
        response = authenticated_client.get(
            reverse('pki:truststores-download', kwargs={'pks': f'{truststore.pk}/999999'})
        )

        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_unknown_archive_format_returns_404(
        self, authenticated_client: Client, truststore: TruststoreModel, second_truststore: TruststoreModel
    ) -> None:
        """An unsupported archive format is rejected."""
        response = authenticated_client.get(
            reverse(
                'pki:truststores-file-download',
                kwargs={
                    'pks': f'{truststore.pk}/{second_truststore.pk}',
                    'file_format': 'badformat',
                    'archive_format': 'zip',
                },
            )
        )

        assert response.status_code == HTTPStatus.NOT_FOUND


class TestTruststoreBulkDelete:
    """Bulk deletion of truststores."""

    def test_empty_selection_redirects(self, authenticated_client: Client) -> None:
        """An empty selection redirects instead of showing a confirmation."""
        response = authenticated_client.get(
            reverse('pki:truststore-delete_confirm', kwargs={'pks': '999999'})
        )

        assert response.status_code == HTTPStatus.FOUND

    def test_confirmation_page_lists_selected_truststores(
        self, authenticated_client: Client, truststore: TruststoreModel
    ) -> None:
        """The confirmation page lists the truststores about to be deleted."""
        response = authenticated_client.get(
            reverse('pki:truststore-delete_confirm', kwargs={'pks': str(truststore.pk)})
        )

        assert response.status_code == HTTPStatus.OK
        assert list(response.context['truststores']) == [truststore]

    def test_confirmed_deletion_removes_truststore(
        self, authenticated_client: Client, truststore: TruststoreModel
    ) -> None:
        """Confirming the form deletes the selected truststore."""
        response = authenticated_client.post(
            reverse('pki:truststore-delete_confirm', kwargs={'pks': str(truststore.pk)}), data={}
        )

        assert response.status_code == HTTPStatus.FOUND
        assert not TruststoreModel.objects.filter(pk=truststore.pk).exists()
