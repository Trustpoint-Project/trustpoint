"""URL configuration for the PKI application."""

from django.urls import path, re_path  # type: ignore[import-untyped]

from pki.views import certificates, domains, issuing_cas, truststores
from pki.views.domains import DevIdRegistrationCreateView, DevIdRegistrationDeleteView, DevIdMethodSelectView

app_name = 'pki'

urlpatterns = [
    path(
        'truststores/',
        truststores.TruststoreTableView.as_view(),
        name='truststores',
    ),
    path('truststores/add/',
         truststores.TruststoreCreateView.as_view(),
         name='truststores-add'),
    path('truststores/add/<int:pk>/',
         truststores.TruststoreCreateView.as_view(),
         name='truststores-add-with-pk'),
    re_path(
        r'^truststores/download/(?P<pk>[0-9]+)/?$',
        truststores.TruststoreDownloadView.as_view(),
        name='truststore-download',
    ),
    re_path(
        r'^truststores/download/(?P<pks>([0-9]+/)+[0-9]+)/?$',
        truststores.TruststoreMultipleDownloadView.as_view(),
        name='truststores-download',
    ),
    re_path(
        r'^truststores/download/multiple/'
        r'(?P<file_format>[a-zA-Z0-9_]+)/'
        r'(?P<archive_format>[a-zA-Z0-9_]+)/'
        r'(?P<pks>([0-9]+/)+[0-9]+)/?$',
        truststores.TruststoreMultipleDownloadView.as_view(),
        name='truststores-file-download',
    ),
    re_path(
        r'^truststores/download/(?P<file_format>[a-zA-Z0-9_]+)/(?P<pk>[0-9]+)/?$',
        truststores.TruststoreDownloadView.as_view(),
        name='truststore-file-download',
    ),
    path('truststores/details/<int:pk>/',
         truststores.TruststoreDetailView.as_view(),
         name='truststore-detail'),
    re_path(
        r'^truststores/delete/(?P<pks>([0-9]+/)+[0-9]*)/?$',
        truststores.TruststoreBulkDeleteConfirmView.as_view(),
        name='truststore-delete_confirm',
    ),
    path(
        'certificates/',
        certificates.CertificateTableView.as_view(),
        name='certificates',
    ),
    re_path(
        r'^certificates/download/(?P<pk>[0-9]+)/?$',
        certificates.CertificateDownloadView.as_view(),
        name='certificate-download',
    ),
    re_path(
        r'^certificates/download/(?P<pks>([0-9]+/)+[0-9]+)/?$',
        certificates.CertificateMultipleDownloadView.as_view(),
        name='certificates-download',
    ),
    re_path(
        r'^certificates/download/multiple/'
        r'(?P<file_format>[a-zA-Z0-9_]+)/'
        r'(?P<archive_format>[a-zA-Z0-9_]+)/'
        r'(?P<pks>([0-9]+/)+[0-9]+)/?$',
        certificates.CertificateMultipleDownloadView.as_view(),
        name='certificates-file-download',
    ),
    re_path(
        r'^certificates/download/(?P<file_format>[a-zA-Z0-9_]+)/(?P<pk>[0-9]+)/?$',
        certificates.CertificateDownloadView.as_view(),
        name='certificate-file-download',
    ),
    path(
        'certificates/download/issuing-ca/<int:pk>/',
        certificates.CmpIssuingCaCertificateDownloadView.as_view(),
        name='certificate-issuing-ca-download',
    ),
    path('certificates/details/<int:pk>/',
         certificates.CertificateDetailView.as_view(),
         name='certificate-detail'),
    path('issuing-cas/', issuing_cas.IssuingCaTableView.as_view(), name='issuing_cas'),
    path(
        'issuing-cas/add/method-select/',
        issuing_cas.IssuingCaAddMethodSelectView.as_view(),
        name='issuing_cas-add-method_select',
    ),
    path(
        'issuing-cas/add/file-import/pkcs12',
        issuing_cas.IssuingCaAddFileImportPkcs12View.as_view(),
        name='issuing_cas-add-file_import-pkcs12',
    ),
    path(
        'issuing-cas/add/file-import/separate-files',
        issuing_cas.IssuingCaAddFileImportSeparateFilesView.as_view(),
        name='issuing_cas-add-file_import-separate_files',
    ),
    path('issuing-cas/detail/<int:pk>/', issuing_cas.IssuingCaDetailView.as_view(), name='issuing_cas-detail'),
    path('issuing-cas/config/<int:pk>/', issuing_cas.IssuingCaConfigView.as_view(), name='issuing_cas-config'),
    path('issuing-cas/crl-gen/<int:pk>/', issuing_cas.IssuingCaCrlGenerationView.as_view(), name='issuing_cas-crl-gen'),
    re_path(
        r'^issuing-cas/delete/(?P<pks>([0-9]+/)+[0-9]*)/?$',
        issuing_cas.IssuingCaBulkDeleteConfirmView.as_view(),
        name='issuing_cas-delete_confirm',
    ),
    path('domains/', domains.DomainTableView.as_view(), name='domains'),
    path('domains/add/', domains.DomainCreateView.as_view(), name='domains-add'),
    path('domains/config/<int:pk>/', domains.DomainConfigView.as_view(), name='domains-config'),
    path('domains/detail/<int:pk>/', domains.DomainDetailView.as_view(), name='domains-detail'),
    re_path(
        r'^domains/delete/(?P<pks>([0-9]+/)+[0-9]*)/?$',
        domains.DomainCaBulkDeleteConfirmView.as_view(),
        name='domains-delete_confirm',
    ),
    path(
        'devid-registration/method_select/<int:pk>/',
        DevIdMethodSelectView.as_view(),
        name='devid_registration-method_select',
    ),
    path(
        'devid-registration/create/<int:pk>/',
        DevIdRegistrationCreateView.as_view(),
        name='devid_registration_create',
    ),
    path(
        'devid-registration/create/<int:pk>/<int:truststore_id>/',
        DevIdRegistrationCreateView.as_view(),
        name='devid_registration_create-with_truststore_id',
    ),
    path('devid-registration/delete/<int:pk>/',
         DevIdRegistrationDeleteView.as_view(),
         name='devid_registration_delete'),

]
