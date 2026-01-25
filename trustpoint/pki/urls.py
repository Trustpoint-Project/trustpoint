"""URL configuration for the PKI application."""

from django.urls import path, re_path

from help_pages import pki_help_views
from pki.views import ca, cert_profiles, certificates, crls, domains, issuing_cas, owner_credentials, truststores
from pki.views.domains import DevIdMethodSelectView, DevIdRegistrationCreateView, DevIdRegistrationDeleteView
from pki.views.issuing_cas import IssuedCertificatesListView

app_name = 'pki'

urlpatterns = [
    path(
        'truststores/',
        truststores.TruststoreTableView.as_view(),
        name='truststores',
    ),
    path('truststores/add/', truststores.TruststoreCreateView.as_view(), name='truststores-add'),
    re_path(r'^truststores/add/(?P<pk>\d+)?/?$',
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
    path('truststores/details/<int:pk>/', truststores.TruststoreDetailView.as_view(), name='truststore-detail'),
    re_path(
        r'^truststores/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$',
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
    re_path(
        r'^certificates/download/(?P<file_format>[a-zA-Z0-9_]+)/(?P<pk>[0-9]+)/(?P<file_name>[^/]+)/?$',
        certificates.CertificateDownloadView.as_view(),
        name='certificate-file-download-file-name',
    ),
    path(
        'certificates/download/issuing-ca/<int:pk>/',
        certificates.IssuingCaCertificateDownloadView.as_view(),
        name='certificate-issuing-ca-download',
    ),
    path('certificates/details/<int:pk>/', certificates.CertificateDetailView.as_view(), name='certificate-detail'),
    path('cas/', ca.CaTableView.as_view(), name='cas'),
    re_path(
        r'^cas/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$',
        ca.CaBulkDeleteConfirmView.as_view(),
        name='cas-delete_confirm',
    ),
    path('crls/', crls.CrlTableView.as_view(), name='crls'),
    path('crls/import/', crls.CrlImportView.as_view(), name='crl-import'),
    re_path(
        r'^crls/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$',
        crls.CrlBulkDeleteConfirmView.as_view(),
        name='crls-delete_confirm',
    ),
    path('crls/details/<int:pk>/', crls.CrlDetailView.as_view(), name='crl-detail'),
    re_path(
        r'^crls/download/(?P<pk>[0-9]+)/?$',
        crls.CrlDownloadView.as_view(),
        name='crl-download',
    ),
    re_path(
        r'^crls/download/(?P<file_format>[a-zA-Z0-9_]+)/(?P<pk>[0-9]+)/?$',
        crls.CrlDownloadView.as_view(),
        name='crl-file-download',
    ),
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
    path('keyless-cas/config/<int:pk>/', issuing_cas.KeylessCaConfigView.as_view(), name='keyless_cas-config'),
    path('issuing-cas/crl-gen/<int:pk>/', issuing_cas.IssuingCaCrlGenerationView.as_view(), name='issuing_cas-crl-gen'),
    path(
        'issuing-cas/config/<int:pk>/help/crl-download/',
        pki_help_views.CrlDownloadHelpView.as_view(),
        name='help_issuing_cas_crl_download',
    ),
    path(
        'issuing-cas/issued-certificates/<int:pk>',
        IssuedCertificatesListView.as_view(),
        name='issuing_ca-issued_certificates',
    ),
    re_path(
        r'^issuing-cas/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$',
        issuing_cas.IssuingCaBulkDeleteConfirmView.as_view(),
        name='issuing_cas-delete_confirm',
    ),
    path('domains/', domains.DomainTableView.as_view(), name='domains'),
    path('domains/add/', domains.DomainCreateView.as_view(), name='domains-add'),
    path('domains/config/<int:pk>/', domains.DomainConfigView.as_view(), name='domains-config'),
    path(
        'domains/config/<int:pk>/help/onboarding-method-select-idevid/',
        domains.OnboardingMethodSelectIdevidHelpView.as_view(),
        name='help_onboarding_method_select_idevid'
    ),
    path(
        'domains/config/<int:pk>/help/cmp-idevid-registration/',
        pki_help_views.OnboardingCmpIdevidRegistrationHelpView.as_view(),
        name='help_onboarding_cmp_idevid_registration',
    ),
    path(
        'domains/config/<int:pk>/help/est-idevid-registration/',
        pki_help_views.OnboardingEstIdevidRegistrationHelpView.as_view(),
        name='help_onboarding_est_idevid_registration',
    ),
    path('domains/detail/<int:pk>/', domains.DomainDetailView.as_view(), name='domains-detail'),
    re_path(
        r'^domains/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$',
        domains.DomainCaBulkDeleteConfirmView.as_view(),
        name='domains-delete_confirm',
    ),
    path(
        'domains/issued-certificates/<int:pk>/',
        domains.IssuedCertificatesView.as_view(),
        name='domain-issued_certificates',
    ),
    re_path(
        r'^devid-registration/method_select/(?P<pk>\d+)?/?$',
        DevIdMethodSelectView.as_view(),
        name='devid_registration-method_select',
    ),

    re_path(
        r'devid-registration/create/(?P<pk>\d+)?/?$',
        DevIdRegistrationCreateView.as_view(),
        name='devid_registration_create',
    ),

    path(
        'devid-registration/create/<int:pk>/<int:truststore_id>/',
        DevIdRegistrationCreateView.as_view(),
        name='devid_registration_create-with_truststore_id',
    ),
    path(
        'truststores/add/from-device/',
        truststores.TruststoreCreateView.as_view(),
        name='truststores-add-from-device',
    ),

    path(
        'devid-registration/delete/<int:pk>/', DevIdRegistrationDeleteView.as_view(), name='devid_registration_delete'
    ),
    # DevOwnerID views
    path('owner-credentials/', owner_credentials.OwnerCredentialTableView.as_view(), name='owner_credentials'),
    path(
        'owner-credentials/details/<int:pk>/',
        owner_credentials.OwnerCredentialDetailView.as_view(),
        name='owner_credentials-details',
    ),
    path(
        'owner-credentials/add/',
        owner_credentials.OwnerCredentialAddView.as_view(),
        name='owner_credentials-add',
    ),
    re_path(
        r'^owner-credentials/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$',
        owner_credentials.OwnerCredentialBulkDeleteConfirmView.as_view(),
        name='owner_credentials-delete_confirm',
    ),
    # Certificate Profile views
    path('cert-profiles/', cert_profiles.CertProfileTableView.as_view(), name='cert_profiles'),
    path(
        'cert-profiles/config/<int:pk>/',
        cert_profiles.CertProfileConfigView.as_view(),
        name='cert_profiles-details',
    ),
    path(
        'cert-profiles/add/',
        cert_profiles.CertProfileConfigView.as_view(),
        name='cert_profiles-add',
    ),
    re_path(
        r'^cert-profiles/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$',
        cert_profiles.CertProfileBulkDeleteConfirmView.as_view(),
        name='cert_profiles-delete_confirm',
    ),
    path(
        'trustpoint/download/tls-server/',
        certificates.TlsServerCertificateDownloadView.as_view(),
        name='trustpoint-tls-server-download',
    ),
]
