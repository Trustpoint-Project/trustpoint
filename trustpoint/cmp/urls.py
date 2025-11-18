"""URLs for the Django CMP Application."""

from django.urls import path

from cmp import views

app_name = 'cmp'

urlpatterns = [
    path(
        'p/<str:domain_name>/<str:certificate_profile>/initialization',
        views.CmpInitializationRequestView.as_view(),
        name='initialization_profile',
    ),
    path(
        'p/<str:domain_name>/<str:certificate_profile>/initialization/',
        views.CmpInitializationRequestView.as_view(),
        name='initialization_profile_slash',
    ),

    path('p/<str:domain_name>/initialization', views.CmpInitializationRequestView.as_view(), name='initialization'),
    path('p/<str:domain_name>/initialization/',
         views.CmpInitializationRequestView.as_view(),
         name='initialization_slash'
    ),
    path(
        'p/<str:domain_name>/<str:certificate_profile>/certification',
        views.CmpCertificationRequestView.as_view(),
        name='certification_template',
    ),
    path(
        'p/<str:domain_name>/<str:certificate_profile>/certification/',
        views.CmpCertificationRequestView.as_view(),
        name='certification_template_slash',
    ),

    path('p/<str:domain_name>/certification', views.CmpCertificationRequestView.as_view(), name='certification'),
    path('p/<str:domain_name>/certification/', views.CmpCertificationRequestView.as_view(), name='certification_slash'),

    path('p/<str:domain_name>/revocation', views.CmpRevocationRequestView.as_view(), name='revocation'),
    path('p/<str:domain_name>/revocation/', views.CmpRevocationRequestView.as_view(), name='revocation_slash'),

    path('p/<str:domain_name>/getcacerts', views.CmpGetCaCertsRequestView.as_view(), name='getcacerts'),
    path('p/<str:domain_name>/getcacerts/', views.CmpGetCaCertsRequestView.as_view(), name='getcacerts_slash'),

    path('p/<str:domain_name>/getcrls', views.CmpGetCrlsRequestView.as_view(), name='getcrls'),
    path('p/<str:domain_name>/getcrls/', views.CmpGetCrlsRequestView.as_view(), name='getcrls_slash'),
]
