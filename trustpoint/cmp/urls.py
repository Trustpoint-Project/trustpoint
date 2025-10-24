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
]
