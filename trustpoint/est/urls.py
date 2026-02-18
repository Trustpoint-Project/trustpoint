"""URL configuration for the 'est' app."""

from django.urls import path, re_path

from est import views

app_name = 'est'

urlpatterns = [
    re_path(
        r'^simpleenroll/?$',
        views.EstSimpleEnrollmentView.as_view(),
        name='simple-enrollment-default'
    ),
    re_path(
        r'^simplereenroll/?$',
        views.EstSimpleReEnrollmentView.as_view(),
        name='simple-reenrollment-default'
    ),
    # single path seg, only profile specified in URL
    re_path(
        r'^(?P<cert_profile>~[^/]+)/simpleenroll/?$',
        views.EstSimpleEnrollmentView.as_view(),
        name='simple-enrollment-post-nodomain'
    ),
    re_path(
        r'^(?P<cert_profile>~[^/]+)/simplereenroll/?$',
        views.EstSimpleReEnrollmentView.as_view(),
        name='simple-reenrollment-post-nodomain'
    ),
    # 1-2 path segments: domain and optional profile, operation specified in URL
    re_path(
        r'^(?P<domain>[^/]+)(?:/(?P<cert_profile>[^/]+))?/simpleenroll/?$',
        views.EstSimpleEnrollmentView.as_view(),
        name='simple-enrollment-post',
    ),
    re_path(
        r'^(?P<domain>[^/]+)(?:/(?P<cert_profile>[^/]+))?/simplereenroll/?$',
        views.EstSimpleReEnrollmentView.as_view(),
        name='simple-reenrollment-post',
    ),
    re_path(
        r'^(?P<domain>[^/]+)(?:/(?P<cert_profile>[^/]+))?/cacerts/$',
        views.EstCACertsView.as_view(),
        name='ca-certs-post'
    ),
    path(
        '<str:domain>/<str:cert_profile>/csrattrs/',
        views.EstCsrAttrsView.as_view(),
        name='csrattrs'
    ),
    path(
        '<str:domain>/<str:cert_profile>/csrattrs/',
        views.EstCsrAttrsView.as_view(),
        name='csrattrs'
    ),
    path('<str:domain>/<str:certtemplate>/csrattrs/', views.EstCsrAttrsView.as_view(), name='csrattrs'),
    path('<str:domain>/<str:certtemplate>/csrattrs/', views.EstCsrAttrsView.as_view(), name='csrattrs'),
]
