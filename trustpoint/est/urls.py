"""URL configuration for the 'est' app."""
from django.urls import path, re_path

from est import views

app_name = 'est'

urlpatterns = [
    path(
        '<str:domain>/<str:certtemplate>/simpleenroll/',
        views.MyView.as_view(),
        name='simple-enrollment-post'
    ),
    re_path(
        r'^(?P<domain>[^/]+)(?:/(?P<certtemplate>[^/]+))?/cacerts/$',
        views.EstCACertsView.as_view(),
        name='ca-certs-post'
    ),
    path(
        '<str:domain>/<str:certtemplate>/csrattrs/',
        views.EstCsrAttrsView.as_view(),
        name='csrattrs'
    ),
]
