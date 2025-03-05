"""URL configuration for the 'est' app."""
from django.urls import path

from est import views

app_name = 'est'

urlpatterns = [
    path(
        'simpleenroll/<str:domain>/<str:certtemplate>/',
        views.EstSimpleEnrollmentView.as_view(),
        name='simple-enrollment'
    ),
    path(
        'simplereenroll/<str:domain>/<str:certtemplate>/',
        views.EstSimpleReenrollmentView.as_view(),
        name='simple-re-enrollment'
    ),
    path(
        'cacerts/<str:domain>/',
        views.EstCACertsView.as_view(),
        name='ca-certs'
    ),
]
