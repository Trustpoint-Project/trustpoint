"""URLs for the Django AOKI Application."""

from django.urls import path

from aoki import views

app_name = 'aoki'

urlpatterns = [
    path(
        'init/',
        views.AokiInitializationRequestView.as_view(),
        name='aoki_init',
    ),
]
