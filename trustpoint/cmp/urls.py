"""URLs for the Django CMP Application."""

from django.urls import path

from cmp import views

app_name = 'cmp'

urlpatterns = [
    path(
        'initialization/<str:domain>/<str:template>/',
        views.CmpInitializationRequestView.as_view(),
        name='certification-template',
    ),
    path('initialization/<str:domain>/', views.CmpInitializationRequestView.as_view(), name='initialization'),
    path(
        'certification/<str:domain>/<str:template>/',
        views.CmpCertificationRequestView.as_view(),
        name='certification-template',
    ),
    path('certification/<str:domain>/', views.CmpCertificationRequestView.as_view(), name='certification'),
]
