"""URLs for the Django CMP Application."""

from django.urls import path

from cmp import views

app_name = 'cmp'

urlpatterns = [
    path(
        'initialization/<str:domain>/<str:template>',
        views.CmpInitializationRequestView.as_view(),
        name='initialization_template',
    ),
    path(
        'initialization/<str:domain>/<str:template>/',
        views.CmpInitializationRequestView.as_view(),
        name='initialization_template_slash',
    ),

    path('initialization/<str:domain>', views.CmpInitializationRequestView.as_view(), name='initialization'),
    path('initialization/<str:domain>/', views.CmpInitializationRequestView.as_view(), name='initialization_slash'),

    path(
        'certification/<str:domain>/<str:template>',
        views.CmpCertificationRequestView.as_view(),
        name='certification_template',
    ),
    path(
        'certification/<str:domain>/<str:template>/',
        views.CmpCertificationRequestView.as_view(),
        name='certification_template_slash',
    ),

    path('certification/<str:domain>', views.CmpCertificationRequestView.as_view(), name='certification'),
    path('certification/<str:domain>/', views.CmpCertificationRequestView.as_view(), name='certification_slash'),
]
