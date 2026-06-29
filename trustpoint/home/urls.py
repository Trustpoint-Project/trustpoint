"""Defines URL patterns for the Home application, mapping views to URLs."""

from django.urls import path

from . import simplified_view, views

app_name = 'home'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    path('dashboard_data/', views.DashboardChartsAndCountsView.as_view(), name='dashboard_data'),
    path('simplified/', simplified_view.SimplifiedDomainOverviewView.as_view(), name='simplified_overview'),
    path(
        'simplified/enable-crl-cycle/<int:pk>/',
        simplified_view.EnableCrlCycleQuickActionView.as_view(),
        name='simplified_enable_crl_cycle'
    ),
]
