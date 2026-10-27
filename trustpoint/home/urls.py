# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""URL routes for the Home application, including Dashboard endpoints."""

from django.urls import path

from . import analytics, simplified_view, views

app_name = 'home'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('dashboard_data/', views.DashboardChartsAndCountsView.as_view(), name='dashboard_data'),
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    path('dashboard/overview/', views.DashboardOverviewAPIView.as_view(), name='dashboard_overview'),
    path(
        'dashboard/notifications/',
        views.DashboardNotificationsAPIView.as_view(),
        name='dashboard_notifications',
    ),
    path('dashboard/security/', views.DashboardSecurityAPIView.as_view(), name='dashboard_security'),
    path('dashboard/analytics/', analytics.DashboardAnalyticsAPIView.as_view(), name='dashboard_analytics'),
    path('simplified/', simplified_view.SimplifiedDomainOverviewView.as_view(), name='simplified_overview'),
    path(
        'simplified/enable-crl-cycle/<int:pk>/',
        simplified_view.EnableCrlCycleQuickActionView.as_view(),
        name='simplified_enable_crl_cycle',
    ),
]
