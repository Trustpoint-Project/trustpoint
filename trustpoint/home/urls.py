"""Defines URL patterns for the Home application, mapping views to URLs."""

from django.urls import path

from . import views

app_name = 'home'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    path('dashboard_data/', views.DashboardChartsAndCountsView.as_view(), name='dashboard_data'),
]

