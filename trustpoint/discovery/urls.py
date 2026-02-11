"""URL configuration for the network discovery module."""

from django.urls import path

from . import views

app_name = 'discovery'

urlpatterns = [
    path('', views.device_list, name='device_list'),
    path('start-scan/', views.start_scan, name='start_scan'),
    path('stop-scan/', views.stop_scan, name='stop_scan'),
    path('clear/', views.clear_devices, name='clear_devices'),
    path('device/<int:device_id>/', views.device_detail, name='device_detail'),
    path('export-csv/', views.export_csv, name='export_csv'),
]
