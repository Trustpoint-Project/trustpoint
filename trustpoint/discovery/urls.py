"""URL configuration for the network discovery module."""

from django.urls import path

from . import views

app_name = 'discovery'

urlpatterns = [
    path('', views.DeviceListView.as_view(), name='device_list'),
    path('start-scan/', views.StartScanView.as_view(), name='start_scan'),
    path('stop-scan/', views.StopScanView.as_view(), name='stop_scan'),
    path('clear/', views.ClearDevicesView.as_view(), name='clear_devices'),
    path('device/<int:device_id>/', views.DeviceDetailView.as_view(), name='device_detail'),
    path('port-config/', views.PortConfigView.as_view(), name='port_config'),
    path('port/add/', views.AddPortView.as_view(), name='add_port'),
    path('port/delete/<int:port_id>/', views.DeletePortView.as_view(), name='delete_port'),
    path('export-csv/', views.ExportCsvView.as_view(), name='export_csv'),
]
