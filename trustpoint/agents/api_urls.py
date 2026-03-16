"""API URL configuration for the agents application."""
from django.urls import include, path

app_name = 'agents_api'

urlpatterns = [
    path('agents/wbm/', include('agents.wbm.urls', namespace='agents_wbm')),
]
