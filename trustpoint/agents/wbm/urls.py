"""URL configuration for the WBM agent API endpoints."""
from django.urls import path

from agents.wbm.views import WbmCheckInView, WbmPushResultView, WbmSubmitCsrView

app_name = 'agents_wbm'

urlpatterns = [
    path('check-in/', WbmCheckInView.as_view(), name='check-in'),
    path('submit-csr/', WbmSubmitCsrView.as_view(), name='submit-csr'),
    path('push-result/', WbmPushResultView.as_view(), name='push-result'),
]
