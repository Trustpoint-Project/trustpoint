"""Defines URL patterns for the NOTIFICATIONS application, mapping views to URLs."""

from django.urls import path

from . import views

app_name = 'notifications'
urlpatterns = [
    path('notifications/execute/', views.ExecuteNotificationsView.as_view(), name='execute_notifications'),
]
