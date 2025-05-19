"""Defines URL patterns for the NOTIFICATIONS application, mapping views to URLs."""

from django.urls import path

from . import views

app_name = 'notifications'
urlpatterns = [
    path('notifications/refresh/', views.RefreshNotificationsView.as_view(), name='refresh_notifications'),
    path('notifications/<int:pk>/delete/', views.NotificationDeleteView.as_view(), name='notification_delete'),

]
