"""Module containing urls for user app."""
from django.contrib.auth.views import LoginView, LogoutView
from django.urls import path

from .views import TokenCreateView, TokenListView
appname = 'Auth'
urlpatterns = [
    path('tokens/', TokenListView.as_view(), name='token_list'),
    path('generate-token/', TokenCreateView.as_view(), name='api_token'),
]