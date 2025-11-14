"""Module containing urls for user app."""

from django.urls import path

from . import views
app_name = 'auth'
urlpatterns = [
    path('tokens/', views.TokenListView.as_view(), name='token_list'),
    path('generate-token/', views.TokenCreateView.as_view(), name='gen_token'),
]