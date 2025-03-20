"""URL configuration for the users application."""

from django.contrib.auth import views as auth_views
from django.urls import path

from users.views import TrustpointLoginView

app_name = 'users'
urlpatterns = [
    path('login/', TrustpointLoginView.as_view(template_name='users/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(template_name='users/logout.html'), name='logout'),
]
