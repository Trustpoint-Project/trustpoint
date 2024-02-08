from django.urls import path
from . import views


app_name = 'devices'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('devices/', views.devices, name='devices'),
]
