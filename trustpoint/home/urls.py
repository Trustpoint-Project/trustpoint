from django.urls import path
from . import views


app_name = 'home'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    path('notification/<int:pk>/', views.notification_details_view, name='notification_details'),
    path('notification/<int:pk>/mark-as-solved/', views.mark_as_solved, name='mark_as_solved'),
    path('dashboard_data/', views.DashboardChartsAndCountsView.as_view(), name='dashboard_data'),
]
