"""API URL configuration for the agents application."""
from django.urls import path

from agents.api_views import AgentJobResultView, AgentJobsView

app_name = 'agents_api'

urlpatterns = [
    path('agents/jobs/', AgentJobsView.as_view(), name='agent-jobs'),
    path('agents/jobs/result/', AgentJobResultView.as_view(), name='agent-jobs-result'),
]
