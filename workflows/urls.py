from __future__ import annotations

from django.urls import path

from workflows.views import PendingApprovalsView, SignalInstanceView

app_name = 'workflows'

urlpatterns = [
    path('pending/', PendingApprovalsView.as_view(), name='pending_list'),
    path(
        'instances/<uuid:instance_id>/signal/',
        SignalInstanceView.as_view(),
        name='signal',
    ),
]
