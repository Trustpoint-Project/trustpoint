# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""URL configuration for Web UI automation."""

from django.urls import path, re_path

from web_ui_automation.web_views import (
    AssignedProfileCreateView,
    AssignedProfileDeleteView,
    AssignedProfileUpdateView,
    AutomationDeviceCreateView,
    AutomationDeviceDeleteView,
    AutomationDeviceListView,
    AutomationDeviceRevokeView,
    AutomationJobDetailView,
    AutomationProfileCreateView,
    AutomationProfileListView,
    AutomationProfileUpdateView,
    ConfirmJobView,
    DisableAutomaticRenewalView,
    EnableAutomaticRenewalView,
    ExecuteJobNowView,
    RenewalConfigView,
    RevokeCertificateView,
    StartOperationView,
    WebUiAutomationDeviceCLMView,
)

app_name = 'web_ui_automation'

urlpatterns = [
    path('', AutomationDeviceListView.as_view(), name='devices'),
    path('devices/create/', AutomationDeviceCreateView.as_view(), name='device-create'),
    re_path(
        r'^devices/delete(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$',
        AutomationDeviceDeleteView.as_view(),
        name='device-delete',
    ),
    re_path(
        r'^devices/revoke(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$',
        AutomationDeviceRevokeView.as_view(),
        name='device-revoke',
    ),
    path('devices/<int:pk>/clm/', WebUiAutomationDeviceCLMView.as_view(), name='device-clm'),
    path(
        'devices/<int:device_id>/profiles/create/',
        AssignedProfileCreateView.as_view(),
        name='assignment-create',
    ),
    path(
        'devices/<int:device_id>/profiles/<int:pk>/edit/',
        AssignedProfileUpdateView.as_view(),
        name='assignment-edit',
    ),
    path(
        'devices/<int:device_id>/profiles/<int:pk>/delete/',
        AssignedProfileDeleteView.as_view(),
        name='assignment-delete',
    ),
    path('profiles/', AutomationProfileListView.as_view(), name='profiles'),
    path('profiles/create/', AutomationProfileCreateView.as_view(), name='profile-create'),
    path('profiles/<int:pk>/edit/', AutomationProfileUpdateView.as_view(), name='profile-edit'),
    path('jobs/<int:pk>/', AutomationJobDetailView.as_view(), name='job-detail'),
    path(
        'assignments/<int:pk>/run/<str:operation>/',
        StartOperationView.as_view(),
        name='operation-run',
    ),
    path('jobs/<int:pk>/confirm/', ConfirmJobView.as_view(), name='job-confirm'),
    path('jobs/<int:pk>/execute/', ExecuteJobNowView.as_view(), name='job-execute'),
    path('assignments/<int:pk>/renewal/enable/', EnableAutomaticRenewalView.as_view(), name='renewal-enable'),
    path(
        'assignments/<int:pk>/renewal/disable/',
        DisableAutomaticRenewalView.as_view(),
        name='renewal-disable',
    ),
    path(
        'devices/<int:device_id>/profiles/<int:pk>/renewal/',
        RenewalConfigView.as_view(),
        name='renewal-config',
    ),
    path(
        'devices/<int:device_id>/profiles/<int:pk>/revoke/',
        RevokeCertificateView.as_view(),
        name='certificate-revoke',
    ),
]
