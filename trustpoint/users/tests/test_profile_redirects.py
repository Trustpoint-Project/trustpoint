# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Profile actions must redirect to named local routes regardless of request paths."""

import pytest
from django.contrib.auth.models import Permission
from django.contrib.messages.storage.fallback import FallbackStorage
from django.core.exceptions import PermissionDenied
from django.urls import reverse
from django.utils import timezone, translation

from users.models import TrustpointUser
from users.views import TrustpointProfileView


@pytest.fixture
def manager():
    user = TrustpointUser.objects.create_user(username='profile-manager')
    user.user_permissions.add(Permission.objects.get(codename='manage_users'))
    return user


@pytest.fixture
def profile_request(rf):
    def build(user, action, target, path):
        data = {
            'form_name': action,
            'first_name': 'Updated',
            'role': str(target.role_id),
            'language': 'en',
            'timezone': 'UTC',
            'date_format': '6',
            'theme': 'dark',
            'view_mode': 'standard',
        }
        request = rf.post('/users/profile/', data)
        # Exercise the sink directly: routing/proxy normalization must not be
        # relied on to make a request-derived redirect destination safe.
        request.path = path
        request.user = user
        request.session = {}
        request._messages = FallbackStorage(request)
        return request

    return build


@pytest.mark.parametrize(
    'path', ['//evil.example/profile/', '/\\evil.example/profile/', 'https://evil.example/profile/']
)
@pytest.mark.parametrize('action', ['profile', 'require_password_change', 'unblock_failed_login'])
@pytest.mark.parametrize('own_profile', [False, True])
def test_profile_actions_ignore_untrusted_request_path(manager, profile_request, path, action, own_profile):
    target = manager if own_profile else TrustpointUser.objects.create_user(username='profile-target')
    if action == 'unblock_failed_login' and not own_profile:
        target.is_active = False
        target.blocked_by_failed_logins = True
        target.failed_login_attempts = 5
        target.save(update_fields=['is_active', 'blocked_by_failed_logins', 'failed_login_attempts'])
    request = profile_request(manager, action, target, path)
    kwargs = {} if own_profile else {'pk': target.pk}
    with translation.override('en'), timezone.override('UTC'):
        response = TrustpointProfileView.as_view()(request, **kwargs)
    if action == 'profile' and own_profile:
        expected = reverse('home:index')
    elif own_profile:
        expected = reverse('users:profile')
    else:
        expected = reverse('users:user-profile', kwargs={'pk': target.pk})
    assert response.status_code == 302
    assert response['Location'] == expected
    target.refresh_from_db()
    if action == 'profile':
        assert target.first_name == 'Updated'
    elif action == 'require_password_change':
        assert target.must_change_password is True
    else:
        assert target.is_active is True
        assert target.blocked_by_failed_logins is False
        assert target.failed_login_attempts == 0


@pytest.mark.parametrize('action', ['require_password_change', 'unblock_failed_login'])
def test_profile_security_actions_still_require_manage_users_permission(profile_request, action):
    user = TrustpointUser.objects.create_user(username='regular-profile-user')
    request = profile_request(user, action, user, '//evil.example/')
    with pytest.raises(PermissionDenied):
        TrustpointProfileView.as_view()(request)
    user.refresh_from_db()
    assert user.must_change_password is False


def test_unblocking_user_who_is_not_blocked_returns_to_named_profile(manager, profile_request):
    target = TrustpointUser.objects.create_user(username='already-active')
    request = profile_request(manager, 'unblock_failed_login', target, '//evil.example/')
    response = TrustpointProfileView.as_view()(request, pk=target.pk)
    assert response['Location'] == reverse('users:user-profile', kwargs={'pk': target.pk})
    target.refresh_from_db()
    assert target.is_active is True
