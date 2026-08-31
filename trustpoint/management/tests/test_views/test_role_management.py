# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the Role Management views."""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.messages import get_messages
from django.test import Client, TestCase
from django.urls import reverse

from users.models import GroupProfile, Role

User = get_user_model()


def _create_admin_group() -> Group:
    group, _ = Group.objects.get_or_create(name='Admin')
    GroupProfile.objects.get_or_create(group=group, defaults={'grants_staff': True, 'grants_superuser': True})
    return group


class RoleTableViewTest(TestCase):
    """Tests for the role list view."""

    def setUp(self) -> None:
        self.client = Client()
        self.url = reverse('management:role_management')
        admin_group = _create_admin_group()
        self.admin_user = User.objects.create_user(username='admin', password='pass', role=admin_group)
        self.client.force_login(self.admin_user)

    def test_get_returns_200(self) -> None:
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_admin_role_shows_permissions(self) -> None:
        """The Admin role displays all available permissions as a read-only list."""
        url = reverse('management:edit_role', kwargs={'pk': self.admin_user.role.pk})

        response = self.client.get(url)

        self.assertContains(response, 'Can use REST API')
        self.assertNotContains(response, 'Assigned Permissions')


class RoleCreateViewTest(TestCase):
    """Tests for the role creation view."""

    def setUp(self) -> None:
        self.client = Client()
        self.url = reverse('management:add_role')
        admin_group = _create_admin_group()
        self.admin_user = User.objects.create_user(username='admin', password='pass', role=admin_group)
        self.client.force_login(self.admin_user)

    def test_get_returns_200(self) -> None:
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_create_role_success(self) -> None:
        """A valid POST creates the group, its GroupProfile, and shows a success message."""
        response = self.client.post(self.url, {
            'name': 'Auditor',
            'grants_staff': '',
            'grants_superuser': '',
            'permissions': [],
        })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Group.objects.filter(name='Auditor').exists())
        self.assertTrue(GroupProfile.objects.filter(group__name='Auditor').exists())
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Auditor' in str(m) for m in messages))


class RoleEditViewTest(TestCase):
    """Tests for the role edit view."""

    def setUp(self) -> None:
        self.client = Client()
        admin_group = _create_admin_group()
        self.admin_user = User.objects.create_user(username='admin', password='pass', role=admin_group)
        self.custom_group, _ = Group.objects.get_or_create(name='Analyst')
        GroupProfile.objects.get_or_create(group=self.custom_group, defaults={'grants_staff': False, 'grants_superuser': False})
        self.url = reverse('management:edit_role', kwargs={'pk': self.custom_group.pk})
        self.client.force_login(self.admin_user)

    def test_get_returns_200(self) -> None:
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_edit_role_success(self) -> None:
        """A valid POST updates the group name and shows a success message."""
        response = self.client.post(self.url, {
            'name': 'Analyst Updated',
            'grants_staff': '',
            'grants_superuser': '',
            'permissions': [],
        })
        self.assertEqual(response.status_code, 302)
        self.custom_group.refresh_from_db()
        self.assertEqual(self.custom_group.name, 'Analyst Updated')
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Analyst Updated' in str(m) for m in messages))

    def test_service_account_role_permissions_are_fixed(self) -> None:
        """The built-in service-account role cannot be modified."""
        service_group = Role.get_service_group()
        url = reverse('management:edit_role', kwargs={'pk': service_group.pk})

        response = self.client.post(url, {
            'name': Role.SERVICE.value,
            'grants_staff': 'on',
            'grants_superuser': 'on',
            'permissions': [],
        })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(service_group.permissions.values_list('codename', flat=True)), ['use_rest_api'])


class RoleDeleteViewTest(TestCase):
    """Tests for the role deletion view."""

    def setUp(self) -> None:
        self.client = Client()
        self.admin_group = _create_admin_group()
        self.admin_user = User.objects.create_user(username='admin', password='pass', role=self.admin_group)
        self.custom_group, _ = Group.objects.get_or_create(name='Temp')
        GroupProfile.objects.get_or_create(group=self.custom_group, defaults={'grants_staff': False, 'grants_superuser': False})
        self.client.force_login(self.admin_user)

    def test_delete_role_success(self) -> None:
        """Deleting a custom role removes the group and shows a success message."""
        url = reverse('management:delete_role', kwargs={'pk': self.custom_group.pk})
        response = self.client.post(url)
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Group.objects.filter(pk=self.custom_group.pk).exists())
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Temp' in str(m) for m in messages))

    def test_delete_admin_role_is_blocked(self) -> None:
        """Deleting the built-in Admin role is blocked with an error message."""
        url = reverse('management:delete_role', kwargs={'pk': self.admin_group.pk})
        response = self.client.post(url)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Group.objects.filter(name='Admin').exists())
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Admin' in str(m) for m in messages))

    def test_delete_role_with_assigned_users_is_blocked(self) -> None:
        """Deleting a role that still has users assigned is blocked."""
        plain_group, _ = Group.objects.get_or_create(name='Occupied')
        GroupProfile.objects.get_or_create(group=plain_group, defaults={'grants_staff': False, 'grants_superuser': False})
        User.objects.create_user(username='occupant', password='pass', role=plain_group)

        url = reverse('management:delete_role', kwargs={'pk': plain_group.pk})
        response = self.client.post(url)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Group.objects.filter(name='Occupied').exists())
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Occupied' in str(m) for m in messages))
