"""Tests for the User Management views."""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.messages import get_messages
from django.test import Client, TestCase
from django.urls import reverse

from users.models import GroupProfile

User = get_user_model()


def _create_admin_group() -> Group:
    group, _ = Group.objects.get_or_create(name='Admin')
    GroupProfile.objects.get_or_create(group=group, defaults={'grants_staff': True, 'grants_superuser': True})
    return group


def _create_plain_group(name: str = 'Viewer') -> Group:
    group, _ = Group.objects.get_or_create(name=name)
    GroupProfile.objects.get_or_create(group=group, defaults={'grants_staff': False, 'grants_superuser': False})
    return group


class UserManagementAccessTest(TestCase):
    """Test that user management pages enforce superuser access."""

    def setUp(self) -> None:
        self.client = Client()
        self.url = reverse('management:user_management')
        admin_group = _create_admin_group()
        plain_group = _create_plain_group()
        self.plain_user = User.objects.create_user(username='plain', password='pass', role=plain_group)

    def test_unauthenticated_redirects_to_login(self) -> None:
        """Unauthenticated requests are redirected to the login page."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/users/login', response['Location'])

    def test_non_superuser_redirects_to_management_index(self) -> None:
        """Non-superuser users are redirected to the management index."""
        self.client.force_login(self.plain_user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], reverse('management:index'))


class UserTableViewTest(TestCase):
    """Tests for the user list view."""

    def setUp(self) -> None:
        self.client = Client()
        self.url = reverse('management:user_management')
        admin_group = _create_admin_group()
        self.admin_user = User.objects.create_user(username='admin', password='pass', role=admin_group)
        self.client.force_login(self.admin_user)

    def test_get_returns_200(self) -> None:
        """List view is accessible to superusers."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)


class UserCreateViewTest(TestCase):
    """Tests for the user creation view."""

    def setUp(self) -> None:
        self.client = Client()
        self.url = reverse('management:add_user')
        admin_group = _create_admin_group()
        self.admin_user = User.objects.create_user(username='admin', password='pass', role=admin_group)
        self.client.force_login(self.admin_user)

    def test_get_returns_200(self) -> None:
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_create_user_success(self) -> None:
        """A valid POST creates the user and shows a success message."""
        plain_group = _create_plain_group()
        response = self.client.post(self.url, {
            'username': 'newuser',
            'password1': 'StrongPass123!',
            'password2': 'StrongPass123!',
            'role': plain_group.pk,
        })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(User.objects.filter(username='newuser').exists())
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('newuser' in str(m) for m in messages))

    def test_create_user_duplicate_username(self) -> None:
        """Duplicate username re-renders the form without creating a second user."""
        plain_group = _create_plain_group()
        User.objects.create_user(username='existing', password='pass', role=plain_group)
        response = self.client.post(self.url, {
            'username': 'existing',
            'password1': 'StrongPass123!',
            'password2': 'StrongPass123!',
            'role': plain_group.pk,
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.filter(username='existing').count(), 1)


class UserDeleteViewTest(TestCase):
    """Tests for the user deletion view."""

    def setUp(self) -> None:
        self.client = Client()
        admin_group = _create_admin_group()
        plain_group = _create_plain_group()
        self.admin_user = User.objects.create_user(username='admin', password='pass', role=admin_group)
        self.other_user = User.objects.create_user(username='other', password='pass', role=plain_group)
        self.client.force_login(self.admin_user)

    def test_delete_user_success(self) -> None:
        """Deleting a non-admin user removes them and shows a success message."""
        url = reverse('management:delete_user', kwargs={'pk': self.other_user.pk})
        response = self.client.post(url)
        self.assertEqual(response.status_code, 302)
        self.assertFalse(User.objects.filter(pk=self.other_user.pk).exists())
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('other' in str(m) for m in messages))

    def test_delete_last_admin_is_blocked(self) -> None:
        """Deleting the only admin account is blocked with an error message."""
        url = reverse('management:delete_user', kwargs={'pk': self.admin_user.pk})
        response = self.client.post(url)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(User.objects.filter(pk=self.admin_user.pk).exists())
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('admin' in str(m).lower() for m in messages))


class UserChangeRoleViewTest(TestCase):
    """Tests for the change-role view."""

    def setUp(self) -> None:
        self.client = Client()
        self.admin_group = _create_admin_group()
        self.plain_group = _create_plain_group()
        self.admin_user = User.objects.create_user(username='admin', password='pass', role=self.admin_group)
        self.other_user = User.objects.create_user(username='other', password='pass', role=self.plain_group)
        self.client.force_login(self.admin_user)

    def test_change_role_success(self) -> None:
        """Changing a user's role updates their is_superuser flag and shows a success message."""
        url = reverse('management:change_role', kwargs={'pk': self.other_user.pk})
        response = self.client.post(url, {'role': self.admin_group.pk})
        self.assertEqual(response.status_code, 302)
        self.other_user.refresh_from_db()
        self.assertTrue(self.other_user.is_superuser)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('other' in str(m) for m in messages))

    def test_downgrade_last_admin_is_blocked(self) -> None:
        """Downgrading the only admin to a non-admin role is blocked."""
        url = reverse('management:change_role', kwargs={'pk': self.admin_user.pk})
        response = self.client.post(url, {'role': self.plain_group.pk})
        self.assertEqual(response.status_code, 200)
        self.admin_user.refresh_from_db()
        self.assertTrue(self.admin_user.is_superuser)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('admin' in str(m).lower() for m in messages))
