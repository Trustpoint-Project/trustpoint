"""Tests for the Organization management views."""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.messages import get_messages
from django.test import Client, TestCase
from django.urls import reverse

from management.models.organization import OrganizationModel
from users.models import GroupProfile

User = get_user_model()


def _create_admin_group() -> Group:
    group, _ = Group.objects.get_or_create(name='Admin')
    GroupProfile.objects.get_or_create(group=group, defaults={'grants_staff': True, 'grants_superuser': True})
    return group


class OrganizationTableViewTest(TestCase):
    """Tests for the organization list view."""

    def setUp(self) -> None:
        self.client = Client()
        self.url = reverse('management:organization')
        admin_group = _create_admin_group()
        self.admin_user = User.objects.create_user(username='admin', password='pass', role=admin_group)
        self.client.force_login(self.admin_user)

    def test_get_returns_200(self) -> None:
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)


class OrganizationCreateViewTest(TestCase):
    """Tests for organization creation."""

    def setUp(self) -> None:
        self.client = Client()
        self.url = reverse('management:add_organization')
        admin_group = _create_admin_group()
        self.admin_user = User.objects.create_user(username='admin', password='pass', role=admin_group)
        self.client.force_login(self.admin_user)

    def test_get_returns_200(self) -> None:
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_create_organization_success(self) -> None:
        response = self.client.post(
            self.url,
            {
                'name': 'Example Org',
                'organization': 'Example Org',
                'organization_unit': 'Security',
                'country': 'DE',
                'state': 'Berlin',
                'locality': 'Berlin',
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(OrganizationModel.objects.filter(name='Example Org').exists())
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Example Org' in str(m) for m in messages))


class OrganizationEditViewTest(TestCase):
    """Tests for organization editing."""

    def setUp(self) -> None:
        self.client = Client()
        admin_group = _create_admin_group()
        self.admin_user = User.objects.create_user(username='admin', password='pass', role=admin_group)
        self.organization = OrganizationModel.objects.create(
            name='Old Name',
            organization='Old Name',
            organization_unit='IT',
            country='DE',
            state='Berlin',
            locality='Berlin',
        )
        self.url = reverse('management:edit_organization', kwargs={'pk': self.organization.pk})
        self.client.force_login(self.admin_user)

    def test_get_returns_200(self) -> None:
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_edit_organization_success(self) -> None:
        response = self.client.post(
            self.url,
            {
                'name': 'New Name',
                'organization': 'New Name',
                'organization_unit': 'Ops',
                'country': 'DE',
                'state': 'Hamburg',
                'locality': 'Hamburg',
            },
        )
        self.assertEqual(response.status_code, 302)
        self.organization.refresh_from_db()
        self.assertEqual(self.organization.name, 'New Name')
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('New Name' in str(m) for m in messages))


class OrganizationDeleteViewTest(TestCase):
    """Tests for organization deletion."""

    def setUp(self) -> None:
        self.client = Client()
        admin_group = _create_admin_group()
        self.admin_user = User.objects.create_user(username='admin', password='pass', role=admin_group)
        self.organization = OrganizationModel.objects.create(
            name='Delete Me',
            organization='Delete Me',
            country='DE',
        )
        self.url = reverse('management:delete_organization', kwargs={'pk': self.organization.pk})
        self.client.force_login(self.admin_user)

    def test_delete_organization_success(self) -> None:
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertFalse(OrganizationModel.objects.filter(pk=self.organization.pk).exists())
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Delete Me' in str(m) for m in messages))
