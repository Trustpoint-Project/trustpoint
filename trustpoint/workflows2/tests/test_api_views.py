from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from workflows2.models import Workflow2Definition


VALID_CREATE_YAML = """\
schema: trustpoint.workflow.v2
name: API Created Workflow
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true

workflow:
  start: done
  steps:
    done:
      type: set
      vars: {}
  flow: []
"""


VALID_UPDATE_YAML = """\
schema: trustpoint.workflow.v2
name: API Updated Workflow
enabled: false

trigger:
  on: certificate.issued
  sources:
    trustpoint: true

workflow:
  start: done
  steps:
    done:
      type: set
      vars:
        status: updated
  flow: []
"""


INVALID_YAML = """\
schema: trustpoint.workflow.v2
name: Bad
workflow:
  start:
"""


class Workflow2DefinitionApiViewSetTests(TestCase):
    def setUp(self) -> None:
        self.user = get_user_model().objects.create_user(
            username='workflow2-api-tester',
            password='testpass123',
        )
        self.authenticated_client = APIClient()
        self.authenticated_client.force_authenticate(user=self.user)

    @staticmethod
    def _create_definition(*, name: str = 'Stored workflow', trigger_on: str = 'device.created') -> Workflow2Definition:
        return Workflow2Definition.objects.create(
            name=name,
            enabled=True,
            trigger_on=trigger_on,
            yaml_text=VALID_CREATE_YAML,
            ir_json={
                'name': name,
                'enabled': True,
                'trigger': {'on': trigger_on},
                'workflow': {'start': 'done', 'steps': {}, 'flow': []},
                'meta': {'ir_hash': 'abc123'},
            },
            ir_hash='abc123',
        )

    def test_list_requires_authentication(self) -> None:
        response = APIClient().get(reverse('workflow2-definition-list'))
        self.assertEqual(response.status_code, 401)

    def test_list_returns_saved_definitions(self) -> None:
        definition = self._create_definition(name='List me')

        response = self.authenticated_client.get(reverse('workflow2-definition-list'))

        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(len(response.json()), 1)
        ids = [item['id'] for item in response.json()]
        self.assertIn(str(definition.id), ids)

    def test_retrieve_returns_definition(self) -> None:
        definition = self._create_definition(name='Retrieve me')

        response = self.authenticated_client.get(reverse('workflow2-definition-detail', kwargs={'pk': definition.id}))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['id'], str(definition.id))
        self.assertEqual(payload['name'], 'Retrieve me')

    def test_create_uses_yaml_request_body_and_compiles_server_side(self) -> None:
        response = self.authenticated_client.post(
            reverse('workflow2-definition-list'),
            data=VALID_CREATE_YAML,
            content_type='text/plain',
        )

        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertEqual(payload['name'], 'API Created Workflow')
        self.assertTrue(payload['enabled'])
        self.assertEqual(payload['trigger_on'], 'device.created')
        self.assertIn('ir_json', payload)
        self.assertTrue(payload['ir_hash'])

        definition = Workflow2Definition.objects.get(id=payload['id'])
        self.assertEqual(definition.name, 'API Created Workflow')
        self.assertTrue(definition.enabled)
        self.assertEqual(definition.trigger_on, 'device.created')

    def test_create_rejects_invalid_yaml(self) -> None:
        response = self.authenticated_client.post(
            reverse('workflow2-definition-list'),
            data=INVALID_YAML,
            content_type='text/plain',
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn('detail', response.json())

    def test_update_uses_yaml_request_body_and_recompiles_server_side(self) -> None:
        definition = self._create_definition(name='Before update', trigger_on='device.created')

        response = self.authenticated_client.put(
            reverse('workflow2-definition-detail', kwargs={'pk': definition.id}),
            data=VALID_UPDATE_YAML,
            content_type='text/plain',
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['name'], 'API Updated Workflow')
        self.assertFalse(payload['enabled'])
        self.assertEqual(payload['trigger_on'], 'certificate.issued')

        definition.refresh_from_db()
        self.assertEqual(definition.name, 'API Updated Workflow')
        self.assertFalse(definition.enabled)
        self.assertEqual(definition.trigger_on, 'certificate.issued')

    def test_delete_removes_definition(self) -> None:
        definition = self._create_definition()

        response = self.authenticated_client.delete(reverse('workflow2-definition-detail', kwargs={'pk': definition.id}))

        self.assertEqual(response.status_code, 204)
        self.assertFalse(Workflow2Definition.objects.filter(id=definition.id).exists())
