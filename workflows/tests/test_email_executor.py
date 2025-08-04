# # tests/test_email_executor_sync.py

# from pathlib import Path

# import pytest
# from django.conf import settings
# from django.core import mail

# from workflows.services.executors import EmailExecutor


# class DummyInstance:
#     def __init__(self, config):
#         self.payload = {'current_node_config': config}

# @pytest.mark.django_db
# def test_email_executor_sends_and_advances(tmp_path: Path) -> None:
#     # point templates directory
#     settings.TEMPLATES[0]['DIRS'] = [str(tmp_path)]
#     (tmp_path / 'emails').mkdir()
#     (tmp_path / 'emails' / 'sample.txt').write_text('Hi {{ name }}')
#     (tmp_path / 'emails' / 'sample.html').write_text('<p>Hello {{ name }}</p>')

#     cfg = {
#         'email': {
#             'to': ['user@ex.com'],
#             'subject': 'Welcome {{ name }}',
#             'template': 'sample',
#             'context': {'name': 'Alice'},
#         },
#         'next': 'next_node'
#     }
#     inst = DummyInstance(cfg)
#     executor = EmailExecutor()

#     next_node, state = executor.doExecute(inst)

#     # Assert mail was sent
#     assert len(mail.outbox) == 1
#     sent = mail.outbox[0]
#     assert sent.subject == 'Welcome {{ name }}'  # templating happens in EmailService
#     assert 'Hi Alice' in sent.body
#     assert sent.alternatives[0][0] == '<p>Hello Alice</p>'

#     # Assert executor reports correct transition
#     assert next_node == 'next_node'
#     assert state == 'completed'
