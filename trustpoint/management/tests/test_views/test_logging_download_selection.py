# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression coverage for selected-log archive downloads."""

import io
import tarfile
import zipfile
from http import HTTPStatus
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urljoin

import pytest
from bs4 import BeautifulSoup
from django.contrib.auth.models import Permission
from django.test import Client
from django.urls import reverse

from users.models import TrustpointUser


@pytest.mark.django_db
@pytest.mark.parametrize('archive_format', ['zip', 'tar.gz'])
def test_selected_logs_download_from_rendered_table(
    admin_client: Client, admin_user: TrustpointUser, tmp_path: Path, archive_format: str
) -> None:
    """Both rendered buttons target archives containing exactly the selected logs."""
    admin_user.role.permissions.add(Permission.objects.get(codename='view_system_logs'))
    contents = {
        'trustpoint.log': b'2026-10-25 12:00:00 current log',
        'trustpoint.log.1': b'2026-10-24 12:00:00 rotated log',
        'trustpoint.log.2': b'2026-10-23 12:00:00 unselected log',
    }
    for name, content in contents.items():
        (tmp_path / name).write_bytes(content)

    with patch('management.views.logging.LOG_DIR_PATH', tmp_path):
        table_url = reverse('management:logging-files')
        page = admin_client.get(table_url)
        assert page.status_code == HTTPStatus.OK
        html = BeautifulSoup(page.content, 'html.parser')
        button = html.select_one(f'button[data-tp-url="download/{archive_format}"]')
        assert button is not None
        assert button.get('data-tp-value-type') == 'log-filename'
        assert button.has_attr('disabled')

        selected = ['trustpoint.log', 'trustpoint.log.1']
        assert set(selected) <= {field.get('value') for field in html.select('.row_checkbox > input')}
        target = urljoin(table_url, str(button['data-tp-url']) + '/') + '/'.join(selected) + '/'
        response = admin_client.get(target)

    assert response.status_code == HTTPStatus.OK
    assert f'trustpoint-logs.{archive_format}' in response['Content-Disposition']
    if archive_format == 'zip':
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            actual = {name: archive.read(name) for name in archive.namelist()}
    else:
        with tarfile.open(fileobj=io.BytesIO(response.content), mode='r:gz') as archive:
            actual = {}
            for name in archive.getnames():
                member = archive.extractfile(name)
                assert member is not None
                actual[name] = member.read()
    assert actual == {name: contents[name] for name in selected}
