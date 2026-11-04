# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Exercise CI guards with successful and failing external responses."""

# ruff: noqa: INP001, S603, S607 - executes repository shell steps with synthetic inputs.

import os
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow_step(workflow: str, job: str, name: str) -> str:
    """Read the actual shell command so tests exercise the deployed guard."""
    data = yaml.safe_load((ROOT / '.github/workflows' / workflow).read_text())
    return next(step['run'] for step in data['jobs'][job]['steps'] if step.get('name') == name)


@pytest.mark.parametrize(
    ('ref', 'release_tag', 'expected_flags'),
    [
        ('refs/heads/main', '', ('true', 'false')),
        ('refs/heads/feature', '', ('false', 'false')),
        ('refs/tags/{tag}', '', ('true', 'true')),
        ('refs/heads/main', '{tag}', ('true', 'true')),
        ('refs/tags/v0.0.0', '', None),
        ('refs/heads/main', 'v0.0.0', None),
    ],
)
def test_publisher_version_guard(
    tmp_path: Path, ref: str, release_tag: str, expected_flags: tuple[str, str] | None
) -> None:
    """Use the checked-out revision and selected release, while rejecting mismatched tags."""
    version = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']['version']
    tag = f'v{version}'
    output = tmp_path / 'output'
    result = subprocess.run(
        [
            'bash',
            '-e',
            '-c',
            workflow_step('publish-images.yml', 'publish', 'Verify package version and Git release tag'),
        ],
        cwd=ROOT,
        env={
            **os.environ,
            'GITHUB_REF': ref.format(tag=tag),
            'GITHUB_SHA': 'a' * 40,
            'GITHUB_REPOSITORY_OWNER': 'Trustpoint-Project',
            'RELEASE_TAG': release_tag.format(tag=tag),
            'GITHUB_OUTPUT': str(output),
        },
        check=False,
        capture_output=True,
        text=True,
    )
    assert (result.returncode == 0) == (expected_flags is not None), result.stdout + result.stderr
    if expected_flags:
        latest, is_release = expected_flags
        values = dict(line.split('=', 1) for line in output.read_text().splitlines())
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        assert values['revision'] == revision
        assert values['publish_latest'] == latest
        assert values['is_release'] == is_release
        assert values['sbom_version'] == (tag if is_release == 'true' else revision)
        assert values['ghcr_namespace'] == 'ghcr.io/trustpoint-project'


@pytest.mark.parametrize(
    ('status', 'body', 'success'),
    [
        ('200', '<div id="dashboard"></div>', True),
        ('302', '', False),
        ('200', '<form id="login"></form>', False),
        ('500', '<div id="dashboard"></div>', False),
    ],
)
def test_dashboard_requires_authenticated_content(tmp_path: Path, status: str, body: str, *, success: bool) -> None:
    """A redirect, login page, or error response must fail the dashboard check."""
    curl = tmp_path / 'curl'
    curl.write_text('#!/bin/sh\nprintf "%s" "$RESPONSE_BODY" > dashboard.txt\nprintf "%s" "$RESPONSE_STATUS"\n')
    curl.chmod(0o755)
    result = subprocess.run(
        [
            'bash',
            '-e',
            '-c',
            workflow_step('docker-test-auto-setup.yml', 'test-auto-setup', 'Test 4 - Access authenticated dashboard'),
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            'PATH': f'{tmp_path}:{os.environ["PATH"]}',
            'RESPONSE_BODY': body,
            'RESPONSE_STATUS': status,
            'GITHUB_STEP_SUMMARY': str(tmp_path / 'summary'),
        },
        check=False,
        capture_output=True,
        text=True,
    )
    assert (result.returncode == 0) == success, result.stdout + result.stderr


@pytest.mark.parametrize(
    ('image', 'version', 'success'),
    [
        ('ghcr.io/trustpoint-project/trustpoint@sha256:' + 'a' * 64, 'v1.0.0', True),
        ('ghcr.io/trustpoint-project/trustpoint:latest', 'v1.0.0', False),
        ('ghcr.io/trustpoint-project/trustpoint@sha256:' + 'a' * 64, '../outside', False),
    ],
)
def test_sbom_requires_digest_and_safe_path(image: str, version: str, *, success: bool) -> None:
    """Never publish an SBOM from a moving tag or write outside its version directory."""
    result = subprocess.run(
        ['bash', '-e', '-c', workflow_step('sbom.yml', 'sbom', 'Require immutable image and safe version path')],
        env={**os.environ, 'IMAGE': image, 'VERSION': version},
        check=False,
        capture_output=True,
        text=True,
    )
    assert (result.returncode == 0) == success, result.stdout + result.stderr
