# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Remote credential download steps migrated from R_013."""

from __future__ import annotations

from behave import given, runner, then, when
from bs4 import BeautifulSoup
from django.test import Client

from devices.models import IssuedCredentialModel, RemoteDeviceCredentialDownloadModel
from devices.tests.conftest import create_mock_models
from features.support.auth import create_admin_client

HTTP_OK = 200
HTTP_FOUND = 302
MIN_OTP_LENGTH = 8
MAX_OTP_LENGTH = 32


@given('an issued credential is successfully issued')
def step_issued_credential(context: runner.Context) -> None:
    models = create_mock_models()
    context.issued_credential_model = IssuedCredentialModel.objects.get(pk=models['issued_credential'].pk)
    context.download_view_url = f'/devices/credential-download/browser/{context.issued_credential_model.pk}/'


@when('the admin visits the associated "Download on Device browser" view')
def step_admin_download_view(context: runner.Context) -> None:
    context.response = context.authenticated_client.get(context.download_view_url)
    assert context.response.status_code == HTTP_OK
    context.otp_view_response = context.response.content


@then('a one-time password is displayed which can be used to download the credential from a remote device')
def step_otp_displayed(context: runner.Context) -> None:
    element = BeautifulSoup(context.otp_view_response, 'html.parser').find(id='otp-display')
    assert element is not None, 'otp-display not in response'
    otp = element.text.strip()
    assert MIN_OTP_LENGTH <= len(otp) <= MAX_OTP_LENGTH
    context.otp = otp


def _prepare_valid_otp(context: runner.Context) -> None:
    context.admin_user, context.authenticated_client = create_admin_client()
    step_issued_credential(context)
    step_admin_download_view(context)
    step_otp_displayed(context)


@given('a correct one-time password')
def step_correct_otp(context: runner.Context) -> None:
    _prepare_valid_otp(context)


@given('an incorrect one-time password')
def step_incorrect_otp(context: runner.Context) -> None:
    context.otp = 'very_wrong_otp'


@when('the user visits the "/devices/browser" endpoint and enters the OTP')
def step_submit_otp(context: runner.Context) -> None:
    context.unauthenticated_user_client = Client()
    response = context.unauthenticated_user_client.get('/devices/browser/')
    assert response.status_code == HTTP_OK
    assert 'id="id_otp"' in response.content.decode()
    response = context.unauthenticated_user_client.post('/devices/browser/', {'otp': context.otp})
    if response.status_code == HTTP_FOUND:
        redirect_url = response.url
        context.download_token = redirect_url.split('?token=')[-1] if '?token=' in redirect_url else None
        context.download_id = (
            int(redirect_url.split('credential-download/')[1].split('/')[0])
            if 'credential-download' in redirect_url else None
        )
        response = context.unauthenticated_user_client.get(response.url)
    assert response.status_code == HTTP_OK
    context.otp_post_view_response = response.content


@then('they will receive a page to select the format for the credential download')
def step_format_page(context: runner.Context) -> None:
    assert 'value="pem_zip"' in context.otp_post_view_response.decode()


@then('they will receive a warning saying the OTP is incorrect')
def step_incorrect_warning(context: runner.Context) -> None:
    assert 'The provided password is not valid.' in context.otp_post_view_response.decode()


@given('the user is on the credential download page')
def step_download_page(context: runner.Context) -> None:
    _prepare_valid_otp(context)
    step_submit_otp(context)
    step_format_page(context)


@given('the download token is not yet expired')
def step_token_valid(context: runner.Context) -> None:
    assert context.download_token is not None
    model = RemoteDeviceCredentialDownloadModel.objects.get(pk=context.download_id)
    assert not model.check_token('dummy_token')
    assert model.check_token(context.download_token)


@when('the user enters a password to encrypt the credential private key')
def step_download_password(context: runner.Context) -> None:
    context.test_password = 'testing321321'  # noqa: S105


@when('selects a file format')
def step_file_format(context: runner.Context) -> None:
    url = f'/devices/browser/credential-download/{context.download_id}/?token={context.download_token}'
    context.download_response = context.unauthenticated_user_client.post(
        url,
        {
            'password': context.test_password,
            'confirm_password': context.test_password,
            'file_format': 'pem_zip',
        },
    )
    assert context.download_response.status_code == HTTP_OK


@then('the credential will be downloaded to their browser in the requested format')
def step_downloaded(context: runner.Context) -> None:
    assert 'application/zip' in context.download_response['Content-Type']
    assert 'attachment; filename=' in context.download_response['Content-Disposition']
