# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management API and service-account Behave steps."""

from __future__ import annotations

from behave import given, runner, then, when
from django.test import Client

from features.support.auth import create_service_account
from features.support.assertions import response_json


@given('an active service account credential exists')
def step_service_account_exists(context: runner.Context) -> None:
    account, credential, secret = create_service_account()
    context.service_account = account
    context.service_credential = credential
    context.service_secret = secret


@when('the service account requests an OAuth2 token with client credentials')
def step_service_account_token(context: runner.Context) -> None:
    context.response = Client().post(
        '/api/token/',
        {
            'grant_type': 'client_credentials',
            'client_id': context.service_credential.client_id,
            'client_secret': context.service_secret,
        },
    )
    if context.response.status_code == 200:
        context.api_token = response_json(context.response)['access']


@when('the service account requests a token with an invalid secret')
def step_service_account_invalid_secret(context: runner.Context) -> None:
    context.response = Client().post(
        '/api/token/',
        {
            'grant_type': 'client_credentials',
            'client_id': context.service_credential.client_id,
            'client_secret': 'invalid-secret',
        },
    )


@then('the token response contains an access token')
def step_access_token_present(context: runner.Context) -> None:
    payload = response_json(context.response)
    assert isinstance(payload.get('access'), str)
    assert payload['access']


@then('the service account is not allowed to log into the web UI')
def step_service_web_login_denied(context: runner.Context) -> None:
    client = Client()
    logged_in = client.login(username=context.service_account.username, password=context.service_secret)
    assert not logged_in


@when('an unauthenticated client posts to the REST PKI enroll endpoint')
def step_rest_pki_unauthenticated(context: runner.Context) -> None:
    context.response = Client().post(
        '/api/rest-pki/enroll/',
        data='{}',
        content_type='application/json',
    )


@when('an unauthenticated client posts to the REST PKI revoke endpoint')
def step_rest_pki_revoke_unauthenticated(context: runner.Context) -> None:
    context.response = Client().post(
        '/api/rest-pki/revoke/',
        data='{}',
        content_type='application/json',
    )


@then('the response is an authentication failure')
def step_auth_failure(context: runner.Context) -> None:
    assert context.response.status_code in (401, 403)

@given('the "{protocol}" protocol endpoint is registered')
def step_protocol_registered(context: runner.Context, protocol: str) -> None:
    from django.urls import resolve
    probe = {
        'CMP': '/.well-known/cmp/p/test-domain',
        'EST': '/.well-known/est/test-domain/cacerts/',
    }[protocol]
    context.resolved_protocol = resolve(probe)
    assert context.resolved_protocol is not None


@then('the "{protocol}" route resolves to a Trustpoint view')
def step_protocol_resolves(context: runner.Context, protocol: str) -> None:
    del protocol
    assert context.resolved_protocol.func is not None

@given('the REST certificate "{operation}" endpoint is registered')
def step_rest_certificate_route_registered(context: runner.Context, operation: str) -> None:
    from django.urls import resolve

    probe = {
        'enroll': '/rest/test-domain/domain_credential/enroll',
        'reenroll': '/rest/test-domain/domain_credential/reenroll',
    }[operation]
    context.resolved_rest_certificate_route = resolve(probe)
    assert context.resolved_rest_certificate_route is not None


@then('the REST certificate route resolves to a Trustpoint view')
def step_rest_certificate_route_resolves(context: runner.Context) -> None:
    assert context.resolved_rest_certificate_route.func is not None

@when('the authenticated service account enrolls for missing device {device_id:d}')
def step_authenticated_missing_device_enroll(context: runner.Context, device_id: int) -> None:
    import json

    context.response = Client().post(
        '/api/rest-pki/enroll/',
        data=json.dumps(
            {
                'device_id': device_id,
                'cert_profile': 'tls_server',
                'csr': 'not-parsed-before-device-resolution',
            }
        ),
        content_type='application/json',
        HTTP_AUTHORIZATION=f'Bearer {context.api_token}',
    )
