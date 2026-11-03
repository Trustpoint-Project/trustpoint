# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Certificate names in the CA hierarchy must remain text when rendered as HTML."""

from unittest.mock import Mock

import pytest
from django.template import Context, Template
from django.test import RequestFactory
from django.urls import reverse

from help_pages.devices_help_views import OpcUaGdsPushOnboardingStrategy


@pytest.mark.parametrize('source', ['common_name', 'bytes_common_name', 'unique_name'])
def test_ca_hierarchy_escapes_names(source: str) -> None:
    name = '<b>CA & "name"</b>'
    ca = Mock(pk=1, unique_name=name, crl_pem=None)
    common_names = (
        []
        if source == 'unique_name'
        else [
            Mock(value=name.encode() if source == 'bytes_common_name' else name),
        ]
    )
    certificate = ca.ca_certificate_model.get_certificate_serializer.return_value.as_crypto.return_value
    certificate.subject.get_attributes_for_oid.return_value = common_names

    html, missing_crl = OpcUaGdsPushOnboardingStrategy()._build_ca_hierarchy_html([ca])
    rendered = Template('{% load csrf_token_filter %}{{ html|replace_csrf:request }}').render(
        Context({'html': html, 'request': RequestFactory().get('/')}),
    )

    assert name not in rendered
    assert '&lt;b&gt;CA &amp; &quot;name&quot;&lt;/b&gt;' in rendered
    assert f'href="{reverse("pki:issuing_cas-detail", kwargs={"pk": ca.pk})}"' in rendered
    assert missing_crl is True
