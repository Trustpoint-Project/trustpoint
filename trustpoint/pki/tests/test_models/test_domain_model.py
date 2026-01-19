"""Test the DomainModel class."""

import datetime
from typing import Any

import pytest
from cryptography import x509
from django.utils import timezone
from trustpoint_core import oid

from pki.models import DomainModel, CaModel

COMMON_NAME = 'Root CA'
UNIQUE_NAME = COMMON_NAME.replace(' ', '_').lower()
CA_TYPE = CaModel.CaTypeChoice.LOCAL_UNPROTECTED

DOMAIN_UNIQUE_NAME = 'domain_name'


def test_attributes_and_properties(domain_instance: dict[str, Any]) -> None:
    """Test that the common_name property returns the certificate's common name."""
    tz = timezone.get_current_timezone()
    current_time = datetime.datetime.now(tz)
    domain = domain_instance.get('domain')
    issuing_ca = domain_instance.get('issuing_ca')
    cert = domain_instance.get('cert')
    if (
        not isinstance(domain, DomainModel)
        or not isinstance(issuing_ca, CaModel)
        or not isinstance(cert, x509.Certificate)
    ):
        msg = 'Domain or IssuingCA not created properly'
        raise TypeError(msg)
    assert domain.unique_name == DOMAIN_UNIQUE_NAME
    assert domain.issuing_ca == issuing_ca
    assert domain.is_active
    time_difference = (current_time - domain.created_at).total_seconds()
    assert time_difference <= 20
    assert domain.signature_suite == oid.SignatureSuite.from_certificate(cert)
