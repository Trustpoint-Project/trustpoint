"""This module contains the AOKI endpoints (views)."""

from __future__ import annotations
from django.views import View

class AokiInitializationRequestView(View):
    """View for handling AOKI initialization requests."""

    def post(self, request, *args, **kwargs):
        """Handle POST requests for AOKI initialization."""
        # Verify Device IDevID against Truststores
        # (need to figure out how to do this efficiently as we have no domain here)
        # Maybe first look for ownership certs and reference the truststore there?

        # extract SN from client cert
        # go through all registration patterns and check for truststore

        # Check we have a valid ownership certificate for this device

        # Send the device a response of the form:
        # (OwnershipCert || TLS Truststore || enrollment_info) signed by owner private key
        # enrollment_info =
        #   {protocols: [{"protocol": "EST", "url": "/.well-known/est/domain/domaincredential/simpleenroll"}]}
