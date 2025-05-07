"""AOKI Client for testing purposes."""

from __future__ import annotations


class AokiClient:
    """AOKI Client for testing purposes."""

    def __init__(self, server_url: str, *args: str, **kwargs: str) -> None:
        """Initialize the AokiClient."""
        self.server_url = server_url
        self.args = args
        self.kwargs = kwargs

    def onboard(self) -> None:
        """Run the AOKI Zero-Touch Device Onboarding process."""


if __name__ == '__main__':
    client = AokiClient(
        server_url='https://localhost:443/aoki/init',
        cert_path='idevid.pem',
        key_path='idevid_pk.pem',
        owner_truststore_path='owner_truststore.pem',
        mdns = False, # not yet implemented
    )
    client.onboard()
