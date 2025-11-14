"""Business logic for certificate operations."""

from django.db.models.query import QuerySet

from pki.models.certificate import CertificateModel


class CertificateService:
    """Service class for managing Certificate objects."""

    def __init__(self, user_id: str | None = None) -> None:
        """Initializes the CertificateService with a user.

        Args:
            user_id: The credential serializer to store in the database.
        """
        self.user_id = user_id

    def get_certificates(self) -> QuerySet[CertificateModel]:
        """Retrieve certificates from the database."""
        queryset = CertificateModel.objects.all()
        return queryset.order_by('-created_at')
