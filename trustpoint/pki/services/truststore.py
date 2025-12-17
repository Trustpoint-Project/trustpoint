"""Business logic for truststore operations."""

from django.core.exceptions import ValidationError
from django.db.models.query import QuerySet
from trustpoint_core.serializer import CertificateCollectionSerializer

from pki.forms import TruststoreAddForm
from pki.models.truststore import TruststoreModel
from util.field import get_certificate_name


class TruststoreService:
    """Service class for managing Truststore objects."""

    def __init__(self) -> None:
        """Initializes the TruststoreService with a user id."""

    def get_all(self) -> QuerySet[TruststoreModel]:
        """Retrieve Truststore from the database."""
        queryset = TruststoreModel.objects.all()
        return queryset.order_by('-created_at')

    def create(self, unique_name: str, intended_usage: str, trust_store_file: bytes) -> TruststoreModel:
        """Create a new Truststore instance."""
        try:
            certificate_collection_serializer = CertificateCollectionSerializer.from_bytes(trust_store_file)
            certs = certificate_collection_serializer.as_crypto()
        except Exception as exception:
            error_message = 'Unable to process the Truststore. May be malformed / corrupted.'
            raise ValidationError(error_message) from exception

        if not unique_name:
            unique_name = get_certificate_name(certs[0])
        if TruststoreModel.objects.filter(unique_name=unique_name).exists():
            error_message = 'Truststore with the provided name already exists.'
            raise ValidationError(error_message)
        try:
            return TruststoreAddForm.save_trust_store(
                unique_name=unique_name,
                intended_usage=TruststoreModel.IntendedUsage(int(intended_usage)),
                certificates=certs,
            )
        except Exception as exception:
            raise ValidationError(str(exception)) from exception
