"""API Views for Signer-related endpoints.

Provides REST API views for signer operations including hash signing.
"""

from typing import Any, ClassVar

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from drf_yasg.utils import swagger_auto_schema  # type: ignore[import-untyped]
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from signer.models import SignedMessageModel, SignerModel
from signer.serializers import (
    SignedMessageSerializer,
    SignerCertificateSerializer,
    SignerSerializer,
    SignHashRequestSerializer,
    SignHashResponseSerializer,
)
from trustpoint.logger import LoggerMixin


class SignerViewSet(LoggerMixin, viewsets.ReadOnlyModelViewSet[SignerModel]):
    """ViewSet for Signer operations."""

    queryset = SignerModel.objects.all()
    serializer_class = SignerSerializer
    permission_classes: ClassVar[list[Any]] = [IsAuthenticated]  # type: ignore[misc]

    @swagger_auto_schema(  # type: ignore[misc]
        method='post',
        request_body=SignHashRequestSerializer,
        responses={
            200: SignHashResponseSerializer,
            400: 'Bad Request - Invalid input data',
            404: 'Not Found - Signer does not exist',
            500: 'Internal Server Error - Failed to sign hash',
        },
        operation_summary='Sign a hash value',
        operation_description=(
            'Signs a hash value using the specified signer. '
            'The hash value must be provided as a hexadecimal string. '
            'The signature is returned in hexadecimal format.'
        ),
    )
    @action(detail=False, methods=['post'], url_path='sign')
    def sign_hash(self, request: Request) -> Response:
        """Sign a hash value with the specified signer."""
        # Validate input
        serializer = SignHashRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        signer_id = serializer.validated_data['signer_id']
        hash_value = serializer.validated_data['hash_value']

        try:
            signer = SignerModel.objects.get(id=signer_id)

            hash_algorithm_name = signer.hash_algorithm

            hash_bytes = bytes.fromhex(hash_value)

            private_key = signer.credential.get_private_key()

            hash_algo = getattr(hashes, hash_algorithm_name.upper())()
            prehashed_algo = Prehashed(hash_algo)

            if isinstance(private_key, rsa.RSAPrivateKey):
                signature = private_key.sign(hash_bytes, padding.PKCS1v15(), prehashed_algo)
            elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                signature = private_key.sign(hash_bytes, ec.ECDSA(prehashed_algo))
            else:
                self.logger.error('Unsupported key algorithm for signer %s', signer_id)
                return Response(
                    {'error': 'Unsupported key algorithm'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            signature_hex = signature.hex()

            signed_message = SignedMessageModel.objects.create(
                signer=signer,
                hash_value=hash_value,
                signature=signature_hex
            )

            response_data = {
                'signer_id': signer.id,
                'signer_name': signer.unique_name,
                'hash_algorithm': hash_algorithm_name,
                'hash_value': hash_value,
                'signature': signature_hex,
                'signed_message_id': signed_message.id,
                'created_at': signed_message.created_at,
            }

            self.logger.info(
                'Successfully signed hash with signer %s (ID: %d)',
                signer.unique_name,
                signer.id
            )

            return Response(response_data, status=status.HTTP_200_OK)

        except SignerModel.DoesNotExist:
            self.logger.exception('Signer with ID %d not found', signer_id)
            return Response(
                {'error': f'Signer with ID {signer_id} does not exist'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception:
            self.logger.exception('Failed to sign hash with signer %s', signer_id)
            return Response(
                {'error': 'Failed to sign hash'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @swagger_auto_schema(  # type: ignore[misc]
        method='get',
        responses={
            200: SignerCertificateSerializer,
            404: 'Not Found - Signer does not exist',
        },
        operation_summary='Get signer certificate',
        operation_description=(
            "Returns the signer's certificate in PEM format. "
            'The certificate can be used to verify signatures created by this signer.'
        ),
    )
    @action(detail=True, methods=['get'], url_path='certificate')
    def get_certificate(self, request: Request, pk: int | None = None) -> Response:  # noqa: ARG002
        """Get the signer's certificate in PEM format."""
        try:
            signer = self.get_object()

            # Get certificate in PEM format
            certificate_pem = signer.credential.certificate_or_error.get_certificate_serializer().as_pem().decode()

            self.logger.info(
                'Certificate retrieved for signer %s (ID: %d)',
                signer.unique_name,
                signer.id
            )

            return Response(
                {
                    'signer_id': signer.id,
                    'signer_name': signer.unique_name,
                    'certificate_pem': certificate_pem,
                },
                status=status.HTTP_200_OK
            )

        except SignerModel.DoesNotExist:
            self.logger.exception('Signer with ID %d not found', pk)
            return Response(
                {'error': f'Signer with ID {pk} does not exist'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception:
            self.logger.exception('Failed to retrieve certificate for signer %s', pk)
            return Response(
                {'error': 'Failed to retrieve certificate'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SignedMessageViewSet(viewsets.ReadOnlyModelViewSet[SignedMessageModel]):
    """ViewSet for SignedMessage operations."""

    queryset = SignedMessageModel.objects.all().order_by('-created_at')
    serializer_class = SignedMessageSerializer
    permission_classes: ClassVar[list[Any]] = [IsAuthenticated]  # type: ignore[misc]
    filterset_fields: ClassVar[list[str]] = ['signer']

    @swagger_auto_schema(  # type: ignore[misc]
        operation_summary='List all signed messages',
        operation_description='Returns a list of all signed messages, ordered by creation date (newest first).',
    )
    def list(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """List all signed messages."""
        return super().list(request, *args, **kwargs)

    @swagger_auto_schema(  # type: ignore[misc]
        operation_summary='Retrieve a signed message',
        operation_description='Returns details of a specific signed message.',
    )
    def retrieve(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Retrieve a specific signed message."""
        return super().retrieve(request, *args, **kwargs)
