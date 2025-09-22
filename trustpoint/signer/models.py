"""Contains Models For Signers App."""

from typing import ClassVar

from django.db import models
from trustpoint_core.oid import AlgorithmIdentifier, NamedCurve


class KeyLengths(models.IntegerChoices):
    """Key Lengths Choices."""

    B2048 = 2048, '2048 bits'
    B3072 = 3072, '3072 bits'
    B4096 = 4096, '4096 bits'
    B8192 = 8192, '8192 bits'


class Signer(models.Model):
    """Contains fields for signer model."""

    SIGNING_ALGORITHM_CHOICES: ClassVar[list[tuple[str, str]]] = [
        (x.dotted_string, x.verbose_name) for x in AlgorithmIdentifier
    ]
    SIGNING_CURVE_CHOICES: ClassVar[list[tuple[str, str]]] = [
        (x.ossl_curve_name, x.name) for x in NamedCurve if x.ossl_curve_name
    ]

    unique_name = models.CharField(max_length=30, unique=True)
    signing_algorithm = models.CharField(max_length=50, choices=SIGNING_ALGORITHM_CHOICES, editable=True)
    key_length = models.IntegerField(null=True, blank=True, choices=KeyLengths.choices)
    curve = models.CharField(max_length=50, choices=SIGNING_CURVE_CHOICES, null=True, blank=True)  # noqa:DJ001
    hash_function = models.CharField(max_length=50)
    private_key = models.CharField(max_length=4096)
    certificate = models.CharField(max_length=4096)
    expires_by = models.DateTimeField()
    created_by = models.CharField(max_length=100)
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        """To represent the signer object with its unique name.

        Returns: Give out signer objects unique name.

        """
        return self.unique_name


class SignedMessage(models.Model):
    """Model to store signed messages, its signature and certificate(with public key)."""

    signer = models.ForeignKey(Signer, on_delete=models.CASCADE, related_name='signed_messages')
    cert_subject = models.TextField()
    hash_value = models.CharField(max_length=256)
    signature = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        """String representation of SignedMessage object.

        Returns: String formated name of signer and when it was signed.

        """
        return f'Signature by {self.signer.unique_name} on {self.created_at.strftime("%Y-%m-%d %H:%M:%S")}'