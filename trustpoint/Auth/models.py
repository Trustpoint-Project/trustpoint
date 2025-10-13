"""Module defining the UserToken model for API authentication tokens."""
from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


class UserToken(models.Model):
    """Model representing an access token associated with a user."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tokens')
    key = models.CharField(max_length=40, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()



    def __str__(self) -> str:
        """Return a readable string representation of the token.

        Returns:
            A string describing the token user and expiration date.
        """
        return f'Token for {self.user.username} (exp: {self.expires_at.date()})'


    def is_expired(self) -> bool:
        """Check if the token is expired.

        Returns:
            True if the current time is past the token's expiration, False otherwise.
        """
        return timezone.now() > self.expires_at