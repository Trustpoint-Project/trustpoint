from django.db import models

# Create your models here.
from django.db import models

class DiscoveredDevice(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    hostname = models.CharField(max_length=255, blank=True, null=True)
    
    # We store ports as a JSON list (e.g., [80, 443, 1883])
    # SQLite/Postgres supports JSONField nicely in modern Django
    open_ports = models.JSONField(default=list, blank=True)
    
    # Store detailed SSL info as JSON (is_self_signed, issuer, etc.)
    ssl_info = models.JSONField(default=dict, blank=True, null=True)
    
    last_seen = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} ({self.hostname or 'Unknown'})"
