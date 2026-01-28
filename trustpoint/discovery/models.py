from django.db import models
# We import the existing CertificateModel so we can link to it
from pki.models.certificate import CertificateModel 

class DiscoveredDevice(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    hostname = models.CharField(max_length=255, blank=True, null=True)
    
    # Stores ports as a list: [80, 443, 4840, 8883]
    open_ports = models.JSONField(default=list, blank=True)
    
    # Stores basic SSL text info for the table view
    ssl_info = models.JSONField(default=dict, blank=True, null=True)
    
    # NEW: This links the discovery entry to the formal PKI Certificate record
    certificate_record = models.ForeignKey(
        CertificateModel, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='discovered_on_devices'
    )
    
    last_seen = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} ({self.hostname or 'Unknown'})"