import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class WireGuardConfig(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    private_key = models.CharField(max_length=255)  
    public_key = models.CharField(max_length=255)
    ip_address = models.CharField(max_length=15)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['ip_address']),
        ]
    
    def __str__(self):
        return f"WireGuard Config for {self.user.username}"

class UserIPAddress(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    ip_address = models.GenericIPAddressField(help_text="Current IP address")
    registration_ip = models.GenericIPAddressField(help_text="IP address used during registration")
    last_seen_ip = models.GenericIPAddressField(null=True, blank=True)
    last_updated = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name_plural = "User IP Addresses"
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['registration_ip']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.ip_address}"

class RegistrationAttempt(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['ip_address']),
        ]
