import os
import uuid
import subprocess
import ipaddress
import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.http import HttpResponse
from cryptography.fernet import Fernet
from .models import WireGuardConfig, UserIPAddress, RegistrationAttempt

SERVER_PUBLIC_KEY = os.environ.get('WG_SERVER_PUBLIC_KEY', "Public Key generated from WireGuard")
SERVER_ENDPOINT = os.environ.get('WG_SERVER_ENDPOINT', "your server's domain (XXX.XXX.XXX.XXX):51820")
VPN_SUBNET = os.environ.get('WG_VPN_SUBNET', "10.0.0.0/24")
DNS_SERVERS = os.environ.get('WG_DNS_SERVERS', "8.8.8.8, 8.8.4.4")

logger = logging.getLogger(__name__)


ENCRYPTION_KEY = os.environ.get('WG_ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key()
    logger.warning("WG_ENCRYPTION_KEY not found in environment, generated new key")
else:
    
    if not isinstance(ENCRYPTION_KEY, bytes):
        ENCRYPTION_KEY = ENCRYPTION_KEY.encode()

cipher_suite = Fernet(ENCRYPTION_KEY)

def encrypt_private_key(private_key):
    """Encrypt a private key for database storage"""
    return cipher_suite.encrypt(private_key.encode()).decode()

def decrypt_private_key(encrypted_key):
    """Decrypt a private key from database"""
    return cipher_suite.decrypt(encrypted_key.encode()).decode()

def get_client_ip(request):
    """Extract client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def register(request):
    
    client_ip = get_client_ip(request)
    
    
    attempts = RegistrationAttempt.objects.filter(ip_address=client_ip).count()
    
    if attempts >= 2:
        logger.warning(f"Registration blocked - IP {client_ip} exceeded maximum attempts")
        return render(request, 'registration_blocked.html', {
            'message': 'Registration is not available from this IP address.'
        })
    
    
    if UserIPAddress.objects.filter(ip_address=client_ip).exists():
        messages.error(request, 'An account already exists for this IP address.')
        return redirect('register')
    
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        
        
        RegistrationAttempt.objects.create(ip_address=client_ip)
        
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')
            
            
            UserIPAddress.objects.create(
                user=user,
                ip_address=client_ip,
                registration_ip=client_ip
            )
            
            
            logger.info(f"User {username} registered from IP {client_ip}")
            
            messages.success(request, f'Account created for {username}. You can now log in.')
            return redirect('login')
    else:
        form = UserCreationForm()
    
    return render(request, 'register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                
                
                client_ip = get_client_ip(request)
                user_ip_record, created = UserIPAddress.objects.get_or_create(
                    user=user,
                    defaults={'ip_address': client_ip, 'registration_ip': client_ip}
                )
                
                if not created:
                    user_ip_record.last_seen_ip = client_ip
                    user_ip_record.save()
                
                
                logger.info(f"User {username} logged in from IP {client_ip}")
                
                return redirect('dashboard')
            else:
                messages.error(request, "Invalid username or password.")
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()
    return render(request, "login.html", {"form": form})

def logout_view(request):
    
    if request.user.is_authenticated:
        logger.info(f"User {request.user.username} logged out")
    
    logout(request)
    messages.info(request, "You have successfully logged out.") 
    return redirect('login')

def generate_keys():
    """Generate WireGuard private and public key pair securely"""
    try:
        
        private_key = subprocess.check_output(["wg", "genkey"], shell=False).decode('utf-8').strip()
        
        
        process = subprocess.run(
            ["wg", "pubkey"], 
            input=private_key.encode(), 
            capture_output=True, 
            shell=False
        )
        
        if process.returncode != 0:
            logger.error(f"Error generating public key: {process.stderr.decode()}")
            raise Exception("Failed to generate WireGuard keys")
            
        public_key = process.stdout.decode('utf-8').strip()
        return private_key, public_key
    except Exception as e:
        logger.error(f"Error in key generation: {str(e)}")
        raise

def assign_ip_address():
    """Assign an IP address from the VPN subnet with validation"""
    assigned_ips = WireGuardConfig.objects.values_list('ip_address', flat=True)
    
    try:
        network = ipaddress.IPv4Network(VPN_SUBNET)
        
        
        available_ips = [str(ip) for ip in network.hosts()][1:]
        
        for ip in available_ips:
            if ip not in assigned_ips:
                
                ipaddress.IPv4Address(ip)
                return ip
        
        logger.warning("IP pool exhausted")
        raise ValueError("No more IP addresses available in the subnet")
    except Exception as e:
        logger.error(f"Error assigning IP: {str(e)}")
        raise

@login_required
def dashboard(request):
    try:
        
        client_ip = get_client_ip(request)
        user_ip_record = get_object_or_404(UserIPAddress, user=request.user)
        user_ip_record.last_seen_ip = client_ip
        user_ip_record.save()
        
        
        if client_ip != user_ip_record.registration_ip:
            logger.warning(f"User {request.user.username} accessing from new IP: {client_ip}, registered with: {user_ip_record.registration_ip}")
        
        try:
            config = WireGuardConfig.objects.get(user=request.user)
        except WireGuardConfig.DoesNotExist:
            
            private_key, public_key = generate_keys()
            
            
            ip_address = assign_ip_address()
            
            
            encrypted_private_key = encrypt_private_key(private_key)
            
            
            config = WireGuardConfig.objects.create(
                user=request.user,
                private_key=encrypted_private_key,
                public_key=public_key,
                ip_address=ip_address
            )
            
            
            logger.info(f"Created new WireGuard config for user {request.user.username}")
        
        
        decrypted_private_key = decrypt_private_key(config.private_key)
        
        
        config_file_content = generate_wireguard_config(
            decrypted_private_key,
            config.ip_address
        )
        
        return render(request, 'dashboard.html', {
            'config': config,
            'config_file_content': config_file_content
        })
    except Exception as e:
        logger.error(f"Dashboard error for user {request.user.username}: {str(e)}")
        messages.error(request, "An error occurred loading your configuration.")
        return render(request, 'dashboard.html', {'error': True})

def generate_wireguard_config(private_key, ip_address):
    """Generate a WireGuard configuration file for the client"""
    wireguard_config = f"""[Interface]
PrivateKey = {private_key}
Address = {ip_address}/24
DNS = {DNS_SERVERS}

[Peer]
PublicKey = {SERVER_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
Endpoint = {SERVER_ENDPOINT}
PersistentKeepalive = 25
"""
    return wireguard_config

@login_required
def download_config(request):
    try:
        
        client_ip = get_client_ip(request)
        user_ip_record = get_object_or_404(UserIPAddress, user=request.user)
        user_ip_record.last_seen_ip = client_ip
        user_ip_record.save()
        
        
        logger.info(f"Config download by {request.user.username} from IP {client_ip}")
        
        config = get_object_or_404(WireGuardConfig, user=request.user)
        
        
        decrypted_private_key = decrypt_private_key(config.private_key)
        
        config_content = generate_wireguard_config(
            decrypted_private_key,
            config.ip_address
        )
        
        response = HttpResponse(config_content, content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename={request.user.username}_wireguard.conf'
        
        
        response['X-Content-Type-Options'] = 'nosniff'
        response['Content-Security-Policy'] = "default-src 'none'"
        response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response['Pragma'] = 'no-cache'
        
        return response
    except WireGuardConfig.DoesNotExist:
        messages.error(request, 'No configuration found. Please visit the dashboard first.')
        return redirect('dashboard')
    except Exception as e:
        logger.error(f"Config download error for user {request.user.username}: {str(e)}")
        messages.error(request, "An error occurred generating your configuration.")
        return redirect('dashboard')
