WireGuard VPN Management System
===============================

A secure Django-based web application for managing WireGuard VPN configurations with one-account-per-IP restrictions.

Features
--------

*   User registration with IP address restrictions (max 2 attempts per IP address)
*   One account per IP address enforcement
*   Secure WireGuard configuration generation and management
*   Encrypted storage of private keys
*   Comprehensive logging and security features
*   User-friendly dashboard for managing VPN configurations

### ⭐ Support This Project

If you find this project useful, please consider giving it a star on GitHub! Your support helps make this project better and reaches more users.

[⭐ Star on GitHub](https://github.com/AsaBizanjo/PAK-PN)

Getting a Virtual Machine
-------------------------

### Recommended Specifications

*   **RAM**: 2GB (recommended), 1GB (minimum)
*   **CPU**: 1 vCPU or more
*   **Storage**: 20GB SSD
*   **OS**: Ubuntu 20.04 LTS

### Providers

You can get a suitable VM from:

*   DigitalOcean ($5-10/month)
*   Linode ($5-10/month)
*   Vultr ($5-10/month)
*   AWS EC2 (t3.micro or t3.small)
*   Azure B1s or B1ms
*   For Cheaper Options Use https://lowendbox.com/ ($1 per month!)

When setting up your VM, make sure to:

1.  Choose Ubuntu 20.04 LTS as the operating system
2.  Enable SSH access
3.  Configure a firewall to allow ports 22 (SSH), 80 (HTTP), 443 (HTTPS), and 51820 (WireGuard UDP)

Installation Instructions for Ubuntu 20.04
------------------------------------------

### 1\. Install System Dependencies

    # Update system packages
    sudo apt update
    sudo apt upgrade -y
    
    # Install required packages
    sudo apt install -y python3-pip python3-venv wireguard nginx
    
    # Enable IP forwarding for WireGuard
    echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p

### 2\. Set Up WireGuard Server

    # Generate server keys
    umask 077
    wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
    
    # Create WireGuard server configuration
    sudo nano /etc/wireguard/wg0.conf

Add the following to wg0.conf:

    [Interface]
    PrivateKey = $(cat /etc/wireguard/server_private.key)
    Address = 10.0.0.1/24
    ListenPort = 51820
    SaveConfig = true
    PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

Note: Replace `eth0` with your actual network interface (check with `ip a`).

    # Start and enable WireGuard
    sudo systemctl enable wg-quick@wg0
    sudo systemctl start wg-quick@wg0

### 3\. Clone and Set Up the Project

    # Create project directory
    sudo mkdir -p /opt/wireguard_vpn
    sudo chown $USER:$USER /opt/wireguard_vpn
    
    # Clone the repository
    git clone https://github.com/yourusername/wireguard-vpn-management.git /opt/wireguard_vpn
    
    # Create and activate virtual environment
    cd /opt/wireguard_vpn
    python3 -m venv venv
    source venv/bin/activate
    
    # Install dependencies
    pip install -r requirements.txt
    pip install gunicorn cryptography

### 4\. Configure the Application

    # Create .env file for environment variables
    nano .env

Add the following to .env:

    WG_SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server_public.key)
    WG_SERVER_ENDPOINT=your_server_ip:51820
    WG_VPN_SUBNET=10.0.0.0/24
    WG_DNS_SERVERS=8.8.8.8, 8.8.4.4
    WG_ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

    # Apply migrations
    python manage.py migrate
    
    # Create superuser (admin)
    python manage.py createsuperuser
    
    # Collect static files
    python manage.py collectstatic

### 5\. Set Up Gunicorn Service

    # Create systemd service file
    sudo nano /etc/systemd/system/wireguard_vpn.service

Add the following:

    [Unit]
    Description=Gunicorn daemon for WireGuard VPN Management
    After=network.target
    
    [Service]
    User=www-data
    Group=www-data
    WorkingDirectory=/opt/wireguard_vpn
    ExecStart=/opt/wireguard_vpn/venv/bin/gunicorn --bind unix:/opt/wireguard_vpn/wireguard_vpn.sock your_project.wsgi:application
    Restart=on-failure
    Environment="DJANGO_SETTINGS_MODULE=your_project.settings"
    EnvironmentFile=/opt/wireguard_vpn/.env
    
    [Install]
    WantedBy=multi-user.target

Note: Replace `your_project` with your actual Django project name.

    # Set permissions
    sudo chown -R www-data:www-data /opt/wireguard_vpn
    
    # Enable and start the service
    sudo systemctl enable wireguard_vpn
    sudo systemctl start wireguard_vpn

### 6\. Configure Nginx

    # Create Nginx site configuration
    sudo nano /etc/nginx/sites-available/wireguard_vpn

Add the following:

    server {
        listen 80;
        server_name your_server_domain_or_ip;
    
        location = /favicon.ico { access_log off; log_not_found off; }
        location /static/ {
            root /opt/wireguard_vpn;
        }
    
        location / {
            include proxy_params;
            proxy_pass http://unix:/opt/wireguard_vpn/wireguard_vpn.sock;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }

    # Enable the site
    sudo ln -s /etc/nginx/sites-available/wireguard_vpn /etc/nginx/sites-enabled/
    sudo nginx -t
    sudo systemctl restart nginx

### 7\. Set Up HTTPS (Recommended)

    # Install Certbot
    sudo apt install -y certbot python3-certbot-nginx
    
    # Obtain SSL certificate
    sudo certbot --nginx -d your_server_domain

### 8\. Set Up Server Configuration Update Cron Job

This cron job will update the WireGuard server configuration every 5 minutes:

    # Create the update script
    sudo nano /opt/wireguard_vpn/update_server.py

Add your server update script content to this file, then:

    # Make the script executable
    sudo chmod +x /opt/wireguard_vpn/update_server.py
    
    # Add the cron job
    (crontab -l 2>/dev/null; echo "*/5 * * * * /opt/wireguard_vpn/venv/bin/python /opt/wireguard_vpn/update_server.py >> /var/log/wireguard_update.log 2>&1 && sudo systemctl restart wg-quick@wg0") | crontab -
    
    # Create log file with proper permissions
    sudo touch /var/log/wireguard_update.log
    sudo chown $USER:$USER /var/log/wireguard_update.log

Usage
-----

1.  Access your VPN management system at `https://your_server_domain`
2.  Register a new user account (limited to one per IP address)
3.  Log in to access your dashboard
4.  Download your WireGuard configuration file
5.  Import the configuration into your WireGuard client

Troubleshooting
---------------

If you encounter a 502 Bad Gateway error:

    # Check Nginx error logs
    sudo tail -f /var/log/nginx/error.log
    
    # Check application logs
    sudo tail -f /opt/wireguard_vpn/vpn_service.log
    
    # Restart services
    sudo systemctl restart wireguard_vpn
    sudo systemctl restart nginx

Security Considerations
-----------------------

*   Keep your server updated regularly
*   Monitor logs for suspicious activity
*   Consider implementing additional security measures like fail2ban
*   Regularly back up your database and configuration

Support the Project
-------------------

If you find this project helpful, consider supporting the development:

[![Buy Me A Coffee](https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png)](https://www.buymeacoffee.com/asabizanjo)

Your support helps maintain this project and develop new features!

License
-------

This project is licensed under the GNU General Public License v3.0 (GPLv3) - see the [GNU GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html) for details.

The GNU GPLv3 is a free, copyleft license for software that guarantees end users the freedom to run, study, share, and modify the software.
