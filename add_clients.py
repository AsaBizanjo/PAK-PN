
import os
import django
import subprocess


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'wireguard_project.settings')
os.chdir('/opt/wireguard_vpn')
django.setup()

from wireguard_app.models import WireGuardConfig


clients = WireGuardConfig.objects.all()
print(f"Found {len(clients)} clients in database")


with open('/etc/wireguard/wg0.conf', 'r') as f:
    config_lines = f.readlines()


interface_section = []
in_interface = False
for line in config_lines:
    if '[Interface]' in line:
        in_interface = True
    elif line.strip().startswith('[Peer]'):
        in_interface = False
        break
    
    if in_interface:
        interface_section.append(line)


new_config = ''.join(interface_section)


for client in clients:
    print(f"Adding client: {client.user.username} with IP {client.ip_address}")
    new_config += f"""
[Peer]
PublicKey = {client.public_key}
AllowedIPs = {client.ip_address}/32
"""


with open('/etc/wireguard/wg0.conf', 'w') as f:
    f.write(new_config)


subprocess.run(['systemctl', 'restart', 'wg-quick@wg0'])
print("WireGuard configuration updated and service restarted")
