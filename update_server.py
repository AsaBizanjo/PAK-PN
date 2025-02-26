
import os
import subprocess
import django


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'wireguard_project.settings')
django.setup()

from wireguard_app.models import WireGuardConfig


clients = WireGuardConfig.objects.all()


with open('/etc/wireguard/wg0.conf', 'r') as f:
    config_lines = f.readlines()


interface_section = []
for line in config_lines:
    if line.strip() == '':
        continue
    if line.strip().startswith('[Peer]'):
        break
    interface_section.append(line)


new_config = ''.join(interface_section)


for client in clients:
    new_config += f"""
[Peer]
PublicKey = {client.public_key}
AllowedIPs = {client.ip_address}/32
"""


with open('/etc/wireguard/wg0.conf.new', 'w') as f:
    f.write(new_config)


subprocess.run(['wg', 'syncconf', 'wg0', '/etc/wireguard/wg0.conf.new'])
subprocess.run(['mv', '/etc/wireguard/wg0.conf.new', '/etc/wireguard/wg0.conf'])

print(f"Updated WireGuard configuration with {len(clients)} clients")
