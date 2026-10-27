"""Fixed network-enabled disposable profile, separate from all no-NIC profiles.

Source contract only until its complete guest scenario is reviewed. No hot-add,
QMP, host forwarding, TAP, bridge helper, SSH or shared host path is introduced.
"""
import json
import os
from pathlib import Path
import re
import stat

PROFILE = 'room-launch-ipv4-v1'
MARKER = Path('/run/uas-room-network-profile')
MAC = '52:54:00:62:00:01'
INTERFACE = 'uas-egress'
ADDRESS = '10.0.2.15/24'
GATEWAY = '10.0.2.2'


def require(value, message):
    if not value: raise RuntimeError(message)


def network_config():
    return {'version': 2, 'ethernets': {INTERFACE: {'match': {'macaddress': MAC},
        'set-name': INTERFACE, 'dhcp4': False, 'dhcp6': False, 'accept-ra': False,
        'addresses': [ADDRESS], 'routes': [{'to': '0.0.0.0/0', 'via': GATEWAY}]}}}


def marker(nonce):
    require(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce), 'exact boot nonce required')
    return {'version': 1, 'profile': PROFILE, 'nonce': nonce,
            'interface': INTERFACE, 'mac': MAC, 'address': ADDRESS, 'gateway': GATEWAY}


def qemu_arguments(directory, overlay, seed_image, payload, quota):
    from run_boundary import arguments
    values = arguments(directory, overlay, seed_image, payload, quota)
    # Replace only the existing explicit no-NIC selection for THIS new profile.
    # Existing callers never invoke this entrypoint and remain unchanged.
    require(values.count('-nic') == 1 and values[values.index('-nic') + 1] == 'none',
            'fixed inherited QEMU boundary changed')
    position = values.index('-nic')
    values[position:position + 2] = ['-netdev', 'user,id=room-egress,ipv6=off,net=10.0.2.0/24,host=10.0.2.2',
                                    '-device', 'virtio-net-pci,netdev=room-egress,mac=' + MAC]
    return values


def guest_guard(nonce, *, run):
    """Observe this complete NIC contract from boot, before image assembly.

    The marker is an accidental-execution guard, not authentication. No caller
    boolean, old no-NIC receipt or later interface attachment is accepted.
    """
    require(os.geteuid() == 0, 'owned disposable guest root required')
    expected = marker(nonce)
    for path in (MARKER, Path('/run/uas-vm-fixture')):
        node = path.lstat()
        require(stat.S_ISREG(node.st_mode) and node.st_uid == 0 and node.st_nlink == 1
                and stat.S_IMODE(node.st_mode) == 0o600 and node.st_size <= 1024,
                'private fixed guest marker required')
    require(json.loads(MARKER.read_text()) == expected
            and Path('/run/uas-vm-fixture').read_text().strip() == nonce, 'wrong selected guest profile')
    interfaces = sorted(path.name for path in Path('/sys/class/net').iterdir())
    require(interfaces == ['lo', INTERFACE], 'unexpected network device in selected guest')
    require(Path('/sys/class/net/' + INTERFACE + '/address').read_text().strip() == MAC,
            'wrong selected NIC identity')
    # IPv4-only address output omits link-layer fields in iproute2. Observe
    # the selected link separately; do not treat an absent MAC as a match.
    raw = run('ip', '-j', 'link', 'show', 'dev', INTERFACE, timeout=3)
    require(len(raw) <= 8192, 'oversized link observation')
    links = json.loads(raw)
    require(type(links) is list and len(links) == 1 and type(links[0]) is dict
            and links[0].get('ifname') == INTERFACE
            and links[0].get('address') == MAC, 'wrong actual NIC')
    raw = run('ip', '-j', '-4', 'address', 'show', 'dev', INTERFACE, timeout=3)
    require(len(raw) <= 8192, 'oversized NIC observation')
    observed = json.loads(raw)
    require(type(observed) is list and len(observed) == 1 and type(observed[0]) is dict
            and observed[0].get('ifname') == INTERFACE, 'wrong IPv4 interface')
    addresses = observed[0].get('addr_info')
    require(type(addresses) is list and len(addresses) == 1 and addresses[0].get('family') == 'inet'
            and addresses[0].get('local') == ADDRESS.split('/')[0]
            and addresses[0].get('prefixlen') == 24, 'wrong actual IPv4 address')
    raw = run('ip', '-j', '-4', 'route', 'show', 'default', timeout=3)
    require(len(raw) <= 8192, 'oversized route observation')
    routes = json.loads(raw)
    require(type(routes) is list and len(routes) == 1 and routes[0].get('gateway') == GATEWAY
            and routes[0].get('dev') == INTERFACE, 'wrong actual egress route')
    raw = run('ip', '-j', '-6', 'route', 'show', 'default', timeout=3)
    require(len(raw) <= 8192 and json.loads(raw) == [], 'IPv6 route is not selected')
    return {'profile': PROFILE, 'interface': INTERFACE, 'mac': MAC,
            'address': ADDRESS, 'gateway': GATEWAY, 'ipv6_default_route': False}
