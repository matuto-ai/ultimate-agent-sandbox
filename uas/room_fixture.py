"""Composed Room launch boundary in the existing disposable guest fixture.

The trusted harness supplies owned listeners, never flags that claim successful
observations. This is not an installation interface or a production launcher.
The existing Supervisor remains the sole lifecycle/reconciliation owner.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import socket
import stat

from .guest_fixture import (BLOCK_KIB, INODES, WORKSTATION_HOST_UID,
                            GuestBoundaryBackend, command, guard)
from .kernel_origin import OriginDenied, OriginUnavailable, enable, probe
from .lifecycle import FixtureSpec, LifecycleError
from .workstation_exec import EndpointLease, ExecUnavailable

ENDPOINT_ROOT = Path('/run/uas-room-endpoints')
ENDPOINT_DESTINATIONS = {'hub': '/uas/peer', 'git': '/uas/git', 'forge': '/uas/forge'}
SUPERVISOR_UID = 165533
EGRESS_PROFILE = {'profile': 'room-launch-ipv4-v1', 'interface': 'uas-egress',
                  'mac': '52:54:00:62:00:01', 'address': '10.0.2.15/24', 'gateway': '10.0.2.2'}


@dataclass(frozen=True)
class RoomFixtureLimits:
    """Explicit bounded fixture selection, immutable for one Room instance."""
    memory_bytes: int = 64 * 1024 * 1024
    nano_cpus: int = 500_000_000
    pids: int = 32
    disk_bytes: int = BLOCK_KIB * 1024
    inodes: int = INODES
    log_bytes: int = 1024 * 1024

    def __post_init__(self):
        bounds = {'memory_bytes': (6 * 1024 * 1024, 2 * 1024**3),
                  'nano_cpus': (1_000_000, 2_000_000_000), 'pids': (2, 256),
                  'disk_bytes': (8 * 1024**2, 256 * 1024**2),
                  'inodes': (128, 8192), 'log_bytes': (4096, 16 * 1024**2)}
        if (any(type(getattr(self, key)) is not int or not low <= getattr(self, key) <= high
                for key, (low, high) in bounds.items())
                or self.disk_bytes % 1024 or self.log_bytes > self.disk_bytes):
            raise LifecycleError('ROOM_FIXTURE_INVALID_LIMITS')


class RoomEndpoint:
    """An already bound, owned narrow endpoint; no creation or policy repair.

    The service owner retains the listener lifetime. Holding this object grants
    no Participant authority and does not substitute for Broker authentication.
    The exact stock-policy connection checks still run in the guest scenario.
    """
    def __init__(self, room, kind, listeners, leases):
        if (room not in ('alpha', 'beta') or kind not in ENDPOINT_DESTINATIONS
                or type(listeners) is not tuple or any(type(listener) is not socket.socket for listener in listeners)
                or type(leases) is not tuple or not leases or len(leases) != len(listeners)
                or len(leases) > 2 or any(type(lease) is not EndpointLease for lease in leases)):
            raise LifecycleError('ROOM_FIXTURE_ENDPOINT_REQUIRED')
        self.room, self.kind, self.listeners, self.leases = room, kind, listeners, leases
        self.parent = ENDPOINT_ROOT / room / kind
        self.require()

    def require(self):
        for listener, lease in zip(self.listeners, self.leases):
            if (listener.family != socket.AF_UNIX
                    or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET
                    or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                    or listener.getsockname() != str(lease.path)):
                raise LifecycleError('ROOM_FIXTURE_LISTENER_DRIFT')
        for path, mode in ((ENDPOINT_ROOT, 0o755), (self.parent.parent, 0o711)):
            node = path.lstat()
            if (not stat.S_ISDIR(node.st_mode) or node.st_uid != 0 or node.st_gid != 0
                    or stat.S_IMODE(node.st_mode) != mode):
                raise LifecycleError('ROOM_FIXTURE_ENDPOINT_ANCESTRY')
        from .guest_fixture import ROOMS
        expected_label = ('system_u:object_r:container_file_t:' + ROOMS[self.room][3]).encode()
        expected_socket_label = ('system_u:system_r:container_t:' + ROOMS[self.room][3]).encode()
        for listener in self.listeners:
            # sockfs exposes the retained listener's SID, not its pathname or
            # an accepted child whose MLS range may follow the connecting peer.
            if os.getxattr(listener.fileno(), 'security.selinux').removesuffix(b'\0') != expected_socket_label:
                raise LifecycleError('ROOM_FIXTURE_LISTENER_LABEL')
        names = set()
        for lease in self.leases:
            if (lease.path.parent != self.parent or lease.owner != SUPERVISOR_UID
                    or lease.group != WORKSTATION_HOST_UID or lease.path.name in names):
                raise LifecycleError('ROOM_FIXTURE_ENDPOINT_SCOPE')
            names.add(lease.path.name)
            lease.require()
            for path in (self.parent, lease.path):
                if os.getxattr(path, 'security.selinux', follow_symlinks=False).rstrip(b'\0') != expected_label:
                    raise LifecycleError('ROOM_FIXTURE_ENDPOINT_LABEL')
        # An endpoint directory is not an arbitrary shared host directory.
        if {entry.name for entry in self.parent.iterdir()} != names:
            raise LifecycleError('ROOM_FIXTURE_ENDPOINT_CONTENTS')
        for listener in self.listeners:
            enable(listener)  # Mandatory kernel per-message credentials/pidfd.

    def document(self):
        return {'kind': self.kind, 'source': str(self.parent),
                'target': ENDPOINT_DESTINATIONS[self.kind],
                'objects': [list(lease.expected) for lease in self.leases]}


class RoomLaunchFixtureBackend(GuestBoundaryBackend):
    """Compose the existing real launch checks instead of approving receipts.

    The selected endpoint set is explicit and nonempty. Every used service must
    supply an actual RoomEndpoint; absent/unqualified services cannot be enabled
    by this backend. Participant startup remains after this admission.
    """
    def __init__(self, nonce, room, *, limits, endpoints):
        super().__init__(nonce, room)
        if (type(limits) is not RoomFixtureLimits or type(endpoints) is not tuple or not endpoints
                or len(endpoints) > 3 or any(type(item) is not RoomEndpoint or item.room != room for item in endpoints)
                or len({item.kind for item in endpoints}) != len(endpoints)):
            raise LifecycleError('ROOM_FIXTURE_PROFILE_REQUIRED')
        self.limits = limits
        self.endpoints = tuple(sorted(endpoints, key=lambda item: item.kind))
        profile = {'version': 1, 'room': room, 'limits': asdict(limits),
                   'endpoints': [item.document() for item in self.endpoints],
                   'userns_base': 100000, 'level': self.level, 'egress': EGRESS_PROFILE}
        encoded = json.dumps(profile, sort_keys=True, separators=(',', ':')).encode()
        self.profile_digest = 'sha256:' + hashlib.sha256(encoded).hexdigest()

    def fixture_spec(self, image_id):
        return FixtureSpec(self.room, self.room,
            tuple(str(self.root / name) for name in ('repository', 'workspace', 'checkouts', 'references')),
            image_id, self.profile_digest, self.profile_digest)

    def _profile(self, state):
        if (state['room_id'] != self.room or state['spec']['profile_digest'] != self.profile_digest
                or state['spec']['config_digest'] != self.profile_digest):
            raise LifecycleError('ROOM_FIXTURE_PROFILE_DRIFT')

    def _resource_limits(self, state):
        self._profile(state)
        return {'Memory': self.limits.memory_bytes, 'MemorySwap': self.limits.memory_bytes,
                'NanoCpus': self.limits.nano_cpus, 'PidsLimit': self.limits.pids}

    def _log_config(self, state):
        self._profile(state)
        return {'Type': 'local', 'Config': {'max-size': str(self.limits.log_bytes),
                'max-file': '1', 'compress': 'false'}}

    def _quota_limits(self):
        return self.limits.disk_bytes // 1024, self.limits.inodes

    def _endpoint_mounts(self, state):
        self._profile(state)
        for endpoint in self.endpoints:
            endpoint.require()
        return tuple((ENDPOINT_DESTINATIONS[item.kind], str(item.parent)) for item in self.endpoints)

    def _egress(self):
        """Reobserve the fixed boot-selected NIC, not a caller readiness flag.

        The rootfs guard checked the whole pre-Docker interface set. Existing
        GuestBoundaryBackend separately admits every owned Room bridge/filter;
        these checks pin the sole selected external NIC and default route.
        """
        marker = Path('/run/uas-room-network-profile')
        node = marker.lstat()
        self._require(stat.S_ISREG(node.st_mode) and node.st_uid == 0 and node.st_nlink == 1
                      and stat.S_IMODE(node.st_mode) == 0o600 and node.st_size <= 1024,
                      'ROOM_NETWORK_PROFILE')
        expected = {'version': 1, 'nonce': self.nonce, **EGRESS_PROFILE}
        self._require(json.loads(marker.read_text()) == expected, 'ROOM_NETWORK_PROFILE')
        interface = EGRESS_PROFILE['interface']
        self._require(Path('/sys/class/net/' + interface + '/address').read_text().strip()
                      == EGRESS_PROFILE['mac'], 'ROOM_NETWORK_MAC')
        def observe(*args):
            raw = command('ip', '-j', *args)
            self._require(len(raw) <= 8192, 'ROOM_NETWORK_OBSERVATION')
            return json.loads(raw)
        # ip -4 address omits the link-layer MAC. Keep a separate exact link
        # observation instead of manufacturing that field in address fixtures.
        links = observe('link', 'show', 'dev', interface)
        self._require(type(links) is list and len(links) == 1 and type(links[0]) is dict
                      and links[0].get('ifname') == interface
                      and links[0].get('address') == EGRESS_PROFILE['mac'], 'ROOM_NETWORK_INTERFACE')
        addresses = observe('-4', 'address', 'show', 'dev', interface)
        self._require(type(addresses) is list and len(addresses) == 1
                      and type(addresses[0]) is dict
                      and addresses[0].get('ifname') == interface, 'ROOM_NETWORK_INTERFACE')
        ipv4 = addresses[0].get('addr_info')
        self._require(type(ipv4) is list and len(ipv4) == 1 and ipv4[0].get('family') == 'inet'
                      and ipv4[0].get('local') == '10.0.2.15' and ipv4[0].get('prefixlen') == 24,
                      'ROOM_NETWORK_ADDRESS')
        routes = observe('-4', 'route', 'show', 'default')
        self._require(type(routes) is list and len(routes) == 1
                      and routes[0].get('dev') == interface
                      and routes[0].get('gateway') == EGRESS_PROFILE['gateway'], 'ROOM_NETWORK_ROUTE')
        self._require(observe('-6', 'route', 'show', 'default') == [], 'ROOM_NETWORK_IPV6')

    def _preflight(self, state):
        self._profile(state)
        guard(self.nonce)
        try:
            self._egress()
        except (OSError, ValueError, TypeError, KeyError) as error:
            raise LifecycleError('ROOM_FIXTURE_NETWORK_UNAVAILABLE') from error
        try:
            probe()  # Absence is a launch failure, never a configurable fallback.
            self._endpoint_mounts(state)
        except (OriginDenied, OriginUnavailable, ExecUnavailable, OSError) as error:
            raise LifecycleError('ROOM_FIXTURE_ENDPOINT_UNAVAILABLE') from error

    def admit(self, state):
        self._preflight(state)
        return super().admit(state)

    def create(self, state, kind):
        self._preflight(state)
        return super().create(state, kind)
