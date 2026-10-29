"""Small append-only preparation receipts, not a host-action executor.

Persist an intent before each effect; a missing confirmation means unknown.
Reopening preserves that ambiguity. This owner never retries host effects.
"""
import json
import os
from pathlib import Path
import stat

from .local_host_profile import canonical, digest, require, HostProfileError


class HostReceiptUncertain(HostProfileError):
    def __init__(self):
        super().__init__('HOST_RECEIPT_UNCERTAIN')


class PreparationReceipt:
    def __init__(self, root, plan, *, owner_uid):
        # The apply owner creates this private directory. Opening receipts alone
        # cannot create host directories, confer root authority or adopt data.
        self.root = Path(root)
        self.plan = json.loads(canonical(plan))
        require(type(owner_uid) is int and owner_uid >= 0, 'HOST_RECEIPT_OWNER')
        require(type(plan) is dict and 'plan_id' in plan
                and digest({k:v for k,v in plan.items() if k != 'plan_id'}) == plan['plan_id'], 'HOST_RECEIPT_PLAN')
        self.owner_uid = owner_uid
        self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.poisoned = False
        try:
            info = os.fstat(self.fd)
            require(info.st_uid == owner_uid and stat.S_IMODE(info.st_mode) == 0o700, 'HOST_RECEIPT_DIRECTORY')
            self.identity = (info.st_dev, info.st_ino)
            self._append('plan.json', self.plan)
        except BaseException:
            os.close(self.fd)
            raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    def _guard(self):
        require(not self.poisoned and self.fd is not None, 'HOST_RECEIPT_UNAVAILABLE')
        info = self.root.lstat()
        require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == self.identity
                and info.st_uid == self.owner_uid and stat.S_IMODE(info.st_mode) == 0o700,
                'HOST_RECEIPT_DIRECTORY_CHANGED')

    def _read(self, name):
        self._guard()
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.fd)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == self.owner_uid
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                    and info.st_size <= 65536, 'HOST_RECEIPT_FILE')
            raw = os.read(fd, 65537)
            require(len(raw) <= 65536, 'HOST_RECEIPT_BOUND')
            value = json.loads(raw)
            require(canonical(value) == raw, 'HOST_RECEIPT_ENCODING')
            return value
        finally:
            os.close(fd)

    def _append(self, name, value):
        self._guard()
        raw = canonical(value)
        require(len(raw) <= 65536, 'HOST_RECEIPT_BOUND')
        current = self._read(name)
        if current is not None:
            require(current == value, 'HOST_RECEIPT_CONFLICT')
            return False
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=self.fd)
        except FileExistsError:
            current = self._read(name)
            require(current == value, 'HOST_RECEIPT_CONFLICT')
            return False
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(self.fd)
        except OSError:
            self.poisoned = True
            raise HostReceiptUncertain() from None
        return True

    def _step(self, index):
        require(type(index) is int and 0 <= index < len(self.plan['operations']), 'HOST_RECEIPT_STEP')
        return {'plan_id': self.plan['plan_id'], 'step': index,
                'operation': digest(self.plan['operations'][index])}

    def state(self, index):
        expected = self._step(index)
        intent = self._read(str(index) + '.intent.json')
        confirmed = self._read(str(index) + '.confirmed.json')
        if intent is None:
            require(confirmed is None, 'HOST_RECEIPT_ORPHAN')
            return {'state': 'not-started'}
        require(intent == expected, 'HOST_RECEIPT_CONFLICT')
        if confirmed is None:
            return {'state': 'unknown'}
        require(type(confirmed) is dict and set(confirmed) == {'intent', 'evidence'}
                and confirmed['intent'] == expected, 'HOST_RECEIPT_CONFIRMATION')
        self._evidence(confirmed['evidence'])
        return {'state': 'confirmed', 'evidence': confirmed['evidence']}

    def intent(self, index):
        expected = self._step(index)
        require(all(self.state(i)['state'] == 'confirmed' for i in range(index)), 'HOST_RECEIPT_PREVIOUS_UNKNOWN')
        # True authorizes the caller's first effect only. Existing intent means
        # reconcile, including when the earlier write's acknowledgement was lost.
        prior = self.state(index)
        if prior['state'] != 'not-started':
            return False
        return self._append(str(index) + '.intent.json', expected)

    @staticmethod
    def _evidence(value):
        import re
        require(type(value) is dict and set(value) == {'identity', 'observed_sha256'}
                and type(value['identity']) is list and len(value['identity']) == 2
                and all(type(x) is int and x >= 0 for x in value['identity'])
                and type(value['observed_sha256']) is str
                and re.fullmatch(r'[0-9a-f]{64}', value['observed_sha256']), 'HOST_RECEIPT_EVIDENCE')

    def confirm(self, index, evidence):
        self._evidence(evidence)
        expected = self._step(index)
        require(self._read(str(index) + '.intent.json') == expected, 'HOST_RECEIPT_INTENT_REQUIRED')
        return self._append(str(index) + '.confirmed.json', {'intent': expected, 'evidence': evidence})
