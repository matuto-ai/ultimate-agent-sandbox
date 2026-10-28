"""Supervisor-owned host Git slots; not a Workstation mount/security boundary.

Only trusted supervisor calls select Run/Participant bindings. Host Project paths
must not be mutated concurrently by an adversarial host actor. Git observations
are not filesystem leases; production mount/process qualification remains #62.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import math
import time
import os
from pathlib import Path
import re
import subprocess
import uuid

from .config import load
from .checkout_scope import valid_writer_scope
from .lifecycle import LifecycleError, _canonical, _path, _unique_object
from .manager_owner import (REVISION_FIELDS, CHECKOUT_OBSERVATION_FIELDS, advance_revision,
                            checkout_observations, validate_revision, validate_checkout_observations)


MAX_SLOTS = 1000
MAX_STORE_BYTES = 1_048_576


def _identifier(value):
    return type(value) is str and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}", value) is not None


def _identity(path):
    path = _path(path)  # Reject symlink metadata and ancestor components.
    info = path.stat()
    return [info.st_dev, info.st_ino]


def _identity_shape(value):
    return type(value) is list and len(value) == 2 and all(type(n) is int and n >= 0 for n in value)


class CheckoutAllocator:
    def __init__(self, supervisor, source, *, writer_quiescent=None, writer_guard=None, deadline=None,
                 manifest_reader_gid=None, git_identity=None):
        # Non-Docker consumers (including inert artifact fixtures) must not
        # import Engine/launch code just to inspect or allocate host Git slots.
        guard_factory = getattr(supervisor.backend, 'checkout_writer_guard', None)
        if guard_factory is not None:
            if writer_quiescent is not None:
                raise LifecycleError('INVALID_WRITER_GUARD')
            if writer_guard is None:
                writer_guard = guard_factory(supervisor)
        if deadline is not None and (type(deadline) not in (int, float) or not math.isfinite(deadline)):
            raise LifecycleError('INVALID_DEADLINE')
        if manifest_reader_gid is not None and (type(manifest_reader_gid) is not int
                or not 0 < manifest_reader_gid < 2**31 or os.geteuid() != 0):
            raise LifecycleError('INVALID_MANIFEST_READER')
        if git_identity is not None and (type(git_identity) is not tuple or len(git_identity) != 2
                or any(type(n) is not int or not 0 < n < 2**31 for n in git_identity)
                or os.geteuid() != 0):
            raise LifecycleError('INVALID_GIT_IDENTITY')
        self.manifest_reader_gid, self.git_identity = manifest_reader_gid, git_identity
        self.deadline = deadline
        self.supervisor = supervisor
        self.writer_quiescent = writer_quiescent
        self.writer_guard = writer_guard
        if writer_guard is not None:
            from .checkout_writers import DockerCheckoutWriters
            if (type(writer_guard) is not DockerCheckoutWriters or
                    writer_guard.supervisor is not supervisor or writer_quiescent is not None):
                raise LifecycleError('INVALID_WRITER_GUARD')
        config = load(source)
        self.room = next((r for r in config['rooms'] if r['id'] == supervisor.room_id), None)
        if self.room is None:
            raise LifecycleError('ROOM_MISMATCH')
        self.repo = _path(self.room['project']['roots']['repo'])
        self.root = _path(self.room['project']['roots']['checkouts'])
        if writer_guard is not None and writer_guard.supervisor.backend.writable != {str(self.repo), str(self.root)}:
            raise LifecycleError('PROJECT_BINDING_CONFLICT')
        if self.room['state_root'] != str(supervisor.directory):
            raise LifecycleError('ROOM_MISMATCH')
        self.manifest = supervisor.directory / 'checkouts.json'

    def _remaining(self):
        if getattr(self, 'deadline', None) is None:
            return 20
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            # Never undo a creating intent or guess whether a Git effect ran.
            raise LifecycleError('CHECKOUT_DEADLINE_RECONCILE')
        return min(20, remaining)

    def _git(self, path, *args, allowed=(0,)):
        # No ambient Git credentials/config/environment, hooks, helper/network
        # transport, pager, fsmonitor or recursive submodule commands.
        env = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LC_ALL': 'C',
               'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
               'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0'}
        options = {}
        if getattr(self, 'git_identity', None) is not None:
            # Root only owns the control manifest. Git runs as the fixed owner
            # of prepared native Project roots, with no supplementary groups.
            for root in (self.repo, self.root):
                info = _path(root).stat()
                if (info.st_uid, info.st_gid) != self.git_identity:
                    raise LifecycleError('GIT_OWNER_CHANGED')
            options = {'user': self.git_identity[0], 'group': self.git_identity[1],
                       'extra_groups': [], 'stdin': subprocess.DEVNULL, 'close_fds': True}
        try:
            result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null',
                '-c', 'core.fsmonitor=false', '-c', 'protocol.allow=never',
                '-c', 'submodule.recurse=false', '-C', str(path), *args],
                env=env, capture_output=True, timeout=self._remaining(), **options)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise LifecycleError('GIT_OBSERVATION_UNKNOWN') from error
        if result.returncode not in allowed:
            raise LifecycleError('GIT_OBSERVATION_UNKNOWN')
        try:
            return result.stdout.decode('utf-8', errors='strict').rstrip('\n')
        except UnicodeError as error:
            raise LifecycleError('GIT_OBSERVATION_UNKNOWN') from error

    @contextmanager
    def _locked(self, action):
        lock = (self.supervisor._locked() if getattr(self, 'deadline', None) is None
                else self.supervisor._locked(deadline=self.deadline))
        with lock:
            self._remaining()
            lifecycle = self.supervisor._read()
            if not lifecycle or lifecycle['phase'] in ('destroying', 'destroy_failed', 'destroyed'):
                raise LifecycleError('ROOM_UNAVAILABLE')
            self.supervisor._allowed('checkout.' + action, lifecycle)
            if action == 'allocate' and lifecycle['phase'] != 'running':
                raise LifecycleError('ROOM_NOT_RUNNING')
            if action == 'reserve' and lifecycle['phase'] != 'stopped':
                raise LifecycleError('ROOM_NOT_STOPPED')
            if (lifecycle['spec']['project_id'] != self.room['project']['id'] or
                not {str(self.repo), str(self.root)} <= set(lifecycle['spec']['project_paths'])):
                raise LifecycleError('PROJECT_BINDING_CONFLICT')
            _path(self.repo); _path(self.root)
            if not self.repo.is_dir() or not self.root.is_dir():
                raise LifecycleError('PROJECT_PATH_MISSING')
            _path(self.repo / '.git')
            common = self._git(self.repo, 'rev-parse', '--path-format=absolute', '--git-common-dir')
            _path(common)
            if self._git(self.repo, 'rev-parse', '--show-toplevel') != str(self.repo):
                raise LifecycleError('PROJECT_BINDING_CONFLICT')
            # Worktree checkout can invoke repo-configured filter processes.
            # They are deliberately unsupported by this account-free host seam.
            filters = self._git(self.repo, 'config', '--get-regexp', r'^filter\.', allowed=(0, 1))
            if filters:
                raise LifecycleError('UNSUPPORTED_GIT_FILTER')
            state = self._read(lifecycle['instance_id'], common)
            yield state

    def _read(self, instance, common):
        binding = {'version': 1, 'room_id': self.room['id'], 'instance_id': instance,
                   'project_id': self.room['project']['id'], 'repo': str(self.repo),
                   'root': str(self.root), 'common': common,
                   'filesystem': {'repo': _identity(self.repo), 'root': _identity(self.root),
                                  'common': _identity(common)}}
        if not self.manifest.exists():
            return {**binding, 'slots': {}}
        try:
            if self.manifest.is_symlink() or self.manifest.stat().st_size > MAX_STORE_BYTES:
                raise ValueError()
            state = json.loads(self.manifest.read_text(), object_pairs_hook=_unique_object)
            required = set(binding) | {'slots'}
            if (type(state) is not dict or not required <= state.keys()
                    or set(state) - required - REVISION_FIELDS - CHECKOUT_OBSERVATION_FIELDS):
                raise ValueError()
            validate_revision(state)
            if any(_canonical(state[k]) != _canonical(v) for k, v in binding.items()):
                raise ValueError()
            if type(state['slots']) is not dict or len(state['slots']) > MAX_SLOTS:
                raise ValueError()
            for key, slot in state['slots'].items():
                if not (key == 'primary' or re.fullmatch(r'[0-9a-f]{32}', key)):
                    raise ValueError()
                fields = {'path', 'branch', 'base', 'run', 'participant', 'active', 'phase', 'identity'}
                if type(slot) is not dict or set(slot) not in (fields, fields | {'writer_scope'}):
                    raise ValueError()
                if 'writer_scope' in slot:
                    if not valid_writer_scope(slot['writer_scope'], instance):
                        raise ValueError()
                expected = str(self.repo if key == 'primary' else self.root / key)
                if slot['path'] != expected or not all(_identifier(slot[k]) for k in ('run', 'participant')):
                    raise ValueError()
                if type(slot['active']) is not bool or slot['phase'] not in ('creating', 'ready', 'removing', 'removed'):
                    raise ValueError()
                if type(slot['base']) is not str or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', slot['base']):
                    raise ValueError()
                if type(slot['branch']) is not str or not slot['branch'].startswith('refs/heads/'):
                    raise ValueError()
                if key != 'primary' and slot['branch'] != 'refs/heads/uas-slot/' + key:
                    raise ValueError()
                identity = slot['identity']
                if identity is None:
                    if slot['phase'] != 'creating': raise ValueError()
                elif (type(identity) is not dict or set(identity) != {'directory', 'git_metadata'} or
                      not all(_identity_shape(v) for v in identity.values())):
                    raise ValueError()
                if slot['phase'] in ('removing', 'removed') and slot['active']:
                    raise ValueError()
            validate_checkout_observations(state)
            return state
        except (ValueError, TypeError, KeyError, OSError, RecursionError) as error:
            raise LifecycleError('INVALID_CHECKOUT_STORE') from error

    def _save(self, state, *, working_tree_observations=None):
        self._remaining()
        # Every ordinary owner save invalidates retained probes before changing
        # slot bindings/phase. Only the explicit trusted observer supplies these.
        state.pop('working_tree_observations', None)
        if working_tree_observations is not None:
            state['working_tree_observations'] = working_tree_observations
        try:
            advance_revision(state)
            validate_checkout_observations(state)
        except ValueError as error:
            raise LifecycleError('INVALID_CHECKOUT_STORE') from error
        encoded = _canonical(state).encode('utf-8')
        # Reserve the eventual observed device/inode fields before Git add.
        # A valid creating intent must also fit its ready/recovery record.
        capacity_state = {**state, 'slots': {key: {**slot,
            'identity': slot['identity'] if slot['identity'] is not None else
                {'directory': [2**64 - 1] * 2, 'git_metadata': [2**64 - 1] * 2}}
            for key, slot in state['slots'].items()}}
        if len(state['slots']) > MAX_SLOTS or len(_canonical(capacity_state).encode('utf-8')) > MAX_STORE_BYTES:
            raise LifecycleError('CHECKOUT_CAPACITY_EXCEEDED')
        temporary = self.manifest.parent / ('.checkouts-' + uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(descriptor, 'wb') as output:
                if getattr(self, 'manifest_reader_gid', None) is not None:
                    # Fixed trusted host gets read only; atomic replacements
                    # preserve that policy without a writable control directory.
                    os.fchown(output.fileno(), 0, self.manifest_reader_gid)
                    os.fchmod(output.fileno(), 0o640)
                output.write(encoded); output.flush(); os.fsync(output.fileno())
            self._remaining()
            os.replace(temporary, self.manifest)
            self.supervisor._sync_directory(self.manifest.parent)
        finally:
            temporary.unlink(missing_ok=True)

    def _registered(self):
        records = {}
        for block in self._git(self.repo, 'worktree', 'list', '--porcelain', '-z').split('\0\0'):
            fields = {}
            for field in block.split('\0'):
                if field:
                    name, _, value = field.partition(' '); fields[name] = value
            if 'worktree' in fields:
                records[fields['worktree']] = fields
        return records

    def _observe(self, state, key):
        slot = state['slots'][key]
        result = {'slot': key, **slot, 'observed_dirty': None, 'disposition': 'retained', 'reason': 'UNVERIFIABLE'}
        try:
            path = _path(slot['path'])
            record = self._registered().get(str(path))
            if not os.path.lexists(path) and record is None:
                return {**result, 'reason': 'ABSENT'}
            if not path.is_dir() or record is None or 'locked' in record or 'prunable' in record:
                return result
            observed_identity = {'directory': _identity(path), 'git_metadata': _identity(path / '.git')}
            if slot['identity'] is not None and observed_identity != slot['identity']:
                return {**result, 'reason': 'FILESYSTEM_IDENTITY_MISMATCH'}
            if (record.get('branch') != slot['branch'] or
                self._git(path, 'rev-parse', '--show-toplevel') != str(path) or
                self._git(path, 'rev-parse', '--path-format=absolute', '--git-common-dir') != state['common']):
                return {**result, 'reason': 'METADATA_MISMATCH'}
            # Includes ignored data; never --force, git clean, or recursive rm.
            dirty = bool(self._git(path, 'status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignored=matching'))
            head = self._git(path, 'rev-parse', 'HEAD')
            result.update(observed_dirty=dirty, observed_head=head)
            if dirty:
                return {**result, 'reason': 'DIRTY_OR_UNTRACKED_OR_IGNORED'}
            if slot['active']:
                return {**result, 'reason': 'ACTIVE'}
            # Keep unmerged commits even though the branch itself also survives.
            unmerged = self._git(self.repo, 'rev-list', '--max-count=1', head, '--not', 'HEAD')
            if unmerged:
                return {**result, 'reason': 'UNMERGED'}
            return {**result, 'disposition': 'clean', 'reason': 'RECONCILED'}
        except (LifecycleError, UnicodeError, OSError):
            return result

    def status(self):
        with self._locked('status') as state:
            return [self._observe(state, key) for key in state['slots']]

    def refresh_observation(self, slot):
        """Trusted host probe of ONE owned slot; never called by Manager reads.

        Reuses existing Git admission/observation limits and Room authorization.
        Retained results are historical observations, not current leases or an
        authorization to reclaim a checkout. No file names or Git output escape.
        """
        with self._locked('status') as state:
            if type(slot) is not str or slot not in state['slots']:
                raise LifecycleError('CHECKOUT_SLOT_NOT_OWNED')
            observed = self._observe(state, slot)
            rows = dict(state.get('working_tree_observations', {}))
            dirty = (observed['observed_dirty'] if observed['reason'] in
                     {'DIRTY_OR_UNTRACKED_OR_IGNORED', 'ACTIVE', 'UNMERGED', 'RECONCILED'} else None)
            rows[slot] = {'observed_dirty': dirty,
                          'observed_at': datetime.now(timezone.utc).isoformat(),
                          'reason': observed['reason']}
            self._save(state, working_tree_observations=rows)
            return rows[slot].copy()

    def manager_observations(self):
        """Passive slot intent, NOT working-tree cleanliness or Git existence.

        Do not enter _locked(), which deliberately runs Git admission probes.
        Validate the exact Room/Project/instance manifest under its owner lock.
        """
        with self.supervisor._locked():
            lifecycle = self.supervisor._read()
            if lifecycle is None or lifecycle['spec']['project_id'] != self.room['project']['id']:
                raise LifecycleError('ROOM_UNAVAILABLE')
            if not self.manifest.exists():
                return checkout_observations({'slots': {}})
            try:
                if self.manifest.is_symlink() or self.manifest.stat().st_size > MAX_STORE_BYTES:
                    raise ValueError()
                stored = json.loads(self.manifest.read_text(), object_pairs_hook=_unique_object)
                common = _path(stored['common'])
                state = self._read(lifecycle['instance_id'], str(common))
            except (ValueError, KeyError, TypeError, OSError) as error:
                raise LifecycleError('INVALID_CHECKOUT_STORE') from error
            return checkout_observations(state)

    def _quiescent(self, slot):
        # Called only under the lifecycle lock, which also serializes Start and
        # reservations. Revoked authority/parent exit is not writer quiescence.
        try:
            if self.writer_guard is not None:
                return self.writer_guard.quiescent(self.supervisor._read(), slot.get('writer_scope')) is True
            # A scope captured by the concrete guard can never be downgraded to
            # an empty-set/custom callback after a controller restart.
            return ('writer_scope' not in slot and self.writer_quiescent is not None
                    and self.writer_quiescent(slot['run'], slot['participant']) is True)
        except Exception:
            return False

    @staticmethod
    def _retained_predecessor(state, run, participant, predecessor):
        # Trusted root-owned admission policy, never a participant-supplied path.
        if (type(predecessor) is not tuple or len(predecessor) != 2
                or not _identifier(predecessor[0]) or predecessor[0] == run
                or predecessor[1] != participant):
            raise LifecycleError('CHECKOUT_PREDECESSOR_CHANGED')
        slots = [slot for slot in state['slots'].values() if slot['run'] == predecessor[0]]
        if (len(slots) != 1 or slots[0]['participant'] != participant
                or slots[0]['active'] is not True or slots[0]['phase'] != 'ready'):
            raise LifecycleError('CHECKOUT_PREDECESSOR_CHANGED')

    def allocate(self, run, participant, *, authorize=None, retained_predecessor=None):
        return self._allocate(run, participant, 'allocate', authorize=authorize,
                              retained_predecessor=retained_predecessor)

    def reserve(self, run, participant):
        """Reserve while stopped; Start never reuses a released slot implicitly.

        The whole-Workstation guard deliberately refuses reuse while *any*
        current Workstation writer can touch shared Project paths. A trusted
        supervisor stops, reserves, then starts; no agent badge grants this API.
        """
        return self._allocate(run, participant, 'reserve')

    def _allocate(self, run, participant, action, *, authorize=None, retained_predecessor=None):
        if not _identifier(run) or not _identifier(participant):
            raise LifecycleError('INVALID_CHECKOUT_BINDING')
        with self._locked(action) as state:
            # A trusted Run owner may withdraw while Git work is waiting for
            # this lock. Check inside the same lock, before intent or effects.
            if authorize is not None and authorize() is not True:
                raise LifecycleError('ADMISSION_REVOKED')
            if retained_predecessor is not None:
                self._retained_predecessor(state, run, participant, retained_predecessor)
            for key, slot in state['slots'].items():
                if slot['active'] and slot['run'] == run:
                    if slot['participant'] != participant:
                        raise LifecycleError('CHECKOUT_BINDING_CONFLICT')
                    if self.writer_guard is not None:
                        current = self.writer_guard.capture(self.supervisor._read())
                        prior = slot.get('writer_scope')
                        if (prior is None or any(current[field] != prior[field]
                                                for field in ('kind', 'instance', 'container'))):
                            raise LifecycleError('WRITER_OBSERVATION_UNKNOWN')
                    if slot['phase'] == 'creating':
                        self._recover_creation(state, key)
                    observed = self._observe(state, key)
                    if observed['reason'] not in ('ACTIVE', 'DIRTY_OR_UNTRACKED_OR_IGNORED'):
                        raise LifecycleError('CHECKOUT_UNVERIFIABLE')
                    self._remaining()
                    return observed
            if any(s['phase'] in ('creating', 'removing') for s in state['slots'].values()):
                raise LifecycleError('CHECKOUT_RECONCILIATION_REQUIRED')
            concurrent = any(s['active'] for s in state['slots'].values())
            key = uuid.uuid4().hex if concurrent else 'primary'
            if not concurrent and 'primary' in state['slots']:
                if not self._quiescent(state['slots']['primary']):
                    raise LifecycleError('WRITER_NOT_QUIESCENT')
                # Observe AFTER the writer fence: a final write made while
                # stopping must not be missed by an earlier clean snapshot.
                if self._observe(state, 'primary')['disposition'] != 'clean':
                    raise LifecycleError('PRIMARY_NOT_RECONCILED')
            branch = 'refs/heads/uas-slot/' + key if concurrent else self._git(self.repo, 'symbolic-ref', 'HEAD')
            base = self._git(self.repo, 'rev-parse', 'HEAD')
            path = self.root / key if concurrent else self.repo
            if concurrent and os.path.lexists(path):
                raise LifecycleError('CHECKOUT_OWNERSHIP_CONFLICT')
            if not concurrent and self._git(self.repo, 'status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignored=matching'):
                raise LifecycleError('PRIMARY_NOT_CLEAN')
            slot = dict(path=str(path), branch=branch, base=base, run=run, participant=participant,
                        active=True, phase='creating' if concurrent else 'ready',
                        identity=None if concurrent else {'directory': _identity(path), 'git_metadata': _identity(path / '.git')})
            if self.writer_guard is not None:
                slot['writer_scope'] = self.writer_guard.capture(self.supervisor._read())
            state['slots'][key] = slot
            self._save(state)  # Intent precedes Git effects.
            if concurrent:
                self._recover_creation(state, key)
            observed = self._observe(state, key)
            self._remaining()
            return observed

    def _recover_creation(self, state, key):
        slot = state['slots'][key]
        record = self._registered().get(slot['path'])
        if not os.path.lexists(slot['path']) and record is None:
            # If Git created only the ref before interruption, do not guess or
            # reset it. Preserve it for explicit repair instead of duplicating.
            refs = self._git(self.repo, 'for-each-ref', '--format=%(refname)', slot['branch'])
            if refs:
                raise LifecycleError('CHECKOUT_RECONCILIATION_REQUIRED')
            self._git(self.repo, 'worktree', 'add', '-b', slot['branch'][11:], '--', slot['path'], slot['base'])
        observed = self._observe(state, key)
        if observed['reason'] != 'ACTIVE' or observed.get('observed_head') != slot['base']:
            raise LifecycleError('CHECKOUT_RECONCILIATION_REQUIRED')
        slot['identity'] = {'directory': _identity(slot['path']), 'git_metadata': _identity(Path(slot['path']) / '.git')}
        slot['phase'] = 'ready'; self._save(state)

    def release(self, run, participant, *, authorize=None):
        with self._locked('release') as state:
            if authorize is not None and authorize() is not True:
                raise LifecycleError('ADMISSION_REVOKED')
            for key, slot in state['slots'].items():
                if slot['run'] == run and slot['phase'] != 'removed':
                    if slot['participant'] != participant:
                        raise LifecycleError('CHECKOUT_BINDING_CONFLICT')
                    if slot['phase'] != 'ready':
                        raise LifecycleError('CHECKOUT_RECONCILIATION_REQUIRED')
                    if not self._quiescent(slot):
                        raise LifecycleError('WRITER_NOT_QUIESCENT')
                    slot['active'] = False; self._save(state)
                    return self._observe(state, key)
            raise LifecycleError('UNKNOWN_CHECKOUT_BINDING')

    def reconcile(self):
        with self._locked('reconcile') as state:
            results = []
            for key, slot in state['slots'].items():
                observed = self._observe(state, key)
                if key == 'primary' or slot['active'] or slot['phase'] == 'removed':
                    results.append(observed); continue
                if not self._quiescent(slot):
                    results.append({**observed, 'disposition': 'retained', 'reason': 'WRITER_NOT_QUIESCENT'})
                    continue
                # Git's normal worktree remove may discard ignored files.
                # Recheck all retention/identity facts only after actual writers
                # are fenced; a pre-stop clean observation is insufficient.
                observed = self._observe(state, key)
                if slot['phase'] == 'removing' and observed['reason'] == 'ABSENT':
                    slot['phase'] = 'removed'; self._save(state)
                elif observed['disposition'] == 'clean':
                    slot['phase'] = 'removing'; self._save(state)
                    self._git(self.repo, 'worktree', 'remove', '--', slot['path'])
                    slot['phase'] = 'removed'; self._save(state)
                results.append({**observed, 'phase': slot['phase'],
                    'disposition': 'removed' if slot['phase'] == 'removed' else observed['disposition']})
            return results
