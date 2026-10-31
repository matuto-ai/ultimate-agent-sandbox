#!/usr/bin/env python3
"""Opt-in acceptance probe for an ALREADY prepared two-Room native installation.

Never provisions Docker, storage, identities, credentials, models, or policies.
Run only with the operator's separate approval on a disposable prepared host.
This is not the T42 model/target qualification or T41 VM isolation proof.
"""
import argparse
import calendar
from datetime import datetime
import hashlib
import json
import itertools
import os
from pathlib import Path
import select
import signal
import re
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
# Probe observation only, not a production deadline or performance guarantee.
# Ordinary two-Room composition: 2*(7 native Docker observations*20 + server6
# + child10 + 3 Hub Docker commands*20) + manager10 + Library joins(10+5)
# + existing120s attempt/flush/idle allowance122 + observation margin21 =600.
# Abnormal paths are not guaranteed to fit; timeout still means failed proof.
# Outer guest1200s/job1800s limits remain authoritative and unchanged.
HOST_SHUTDOWN_OBSERVATION_SECONDS = 600
sys.path.insert(0, str(ROOT))


def require(value, code):
    if not value:
        raise RuntimeError(code)


def candidate_identity(expected_commit, source_manifest=None):
    if source_manifest is None:
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        require(head == expected_commit, 'candidate commit mismatch')
        require(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=ROOT),
                'candidate tracked files changed')
        return head
    manifest_path = Path(source_manifest)
    require(manifest_path == ROOT / 'candidate.json' and manifest_path.resolve() == manifest_path,
            'exact staged candidate manifest required')
    raw = manifest_path.read_bytes()
    require(0 < len(raw) <= 262144, 'candidate manifest bound')
    value = json.loads(raw)
    require(set(value) == {'version', 'commit', 'files'} and value['version'] == 1
            and value['commit'] == expected_commit and type(value['files']) is list
            and 0 < len(value['files']) <= 512, 'candidate commit mismatch')
    names = set()
    for entry in value['files']:
        require(type(entry) is dict and set(entry) == {'file', 'bytes', 'sha256'}, 'candidate entry schema')
        relative = Path(entry['file'])
        require(not relative.is_absolute() and '..' not in relative.parts
                and str(relative) == entry['file'] and entry['file'] not in names,
                'candidate path invalid')
        names.add(entry['file'])
        path = ROOT / relative
        require(path.resolve() == path and path.is_file() and path.stat().st_nlink == 1,
                'candidate source invalid')
        source = path.read_bytes()
        require(len(source) == entry['bytes'] and len(source) <= 1024 * 1024
                and hashlib.sha256(source).hexdigest() == entry['sha256'], 'candidate source changed')
    require({'uas/local_cli.py', 'uas/local_library.py', 'tests/native/library_installation_probe.py'} <= names,
            'required candidate sources absent')
    return expected_commit


def safe_code(value):
    if value in ('BackendUnknown', 'OwnershipConflict', 'LifecycleError', 'QualificationError'):
        return value
    return value if type(value) is str and re.fullmatch(r'[A-Z][A-Z0-9_]{0,95}', value) else 'REDACTED'


def safe_state(value):
    if type(value) is not dict:
        return {'state': 'unavailable'}
    result = {}
    if value.get('phase') in ('absent', 'creating', 'starting', 'running', 'start_failed',
                              'stopping', 'stopped', 'stop_failed', 'destroying',
                              'destroy_failed', 'destroyed', 'unknown'):
        result['phase'] = value['phase']
    instance = value.get('instance_id')
    if type(instance) is str and re.fullmatch(r'[0-9a-f]{32}', instance):
        result['instance_id'] = instance
    leftovers = value.get('leftovers')
    if type(leftovers) is list:
        result['leftovers'] = [
            {'kind': item.get('kind') if item.get('kind') in
             ('network', 'container', 'volume', 'control-state', 'authority', 'reconciliation', 'tombstone')
             else 'redacted', 'reason': safe_code(item.get('reason'))}
            for item in leftovers[:16] if type(item) is dict]
        result['leftover_count'] = len(leftovers)
    return result


def diagnostic_command(arguments, *, limit=65536, seconds=5):
    """Bound only the exact read-only diagnostic child, including output bytes."""
    process = subprocess.Popen(['/usr/bin/docker', *arguments], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    output = bytearray(); deadline = time.monotonic() + seconds
    try:
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'diagnostic timeout')
            if not select.select([process.stdout], [], [], remaining)[0]:
                raise RuntimeError('diagnostic timeout')
            chunk = os.read(process.stdout.fileno(), min(8192, limit + 1 - len(output)))
            if not chunk: break
            output.extend(chunk)
            require(len(output) <= limit, 'diagnostic output bound')
        require(process.wait(timeout=max(.01, deadline-time.monotonic())) == 0,
                'diagnostic command unavailable')
        return bytes(output)
    finally:
        if process.poll() is None: process.kill()
        process.wait(); process.stdout.close()


def filtered_hub_errors(raw):
    text = raw.decode('utf-8', errors='replace')
    phases = ('import-start', 'import-done', 'entrypoint-validated', 'probe-start', 'probe-done',
              'metadata-wait', 'metadata-read', 'config-decoded', 'forge-import', 'forge-imported',
              'library-import', 'library-imported', 'binding-validated', 'seats-validated',
              'metadata-parsed', 'mapping-validated', 'paths-validated',
              'control-connect', 'control-connected')
    # Whole exact fixed markers only; arbitrary stderr never becomes evidence.
    phase_lines = {'UAS_LOCAL_HUB_PHASE ' + phase: phase for phase in phases}
    observed_phases = [phase_lines[line] for line in text.split('\n') if line in phase_lines]
    classes = ('ModuleNotFoundError', 'ImportError', 'PermissionError', 'FileNotFoundError',
               'OSError', 'RuntimeError', 'OriginDenied', 'LedgerError', 'QualificationError',
               'SyntaxError', 'TypeError', 'ValueError', 'OperationalError')
    result = {'exception_classes': [name for name in classes
              if re.search(r'(?:^|\n)(?:[a-z_][a-z0-9_]*\.)*' + name + r':', text)]}
    result['startup_phases'] = observed_phases[:len(phases)]
    result['startup_phase_overflow'] = len(observed_phases) > len(phases)
    known = {p.stem for p in (ROOT / 'uas').glob('*.py')}
    result['uas_frames'] = sorted({name for name in re.findall(r'/uas/([a-z_][a-z0-9_]*)\.py', text)
                                   if name in known})[:16]
    result['uas_trace'] = [{'module': name, 'line': int(line)}
                           for name, line in re.findall(r'/uas/([a-z_][a-z0-9_]*)\.py", line ([0-9]{1,6})', text)
                           if name in known][:16]
    modules = known | {'sqlite3', '_sqlite3', 'socket', '_socket', 'markdown_it', 'mdurl',
                       'grp', 'pwd', 'ssl', '_ssl', 'fcntl', 'select', 'uas'}
    result['missing_modules'] = sorted({name for name in re.findall(r"No module named ['\"]([a-z_][a-z0-9_]*)['\"]", text)
                                       if name in modules})[:16]
    result['known_failures'] = [name for name, marker in
        (('permission-denied', 'Permission denied'), ('file-not-found', 'No such file or directory'),
         ('database-open-failed', 'unable to open database file'), ('readonly-database', 'readonly database'),
         ('kernel-origin-unavailable', 'kernel origin unavailable')) if marker in text]
    return result


def docker_time_ns(value):
    require(type(value) is str, 'Docker timestamp type')
    match = re.fullmatch(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d{1,9})Z', value)
    require(match is not None, 'Docker timestamp format')
    instant = datetime.strptime(match[1], '%Y-%m-%dT%H:%M:%S')
    return calendar.timegm(instant.timetuple()) * 1000000000 + int(match[2].ljust(9, '0'))


def timestamped_hub_errors(raw, started_at):
    start = docker_time_ns(started_at)
    parsed = []
    for line in raw.decode('utf-8', errors='replace').split('\n'):
        match = re.fullmatch(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z) (.*)', line)
        if match is None: continue
        try: timestamp = docker_time_ns(match[1])
        except (ValueError, RuntimeError): continue
        parsed.append((timestamp, match[2]))
    result = filtered_hub_errors('\n'.join(line for _, line in parsed).encode())
    phases = set(result['startup_phases'])
    timings = []
    for timestamp, line in parsed:
        prefix = 'UAS_LOCAL_HUB_PHASE '
        if not line.startswith(prefix) or line[len(prefix):] not in phases: continue
        elapsed = timestamp - start
        if 0 <= elapsed <= 120000000000:
            timings.append({'phase': line[len(prefix):], 'elapsed_ms': elapsed // 1000000})
    result['phase_timings'] = timings[:19]
    result['phase_timing_overflow'] = len(timings) > 19
    result['timing_basis'] = 'docker-log-time-relative-to-container-start-not-supervisor-deadline'
    return result


def owned_hub_processes(raw, init_pid):
    lines = raw.decode('ascii').splitlines()
    require(lines and lines[0].split() == ['PID', 'PPID', 'COMMAND'] and len(lines) <= 3,
            'bounded exact container process table required')
    rows = {}
    for line in lines[1:]:
        fields = line.split()
        require(len(fields) == 3 and all(re.fullmatch(r'[1-9][0-9]{0,9}', n) for n in fields[:2])
                and re.fullmatch(r'tini|python3(?:\.[0-9]{1,2})?', fields[2]), 'fixed Hub process roles required')
        pid, parent = map(int, fields[:2])
        require(pid not in rows, 'duplicate container process')
        rows[pid] = (parent, 'tini' if fields[2] == 'tini' else 'python3')
    require(init_pid in rows and rows[init_pid][1] == 'tini', 'owned container init required')
    for pid in rows:
        current = pid; seen = set()
        while current != init_pid:
            require(current in rows and current not in seen, 'owned descendant required')
            seen.add(current); current = rows[current][0]
    return rows


def owned_hub_fd_limits(identity, init_pid):
    try:
        require(type(init_pid) is int and init_pid > 0, 'live owned init required')
        command = ['top', identity, '-eo', 'pid,ppid,comm']
        rows = owned_hub_processes(diagnostic_command(command, limit=4096), init_pid)
        result = []
        for pid, (_, role) in rows.items():
            held = os.pidfd_open(pid, 0)
            try:
                require(not select.select([held], [], [], 0)[0], 'owned process exited')
                directory = os.open('/proc/' + str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    limits = os.open('limits', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
                    try: raw = os.read(limits, 8193)
                    finally: os.close(limits)
                    require(len(raw) <= 8192, 'process limits bound')
                    match = re.search(rb'^Max open files +([0-9]{1,10}) +([0-9]{1,10}) +files *$', raw, re.M)
                    require(match is not None, 'numeric FD limits required')
                    descriptors = os.open('fd', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    try:
                        with os.scandir(descriptors) as entries:
                            count = sum(1 for _ in itertools.islice(entries, 4097))
                    finally: os.close(descriptors)
                    require(count <= 4096, 'descriptor inventory bound')
                    require(not select.select([held], [], [], 0)[0], 'owned process exited')
                    require(owned_hub_processes(diagnostic_command(command, limit=4096), init_pid) == rows,
                            'container processes changed')
                    result.append({'role': role, 'soft': int(match[1]), 'hard': int(match[2]), 'count': count})
                finally: os.close(directory)
            finally: os.close(held)
        return {'state': 'observed', 'processes': result}
    except Exception:
        return {'state': 'unavailable'}


AUDIT_LOG = Path('/var/log/audit/audit.log')


def scoped_avc_rows(raw, process_label, started_at):
    require(type(process_label) is str and re.fullmatch(
        r'system_u:system_r:container_t:s0:c[0-9]{1,4},c[0-9]{1,4}', process_label),
        'exact container process label required')
    start = docker_time_ns(started_at)
    classes = {'fd', 'file', 'dir', 'sock_file', 'unix_stream_socket', 'unix_dgram_socket',
               'process', 'capability', 'capability2'}
    permissions = {'use', 'read', 'write', 'open', 'getattr', 'setattr', 'ioctl', 'lock',
                   'append', 'map', 'connectto', 'connect', 'accept', 'sendto', 'recvfrom',
                   'send_msg', 'recv_msg', 'shutdown', 'search', 'execute', 'entrypoint', 'transition'}
    types = {'container_t', 'container_runtime_t', 'unconfined_t', 'init_t', 'kernel_t',
             'container_file_t', 'var_run_t', 'docker_var_run_t', 'tmp_t', 'unlabeled_t'}
    rows = []
    for line in raw.decode('utf-8', errors='replace').split('\n'):
        if not line.startswith('type=AVC '): continue
        context = re.search(r'(?:^| )scontext=([^ ]+)(?: |$)', line)
        if context is None or context[1] != process_label: continue
        stamp = re.search(r' msg=audit\(([0-9]{1,12})\.([0-9]{1,9}):[0-9]+\):', line)
        if stamp is None: continue
        timestamp = int(stamp[1])*1000000000 + int(stamp[2].ljust(9, '0'))
        if not 0 <= timestamp-start <= 120000000000: continue
        denial = re.search(r' avc: +denied +\{ ([a-z_ ]+) \}', line)
        selected_class = re.search(r'(?:^| )tclass=([a-z0-9_]+)(?: |$)', line)
        target = re.search(r'(?:^| )tcontext=[^ :]+:[^ :]+:([a-z0-9_]+):[^ ]+(?: |$)', line)
        if denial is None or selected_class is None: continue
        selected = denial[1].split()
        rows.append({'class': selected_class[1] if selected_class[1] in classes else 'redacted',
                     'permissions': sorted({p for p in selected if p in permissions}),
                     'target_type': target[1] if target is not None and target[1] in types else 'redacted'})
    return {'state': 'observed', 'denials': rows[:16], 'overflow': len(rows) > 16,
            'scope': 'exact-owned-container-label-and-start-window'}


def owned_hub_avc(process_label, started_at):
    try:
        # Validate scope before any audit access, including when the file is absent.
        scoped_avc_rows(b'', process_label, started_at)
        fd = os.open(AUDIT_LOG, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1,
                    'ordinary root audit log required')
            offset = max(0, info.st_size - 65536)
            os.lseek(fd, offset, os.SEEK_SET)
            raw = os.read(fd, 65536)
            if offset: raw = raw.partition(b'\n')[2]  # discard partial leading record
        finally:
            os.close(fd)
        return scoped_avc_rows(raw, process_label, started_at)
    except FileNotFoundError:
        return {'state': 'absent'}
    except Exception:
        return {'state': 'unavailable'}


def owned_hub_diagnostic(receipt, room_id):
    try:
        require(receipt.get('room_id') == room_id, 'diagnostic Room differs')
        instance = receipt.get('instance_id')
        require(type(instance) is str and re.fullmatch(r'[0-9a-f]{32}', instance), 'diagnostic instance')
        spec = receipt.get('spec', {})
        require(all(type(spec.get(key)) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', spec[key])
                    for key in ('config_digest', 'profile_digest')), 'diagnostic digest')
        name = 'uas-native-' + instance + '-hub'
        # Select only identity/ownership/state, never environment or arbitrary config.
        template = '{{json .Id}} {{json .Name}} {{json .Config.Labels}} {{json .State.Running}} {{json .State.ExitCode}} {{json .State.OOMKilled}} {{json .State.StartedAt}} {{json .ProcessLabel}} {{json .State.Pid}}'
        raw = diagnostic_command(['inspect', '--type', 'container', '--format', template, name])
        decoder = json.JSONDecoder(); values = []; rest = raw.decode().strip()
        while rest:
            value, end = decoder.raw_decode(rest); values.append(value); rest = rest[end:].lstrip()
        require(len(values) == 9, 'diagnostic inspect schema')
        identity, observed_name, labels, running, exit_code, oom, started_at, process_label, init_pid = values
        from uas.local_native import LocalNativeBackend
        prefix = LocalNativeBackend.LABEL
        expected = {prefix: 'true', prefix+'.room': room_id, prefix+'.instance': instance,
                    prefix+'.kind': 'hub', prefix+'.config': spec['config_digest'],
                    prefix+'.profile': spec['profile_digest']}
        require(observed_name == '/' + name and labels == expected
                and type(identity) is str and re.fullmatch(r'[0-9a-f]{64}', identity)
                and type(running) is bool and type(oom) is bool
                and type(exit_code) is int and 0 <= exit_code <= 255, 'diagnostic ownership differs')
        result = {'state': 'owned', 'running': running, 'exit_code': exit_code, 'oom_killed': oom}
        try:
            docker_time_ns(started_at)  # Validate before accessing logs.
            result['errors'] = timestamped_hub_errors(
                diagnostic_command(['logs', '--timestamps', '--tail', '80', identity]), started_at)
        except Exception:
            result['errors'] = {'state': 'unavailable'}
        result['selinux_avc'] = owned_hub_avc(process_label, started_at)
        result['fd_limits'] = owned_hub_fd_limits(identity, init_pid) if running else {'state': 'not-running'}
        return result
    except Exception:
        return {'state': 'unavailable'}


def startup_diagnostic(room, result):
    """Read only this configured Room's fixed receipt; emit no arbitrary details."""
    report = {'action': 'start', 'room': room['id'], 'stage': 'operator-response'}
    if type(result) is dict:
        report['outcome'] = result.get('outcome') if result.get('outcome') in ('observed', 'unknown') else 'redacted'
        if 'error' in result: report['error'] = safe_code(result['error'])
        response = result.get('result')
        if type(response) is dict:
            report['response_state'] = safe_state(response.get('infrastructure'))
    root = Path(room['state_root'])
    path = root / 'lifecycle.json'
    try:
        require(root.resolve() == root and root.is_dir(), 'receipt root invalid')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and info.st_nlink == 1 and info.st_size <= 1048576, 'receipt invalid')
            raw = os.read(fd, 1048577)
            require(len(raw) <= 1048576, 'receipt oversized')
            receipt = json.loads(raw)
            require(type(receipt) is dict and receipt.get('room_id') == room['id'], 'receipt scope invalid')
            report['owned_receipt'] = safe_state(receipt)
            if report.get('outcome') == 'unknown':
                report['owned_hub'] = owned_hub_diagnostic(receipt, room['id'])
        finally:
            os.close(fd)
    except FileNotFoundError:
        report['owned_receipt'] = {'state': 'absent'}
    except Exception:
        report['owned_receipt'] = {'state': 'unavailable'}
    print('Library native startup: ' + json.dumps(report, sort_keys=True), flush=True)
    return report


def isolated_marker(bundle, own, siblings):
    files = list(bundle.rglob('*'))
    require(not any(path.is_symlink() for path in files), 'projection symlink exposed')
    content = b'\n'.join(path.relative_to(bundle).as_posix().encode() + b'\n' + path.read_bytes()
                         for path in files if path.is_file())
    require(own.encode() in content, 'own Project marker absent')
    require(all(marker.encode() not in content for marker in siblings), 'sibling Project content exposed')


def proof_checkpoint(stage, room=None, error=None):
    stages = {'host-ready', 'room-start', 'room-ready', 'projection-verified', 'alpha-stop',
              'alpha-stopped', 'stopped-room-operator', 'operator-observed', 'sibling-status',
              'acceptance-observed', 'primary-failure', 'cleanup-room-stop', 'host-shutdown',
              'cleanup-failure'}
    require(stage in stages and room in (None, 'alpha', 'beta'), 'fixed proof checkpoint required')
    value = {'stage': stage}
    if room is not None: value['room'] = room
    if error is not None:
        value['error_code'] = safe_code(getattr(error, 'code', None))
        name = type(error).__name__
        value['error_class'] = name if name in {'RuntimeError', 'TimeoutExpired', 'LibraryError',
            'LocalInstallationError', 'LedgerError', 'OSError', 'ValueError', 'AssertionError'} else 'redacted'
    print('Library proof checkpoint: ' + json.dumps(value, sort_keys=True), flush=True)


def finish_owned_host(host):
    """Preserve bounded, content-free shutdown evidence without masking first failure."""
    failures = []; out = error = b''
    try:
        if host.poll() is None: host.send_signal(signal.SIGTERM)
        out, error = host.communicate(timeout=HOST_SHUTDOWN_OBSERVATION_SECONDS)
    except subprocess.TimeoutExpired as timeout:
        out, error = timeout.output or b'', timeout.stderr or b''
        failures.append('host shutdown uncertain; operator reconciliation required')
    except Exception:
        failures.append('host shutdown unavailable; operator reconciliation required')
    report = {'stage': 'host-shutdown', 'completed': not failures,
              'stdout_bytes': len(out), 'stderr_bytes': len(error)}
    code = host.poll()
    report['exit_code'] = code if type(code) is int and -255 <= code <= 255 else None
    if 0 < len(out) <= 8192:
        try:
            receipt = json.loads(out)
            if receipt == {'state': 'host-stopped'}:
                report['receipt'] = 'host-stopped'
            elif type(receipt) is dict and receipt.get('outcome') == 'unknown':
                report['error_code'] = safe_code(receipt.get('error'))
        except (ValueError, TypeError): pass
    if error:
        raw = error if type(error) is bytes else error.encode('utf-8', errors='replace')
        report['stderr_evidence'] = filtered_hub_errors(raw[:65536])
    print('Library host shutdown: ' + json.dumps(report, sort_keys=True), flush=True)
    if not failures:
        if code != 0 or error: failures.append('host shutdown unconfirmed')
        elif report.get('receipt') != 'host-stopped': failures.append('host shutdown receipt invalid')
    return failures


def finish_proof_cleanup(failures, primary_failure):
    if failures:
        proof_checkpoint('cleanup-failure')
        known = {'Room Stop unconfirmed', 'Room Stop unavailable',
                 'host shutdown uncertain; operator reconciliation required',
                 'host shutdown unavailable; operator reconciliation required',
                 'host shutdown unconfirmed', 'host shutdown receipt invalid',
                 'selection changed', 'selection observation unavailable'}
        print('Library cleanup outcomes: ' + json.dumps({
            'primary_failure_preserved': primary_failure,
            'failures': [value if value in known else 'redacted' for value in failures[:8]]},
            sort_keys=True), flush=True)
        # Keep the first assertion/operation failure as the raised exception.
        # Cleanup uncertainty remains a failed proof, never a success receipt.
        if not primary_failure:
            raise RuntimeError('; '.join(failures))


def run(installation_root, expected_commit, *, source_manifest=None, expected_markers=None):
    from uas.local_installation import Installation
    from uas.local_host import request
    from uas.library_controls import request as library_request
    require(os.geteuid() == 0, 'prepared native host root owner required')
    head = candidate_identity(expected_commit, source_manifest)
    installation = Installation(installation_root)
    selection, config, selected = installation.open()
    require(selected['native'] is not None and selected['library'] is not None,
            'prepared native and Library selections required')
    rooms = config['rooms']
    require(type(rooms) is list and [room.get('id') for room in rooms] == ['alpha', 'beta'],
            'exact ordered alpha and beta disposable Rooms required')
    if expected_markers is not None:
        require(set(expected_markers) == {r['id'] for r in rooms}
                and len(set(expected_markers.values())) == 2
                and all(type(v) is str and 0 < len(v) <= 128 for v in expected_markers.values()),
                'distinct fixed fixture markers required')
    require(not (installation.root / 'operator.sock').exists(), 'existing host owner must be stopped')
    before = (installation.root / 'installation.json').read_bytes()
    host = subprocess.Popen([sys.executable, '-m', 'uas', 'local', '--root', str(installation.root), 'serve'],
        cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.monotonic() + 60
    started = []
    primary_failure = False
    proof = {'commit': head, 'selection_sha256': hashlib.sha256(before).hexdigest(),
             'kind': 'actual-prepared-native-installation-two-room',
             'target_qualification': 'external-not-established-by-probe',
             'model_qualification': 'external-not-established-by-probe'}
    try:
        while not (installation.root / 'operator.sock').exists():
            require(host.poll() is None, 'host exited before readiness')
            require(time.monotonic() < deadline, 'host readiness deadline')
            time.sleep(.05)
        proof_checkpoint('host-ready')
        generations = {}
        for room in rooms:
            proof_checkpoint('room-start', room['id'])
            result = request(installation, 'start', room['id'])
            startup_diagnostic(room, result)
            require(result.get('outcome') == 'observed', 'Room Start outcome unknown')
            state = result['result']
            require(state.get('infrastructure', {}).get('phase') == 'running'
                    and not state['infrastructure'].get('leftovers')
                    and state.get('services', {}).get('hub') == 'ready', 'real Room/Hub not ready')
            started.append(room['id'])
            proof_checkpoint('room-ready', room['id'])
            reference = Path(room['project']['roots']['reference'])
            snapshot = json.loads((reference / 'library.snapshot.json').read_text())
            require(snapshot['project_id'] == room['project']['id'], 'projection Project mismatch')
            bundle = reference / 'library'
            require(bundle.is_dir(), 'coherent projection missing')
            require(not any(p.name in ('.git', 'clone.git', 'records.db') for p in bundle.rglob('*')),
                    'canonical state exposed in projection')
            require(set(p.name for p in reference.iterdir() if not p.name.startswith('.'))
                    == {'library', 'library.snapshot.json'}, 'unexpected published projection content')
            if expected_markers is not None:
                isolated_marker(bundle, expected_markers[room['id']],
                    [value for key, value in expected_markers.items() if key != room['id']])
            generations[room['id']] = snapshot
            proof_checkpoint('projection-verified', room['id'])
        alpha, beta = rooms
        proof_checkpoint('alpha-stop')
        stopped = request(installation, 'stop', alpha['id'])
        from uas.local_cli import stopped_result
        require(stopped.get('outcome') == 'observed' and stopped_result(stopped['result']),
                'Room Stop unconfirmed')
        started.remove(alpha['id'])
        proof_checkpoint('alpha-stopped')
        proof_checkpoint('stopped-room-operator')
        observation = library_request(installation.root / 'library' / 'operator',
            {'version': 1, 'action': 'observe', 'project_id': alpha['project']['id'], 'for_action': 'drain'})
        require(observation.get('outcome') == 'observed', 'stopped-Room operator unavailable')
        proof_checkpoint('operator-observed')
        require(host.poll() is None, 'singleton host ended with Room')
        proof_checkpoint('sibling-status')
        beta_state = request(installation, 'status', beta['id'])
        require(beta_state.get('outcome') == 'observed'
                and beta_state['result']['infrastructure']['phase'] == 'running', 'sibling Room stopped')
        require(json.loads((Path(beta['project']['roots']['reference']) / 'library.snapshot.json').read_text())
                == generations[beta['id']], 'sibling projection changed')
        if expected_markers is not None:
            proof['project_content_isolation'] = 'own-marker-present-sibling-markers-absent'
        proof.update(status='passed', rooms=[r['id'] for r in rooms],
                     stopped_room_operator='observed', sibling='running',
                     projection_identities={r: s['project_identity'] for r, s in generations.items()})
        proof_checkpoint('acceptance-observed')
    except BaseException as first:
        primary_failure = True
        proof_checkpoint('primary-failure', error=first)
        raise
    finally:
        failures = []
        for room in reversed(started):
            try:
                proof_checkpoint('cleanup-room-stop', room)
                result = request(installation, 'stop', room)
                from uas.local_cli import stopped_result
                if result.get('outcome') != 'observed' or not stopped_result(result['result']):
                    failures.append('Room Stop unconfirmed')
            except Exception:
                failures.append('Room Stop unavailable')
        # No force-kill/PID scans. Unconfirmed termination remains a failed proof.
        proof_checkpoint('host-shutdown')
        failures.extend(finish_owned_host(host))
        try:
            if (installation.root / 'installation.json').read_bytes() != before:
                failures.append('selection changed')
        except OSError:
            failures.append('selection observation unavailable')
        finish_proof_cleanup(failures, primary_failure)
    return proof


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--installation-root', required=True)
    parser.add_argument('--expected-commit', required=True)
    args = parser.parse_args(argv)
    require(args.run and os.environ.get('UAS_LIBRARY_INSTALLATION_PROOF') == '1',
            'explicit prepared-host execution approval required')
    print(json.dumps(run(args.installation_root, args.expected_commit), sort_keys=True))


if __name__ == '__main__':
    main()
