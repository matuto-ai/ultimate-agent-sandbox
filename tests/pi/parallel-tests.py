#!/usr/bin/env python3
"""Two disjoint native Pi suites; no shared sessions, fixtures or evidence writers.

The shell runs the official auth/resume contracts first. This runner never changes
network/provider guards or skips discovered tests. Work is bounded to 125 seconds
plus two seconds of owned process-group cleanup inside the existing CI job.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
PRIMARY = frozenset(('test_pi_runtime', 'test_pi_forge', 'test_pi_assignment'))
WORK_SECONDS = 125
CANCELLED = None


def ids(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from ids(item)
        else:
            yield item.id()


def partition(inventory):
    inventory = list(inventory)
    if not inventory or len(set(inventory)) != len(inventory):
        raise ValueError('empty or duplicate Pi inventory')
    if any(not name.startswith('test_pi_') for name in inventory):
        raise ValueError('non-Pi test or discovery error')
    if not PRIMARY <= {name.split('.')[0] for name in inventory}:
        raise ValueError('measured primary modules missing')
    groups = [[], []]
    for name in inventory:
        groups[0 if name.split('.')[0] in PRIMARY else 1].append(name)
    if not all(groups) or set(groups[0]) & set(groups[1]) or sorted(sum(groups, [])) != sorted(inventory):
        raise ValueError('invalid Pi partition')
    return groups


def discover():
    sys.path.insert(0, str(ROOT / 'tests'))
    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT / 'tests'), pattern='test_pi_*.py')
    if loader.errors:
        raise ValueError('Pi discovery failed: ' + '\n'.join(loader.errors))
    return list(ids(suite))


def worker(manifest):
    sys.path.insert(0, str(ROOT / 'tests'))
    names = json.loads(Path(manifest).read_text())
    if not names or len(set(names)) != len(names):
        raise ValueError('invalid worker inventory')
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(names)
    if loader.errors or list(ids(suite)) != names:
        raise ValueError('worker inventory differs from discovery')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() and not result.skipped and result.testsRun == len(names) else 1


def observe(process):
    # Never reap here. Retaining a live child or its zombie reserves its PID/PGID
    # until every final group signal has been sent; poll() would destroy that proof.
    if process.returncode is not None:
        raise RuntimeError('Pi worker ownership lost: leader already reaped')
    try:
        status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError as exc:
        raise RuntimeError('Pi worker ownership lost: not an unreaped child') from exc
    if status is None:
        return None
    if status.si_pid != process.pid:
        raise RuntimeError('Pi worker wait identity mismatch')
    return status.si_status if status.si_code == os.CLD_EXITED else -status.si_status


def signal_group(process, sig):
    # Popen(start_new_session=True) established this group. Recheck retained
    # child ownership before each signal, including an exited, unreaped leader.
    observe(process)
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass


def cleanup(children):
    errors = []
    for process in children:
        try:
            signal_group(process, signal.SIGTERM)
        except (OSError, RuntimeError) as exc:
            errors.append(str(exc))
    if children:
        time.sleep(0.2)
    for process in children:
        try:
            signal_group(process, signal.SIGKILL)
        except (OSError, RuntimeError) as exc:
            errors.append(str(exc))
    # No numeric group signal may occur after this point. Reap last, even if
    # cleanup failed; never signal an unowned/reused process or silently pass.
    for process in children:
        try:
            process.wait(timeout=0.5)
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(str(exc))
    if errors:
        raise RuntimeError('owned Pi worker cleanup failed: ' + '; '.join(errors))


def wait_workers(children, deadline):
    while True:
        check_cancelled()
        statuses = [observe(process) for process in children]
        if any(code not in (None, 0) for code in statuses):
            raise RuntimeError('Pi partition failed: ' + repr(statuses))
        if all(code == 0 for code in statuses):
            return
        if time.monotonic() >= deadline:
            raise TimeoutError('Pi partitions exceeded absolute work deadline')
        time.sleep(0.05)


def interrupted(signum, _frame):
    # Do not raise across Popen -> retained-handle assignment. Cleanup owns every
    # returned handle before cooperative cancellation is observed.
    global CANCELLED
    CANCELLED = signum


def check_cancelled():
    if CANCELLED is not None:
        raise InterruptedError('Pi runner interrupted by signal ' + str(CANCELLED))


def run():
    global CANCELLED
    CANCELLED = None
    deadline = time.monotonic() + WORK_SECONDS
    inventory = discover()
    groups = partition(inventory)
    print(json.dumps({'pi_inventory_count': len(inventory), 'partitions': [len(g) for g in groups],
                      'inventory_sha256': hashlib.sha256('\n'.join(sorted(inventory)).encode()).hexdigest(),
                      'test_ids': inventory}), flush=True)
    children, logs, evidence = [], [], []
    error = None
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        with tempfile.TemporaryDirectory(prefix='uas-pi-partitions-') as directory:
            base = Path(directory)
            try:
                for index, names in enumerate(groups):
                    check_cancelled()
                    home = base / str(index)
                    home.mkdir()
                    manifest, proof, log = home / 'tests.json', home / 'evidence.jsonl', home / 'tests.log'
                    manifest.write_text(json.dumps(names))
                    proof.write_text('')
                    evidence.append(proof)
                    output = log.open('w+')
                    logs.append(output)
                    env = dict(os.environ, TMPDIR=str(home), TMP=str(home), TEMP=str(home),
                               UAS_PI_EVIDENCE=str(proof), PYTHONDONTWRITEBYTECODE='1')
                    children.append(subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                        '--worker', str(manifest)], cwd=ROOT, env=env, stdout=output,
                        stderr=subprocess.STDOUT, start_new_session=True))
                    check_cancelled()
                wait_workers(children, deadline)
                check_cancelled()
            except BaseException as exc:
                error = exc
            finally:
                # Ignore a repeated termination while fencing only owned groups.
                for sig in previous:
                    signal.signal(sig, signal.SIG_IGN)
                if error is None and CANCELLED is not None:
                    error = InterruptedError('Pi runner interrupted by signal ' + str(CANCELLED))
                try:
                    cleanup(children)
                except BaseException as exc:
                    if error is None:
                        error = exc
                    else:
                        print('Cleanup error: ' + str(exc), file=sys.stderr)
                for index, output in enumerate(logs):
                    output.seek(0)
                    print('=== Pi partition ' + str(index) + ' ===', flush=True)
                    for line in output:
                        print(line, end='')
                    output.close()
                # Append once, after both workers exit, including partial failure evidence.
                with open(os.environ['UAS_PI_EVIDENCE'], 'a') as destination:
                    for proof in evidence:
                        destination.write(proof.read_text())
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    if error is not None:
        raise error
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker')
    args = parser.parse_args()
    raise SystemExit(worker(args.worker) if args.worker else run())
