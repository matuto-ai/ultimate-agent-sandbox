"""Diagnostic only: agents --json applicability, never a readiness authority."""
import json
import os
import selectors
import subprocess
import time


MAX_OUTPUT = 256 * 1024


def summarize(output, *, pid, session_id):
    """Keep exact identity evidence separate from any interpretation of idle."""
    if len(output.encode()) > MAX_OUTPUT:
        raise ValueError('oversized session listing')
    rows = json.loads(output)
    if type(rows) is not list or len(rows) > 64 or any(type(row) is not dict for row in rows):
        raise ValueError('unexpected session listing schema')
    related = [row for row in rows if row.get('pid') == pid or row.get('sessionId') == session_id]
    fields = ('pid', 'sessionId', 'kind', 'state', 'status', 'waitingFor', 'startedAt')
    exact = [row for row in related if type(row.get('pid')) is int
             and row['pid'] == pid and row.get('sessionId') == session_id]
    return {'entry_count': len(rows), 'related_rows': [{k: row[k] for k in fields if k in row} for row in related],
            'exact_identity_count': len(exact),
            'applicability': 'exact-identity-reported' if exact else 'identity-mismatch' if related else 'not-listed',
            'authorizes_delivery': False}


def query(binary, *, cwd, env, pid, session_id):
    """No prompt; fixed read-only public CLI command, bounded to five seconds.

    The caller supplies only a fresh fixture HOME/environment and runs inside
    the mandatory loopback-only namespace. Both output pipes share a hard byte
    cap; this fresh HOME has only the test's single native session.
    """
    started = time.monotonic()
    process = subprocess.Popen([str(binary), 'agents', '--json', '--all', '--setting-sources', ''],
                               cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    total = 0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
            while selector.get_map():
                remaining = started + 5 - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('session query exceeded five seconds')
                for key, _ in selector.select(remaining):
                    data = os.read(key.fd, min(65536, MAX_OUTPUT - total + 1))
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(data)
                    if total > MAX_OUTPUT:
                        raise ValueError('oversized session query output')
                    output[key.data].extend(data)
        process.wait(timeout=max(.001, started + 5 - time.monotonic()))
        if process.returncode != 0:
            raise RuntimeError('session query failed: ' + output['stderr'][-1000:].decode(errors='replace'))
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        process.stdout.close()
        process.stderr.close()
    return {'query_seconds': time.monotonic() - started,
            **summarize(output['stdout'].decode(), pid=pid, session_id=session_id)}
