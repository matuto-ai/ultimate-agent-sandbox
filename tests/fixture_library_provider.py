"""Account-free external dispatch adapter fixture; never imports a provider SDK."""
import json
import os
from pathlib import Path
import sys
import time
wire = json.load(sys.stdin)
marker, mode, reply = sys.argv[1:]
Path(marker).write_bytes(wire['request'].encode())
assert os.getpriority(os.PRIO_PROCESS, 0) >= 10
assert json.loads(wire['request'])['tools'] == []
if mode == 'closed-output':
    sys.stdout.close(); os.close(1); time.sleep(5)
if mode == 'sleep':time.sleep(5)
if mode == 'release':
    deadline = time.monotonic() + 5
    while not Path(marker + '.release').exists():
        if time.monotonic() >= deadline:raise RuntimeError('FIXTURE_RELEASE_TIMEOUT')
        time.sleep(.01)
if mode == 'error':raise RuntimeError('PRIVATE_PROVIDER_EXCEPTION')
if mode == 'oversize':reply='x'*(wire['response_limit']+1)
sys.stdout.write(reply)
