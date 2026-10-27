#!/usr/bin/python3 -I
"""Fixed credential-free SSH-compatible adapter to the private native worker."""
import sys

sys.path.insert(0, '/opt/uas')
from uas.git_worker_native import ssh_shim_main

if __name__ == '__main__':
    try:
        raise SystemExit(ssh_shim_main(sys.argv[1:]))
    except Exception:
        print('Controlled Git transport unavailable', file=sys.stderr)
        raise SystemExit(128)
