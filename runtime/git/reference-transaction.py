#!/usr/bin/python3 -I
"""Immutable native reference-transaction reporter; never import Project code."""
import sys

sys.path.insert(0, '/opt/uas')
from uas.git_transaction import hook_main

if __name__ == '__main__':
    try:
        raise SystemExit(hook_main(sys.argv[1:]))
    except Exception:
        raise SystemExit(128)
