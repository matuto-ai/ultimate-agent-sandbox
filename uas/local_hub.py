"""Persistent local Hub entrypoint; owner loss, not a test deadline, ends it.

The fixed trusted launcher selects this module and supplies local-hub-v1 startup
metadata. It creates no Run or Participant and grants no admission itself.
Kernel startup, confinement checks, ledger, and dispatch remain shared with the
existing admitted Hub. Runtime/Run admission belongs to the existing owners.
"""
from .workstation_service import run_service

COMMAND = ['/opt/uas/bin/tini', '--', '/usr/bin/python3', '-m', 'uas.local_hub']


def main():
    return run_service(persistent=True)


if __name__ == '__main__':
    main()
