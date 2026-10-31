"""Persistent local Hub entrypoint; owner loss, not a test deadline, ends it.

The fixed trusted launcher selects this module and supplies local-hub-v1 startup
metadata. It creates no Run or Participant and grants no admission itself.
Kernel startup, confinement checks, ledger, and dispatch remain shared with the
existing admitted Hub. Runtime/Run admission belongs to the existing owners.
"""
import sys

COMMAND = ['/opt/uas/bin/tini', '--', '/usr/bin/python3', '-m', 'uas.local_hub']


PHASES = frozenset({'import-start','import-done','entrypoint-validated','probe-start',
    'probe-done','metadata-wait','metadata-read','metadata-parsed','mapping-validated',
    'paths-validated','control-connect','control-connected','config-decoded',
    'forge-import','forge-imported','library-import','library-imported',
    'binding-validated','seats-validated'})


def progress(phase):
    # Fixed content-free milestones on the existing owned container log only.
    if type(phase) is not str or phase not in PHASES:
        raise ValueError('invalid fixed Hub phase')
    sys.stderr.write('UAS_LOCAL_HUB_PHASE '+phase+'\n');sys.stderr.flush()


def main():
    progress('import-start')
    from .workstation_service import run_service
    progress('import-done')
    return run_service(persistent=True,progress=progress)


if __name__ == '__main__':
    main()
