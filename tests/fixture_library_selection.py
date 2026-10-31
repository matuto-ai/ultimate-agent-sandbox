"""Synthetic external model-evidence handoff for tests, not T42 qualification."""
import hashlib
import json
from pathlib import Path

from uas import library
from uas.library_dispatch import Profile


def write_selection(path, *, profile, command, bindings,
                    qualification_ref='synth-qualification',
                    valid_until='2030-01-01T00:00:00+00:00'):
    profile = Profile(**profile) if type(profile) is dict else profile
    rows = {}
    for binding in bindings:
        project = binding['project_identity']
        def proof(reference):
            return {'reference': reference, 'profile_sha256': profile.identity(),
                    'project_identity': project, 'valid_until': valid_until,
                    'qualified': True}
        rows[project] = {'qualification': proof(qualification_ref),
                         'authorization': proof(profile.reference), 'hosted_approval': None}
    raw = json.dumps({'version': 1, 'profile_sha256': profile.identity(),
                      'command_sha256': library._digest(list(command)),
                      'selections': rows}, sort_keys=True).encode()
    path = Path(path)
    path.write_bytes(raw)
    path.chmod(0o600)
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}
