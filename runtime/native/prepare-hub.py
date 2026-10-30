#!/usr/bin/env python3
"""Build-stage-only Hub manifest writer; no service import or startup."""
import hashlib
import json
from pathlib import Path
import shutil
import stat
import sys


def main():
    if len(sys.argv) != 2 or '.'.join(map(str, sys.version_info[:3])) != sys.argv[1]:
        raise ValueError('selected Hub Python patch differs')
    root = Path('/opt/uas')
    (root / 'bin').mkdir(exist_ok=True)
    shutil.copyfile('/usr/bin/tini', root / 'bin/tini')
    # Fixed consumer path is a regular file so Engine readback hashes its bytes,
    # not a symlink declaration. The package interpreter remains unchanged.
    python = Path('/usr/bin/python3')
    if python.is_symlink(): python.unlink()
    if python.exists(): raise ValueError('unexpected existing Hub Python entry')
    shutil.copyfile('/usr/bin/python3.11', python)
    for file in (root / 'bin/tini', python): file.chmod(0o555)
    files = sorted((root / 'uas').glob('*.py'))
    if (not 1 <= len(files) <= 256 or not (root / 'uas/workstation_service.py').is_file()
            or not (root / 'uas/__init__.py').is_file()):
        raise ValueError('complete bounded Hub source required')
    artifacts = {}
    for file in [*files, root / 'bin/tini', python]:
        node = file.lstat()
        if (not stat.S_ISREG(node.st_mode) or node.st_uid != 0 or node.st_size > 16*1024*1024
                or file in files and node.st_size > 262144):
            raise ValueError('regular root-owned bounded Hub artifact required')
        file.chmod(0o444 if file in files else 0o555)
        artifacts[str(file)] = hashlib.sha256(file.read_bytes()).hexdigest()
    value = {'version':1,'profile':'fixed-hub-v1','python_version':sys.argv[1],'artifacts':artifacts}
    (root / 'hub-payload.json').write_text(json.dumps(value,sort_keys=True,separators=(',',':')))
    (root / 'hub-payload.json').chmod(0o444)


if __name__ == '__main__': main()
