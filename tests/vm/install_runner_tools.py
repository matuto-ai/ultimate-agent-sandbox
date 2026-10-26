#!/usr/bin/env python3
"""Install signed VM tools only in a disposable hosted Ubuntu 24.04 runner.

The stock Azure HTTP mirror has repeatedly stalled qualification before boot.
Copy its Ubuntu deb822 source, changing only URIs to official HTTPS archives.
Never edit /etc sources, add trust keys, or disable APT authentication.
"""
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

SOURCE = Path('/etc/apt/sources.list.d/ubuntu.sources')
KEYRING = '/usr/share/keyrings/ubuntu-archive-keyring.gpg'
BASE = ('qemu-system-x86', 'qemu-utils', 'cloud-image-utils', 'gnupg')
EXTRA = ('dnf', 'dnf-plugins-core', 'rpm', 'createrepo-c', 'genisoimage')
FIELDS = {'Types', 'URIs', 'Suites', 'Components', 'Signed-By', 'Architectures'}
# Literal emitted by runner-images ubuntu24/20261012.334 configure-apt-sources.sh.
# Recognize its syntax only; never open or follow the mirror file's candidates.
RUNNER_MIRROR = 'mirror+file:/etc/apt/apt-mirrors.txt'


def official_sources(stock):
    """Preserve stock suites/components/signing verbatim; reject other formats."""
    if not stock or len(stock) > 16384 or '\r' in stock or '\0' in stock:
        raise ValueError('unsupported Ubuntu source size/format')
    output = []
    for stanza in re.split(r'(\n[ \t]*\n)', stock):
        if not stanza.strip():
            output.append(stanza); continue
        fields = {}
        lines = stanza.splitlines(keepends=True)
        for line in lines:
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            name, separator, value = line.partition(':')
            if not separator or name not in FIELDS or name in fields:
                raise ValueError('unsupported Ubuntu deb822 field')
            fields[name] = value.strip()
        if not fields:
            output.append(stanza); continue
        required = FIELDS - {'Architectures'}
        if (not required <= fields.keys() or fields['Types'] != 'deb'
                or fields['Signed-By'] != KEYRING
                or not set(fields['Suites'].split()) <= {'noble', 'noble-updates', 'noble-security', 'noble-backports'}
                or not fields['Suites'] or not fields['Components']
                or not set(fields['Components'].split()) <= {'main', 'restricted', 'universe', 'multiverse'}
                or fields.get('Architectures', 'amd64') != 'amd64'):
            raise ValueError('unsupported Ubuntu suites/architecture/signing')
        uris = fields['URIs'].split()
        allowed = {scheme + host + '/ubuntu' for scheme in ('http://', 'https://')
                   for host in ('azure.archive.ubuntu.com', 'archive.ubuntu.com', 'security.ubuntu.com')}
        if not uris or any(uri != RUNNER_MIRROR and uri.rstrip('/') not in allowed for uri in uris):
            # Identify unsupported format without echoing URI credentials/query.
            schemes = sorted({urlsplit(uri).scheme[:32] for uri in uris})
            raise ValueError('unsupported Ubuntu archive URI scheme(s): ' + repr(schemes))
        destination = ('https://security.ubuntu.com/ubuntu' if fields['Suites'] == 'noble-security'
                       else 'https://archive.ubuntu.com/ubuntu')
        output.extend('URIs: ' + destination + '\n' if line.startswith('URIs:') else line for line in lines)
    result = ''.join(output)
    if not any(line.startswith('URIs: https://') for line in result.splitlines()):
        raise ValueError('missing Ubuntu source')
    return result


def apt_arguments(source):
    return ['sudo', '-n', 'apt-get', '-o', 'Dir::Etc::sourcelist=' + str(source),
            '-o', 'Dir::Etc::sourceparts=-', '-o', 'Acquire::Retries=0',
            '-o', 'Acquire::https::Timeout=20', '-o', 'Acquire::http::Timeout=20',
            '-o', 'Acquire::https::Verify-Peer=true', '-o', 'Acquire::https::Verify-Host=true',
            '-o', 'Acquire::AllowInsecureRepositories=false',
            '-o', 'Acquire::AllowDowngradeToInsecureRepositories=false',
            '-o', 'Acquire::Check-Valid-Until=true', '-o', 'APT::Get::AllowUnauthenticated=false',
            '-o', 'APT::Update::Error-Mode=any']


def main(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    if arguments not in (['feasibility'], ['boundary']):
        raise ValueError('choose feasibility or boundary tool set')
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.geteuid() == 0 or platform.machine() != 'x86_64'):
        raise RuntimeError('disposable hosted unprivileged CI runner required')
    release = platform.freedesktop_os_release()
    if release.get('ID') != 'ubuntu' or release.get('VERSION_ID') != '24.04':
        raise RuntimeError('Ubuntu 24.04 runner required')
    if SOURCE.is_symlink() or not SOURCE.is_file() or not Path(KEYRING).is_file():
        raise RuntimeError('stock Ubuntu source/keyring unavailable')
    transformed = official_sources(SOURCE.read_text())
    with tempfile.TemporaryDirectory(prefix='uas-runner-apt-') as temporary:
        directory = Path(temporary); directory.chmod(0o755)  # APT's sandbox user can read the public source.
        source = directory / 'ubuntu.sources'; source.write_text(transformed); source.chmod(0o644)
        command = apt_arguments(source)
        packages = BASE + (EXTRA if arguments == ['boundary'] else ())
        for action in (['update'], ['install', '-y', '--no-install-recommends', *packages]):
            started = time.monotonic()
            print('VM runner tools phase:', action[0], 'official Ubuntu HTTPS; signed metadata required', flush=True)
            subprocess.run([*command, *action], check=True, timeout=300)
            print('VM runner tools phase complete:', action[0], 'elapsed_seconds=', round(time.monotonic() - started, 3), flush=True)


if __name__ == '__main__':
    main()
