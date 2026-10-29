"""Build-stage-only fixed Git layout; importing performs no I/O or execution.

The Dockerfile invokes this only after explicit package selection. Observed
metadata is not an image identity or proof of native ABI/security execution.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import struct
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def source_closure(sources):
    """Use source text only, never import the repository or Project modules."""
    pending = ['__init__', 'git_launcher', 'git_worker', 'git_worker_native', 'git_transaction']
    selected = {}
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        require(re.fullmatch(r'[a-z_][a-z0-9_]*', name) and len(selected) < 192,
                'bounded flat source closure required')
        require(name in sources and type(sources[name]) is str, 'source dependency missing: ' + name)
        text = sources[name]
        selected[name] = text
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.ImportFrom):
                if node.level:
                    require(node.level == 1 and node.module is not None, 'unsupported relative import')
                    pending.append(node.module)
                elif (node.module or '').startswith('uas.'):
                    pending.append(node.module[4:])
                else:
                    require(node.module != 'uas', 'ambiguous absolute package import')
            elif isinstance(node, ast.Import):
                for imported in node.names:
                    if imported.name.startswith('uas.'):
                        pending.append(imported.name[4:])
                    else:
                        require(imported.name != 'uas', 'ambiguous absolute package import')
    return selected


def dependency_paths(output, *, dependency_free=False):
    """Parse ldd for selected package ELF files; unresolved/foreign output fails."""
    require(type(output) is str and len(output) <= 65536, 'bounded dependency output required')
    if dependency_free is True and output.strip() == 'statically linked':
        return set()
    found = set()
    for line in output.splitlines():
        line = line.strip()
        if re.fullmatch(r'linux-vdso\.so\.[0-9]+ \(0x[0-9a-f]+\)', line):
            continue
        match = re.fullmatch(r'(?:[A-Za-z0-9_.+\-]+ => )?(/(?:lib|lib64|usr/lib)/[A-Za-z0-9_./+\-]+) \(0x[0-9a-f]+\)', line)
        require(match is not None, 'unresolved or unsupported ABI dependency')
        name = match.group(1)
        require('..' not in name.split('/') and '//' not in name, 'noncanonical ABI path')
        found.add(name)
    require(found, 'dynamic dependency closure required')
    return found


def dependency_free_extension(raw):
    """ELF64 x86-64 shared object with terminated dynamic table, no DT_NEEDED.

    This permits ldd's dependency-free-extension spelling, not a general static
    binary exception. It is not executable/ABI qualification.
    """
    require(type(raw) is bytes and 64 <= len(raw) <= 64 * 1024 * 1024
            and raw[:7] == b'\x7fELF\x02\x01\x01', 'bounded ELF64 extension required')
    require(struct.unpack_from('<HHI', raw, 16) == (3, 62, 1), 'x86-64 shared extension required')
    offset = struct.unpack_from('<Q', raw, 32)[0]
    size, count = struct.unpack_from('<HH', raw, 54)
    require(size == 56 and 0 < count <= 128 and offset >= 64
            and offset + count * size <= len(raw), 'bounded ELF program headers required')
    dynamic = []
    loads = 0
    for index in range(count):
        kind, flags, start, _, _, length, _, _ = struct.unpack_from('<IIQQQQQQ', raw, offset + index * size)
        require(start + length <= len(raw), 'ELF segment outside file')
        require(kind != 3, 'extension must not select a program interpreter')
        loads += kind == 1
        if kind == 2:
            require(length > 0 and length % 16 == 0 and length <= 65536, 'bounded dynamic table required')
            dynamic.append((start, length))
    require(loads and len(dynamic) == 1, 'one dynamic table and load segment required')
    start, length = dynamic[0]
    needed = False
    for offset in range(start, start + length, 16):
        tag, value = struct.unpack_from('<qQ', raw, offset)
        if tag == 0:
            return not needed
        needed = needed or tag == 1
    raise ValueError('unterminated dynamic table')


def abi_records(names, observe):
    """Hash every observed symlink hop AND target, using a bounded observer."""
    require(type(names) is set and 1 <= len(names) <= 64, 'bounded ABI roots required')
    abi = {}
    for name in sorted(names):
        current = name
        for _ in range(9):
            require(type(current) is str and current.startswith(('/lib/', '/lib64/', '/usr/lib/'))
                    and os.path.normpath(current) == current, 'ABI symlink leaves allowed closure')
            digest, target = observe(current)
            require(type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest), 'ABI file hash required')
            abi[current] = digest
            require(len(abi) <= 64, 'ABI inventory limit exceeded')
            if target is None:
                break
            require(type(target) is str and target, 'ABI link target required')
            current = os.path.normpath(os.path.join(os.path.dirname(current), target))
        else:
            raise ValueError('ABI symlink chain too deep')
    require('/lib64/ld-linux-x86-64.so.2' in abi and any(p.endswith('/libc.so.6') for p in abi),
            'required loader/libc missing')
    return abi


def public_entries(value):
    require(type(value) is list and 1 <= len(value) <= 128
            and all(type(n) is str and re.fullmatch(r'(?:git(?:-[a-z0-9-]+)?|scalar)', n) for n in value)
            and value == sorted(set(value)) and 'git' in value, 'fixed public inventory required')
    return value


def layout(entries):
    """Exact public image layout; values are source-relative name and mode."""
    public_entries(entries)
    files = {'/opt/uas/runtime/git/' + name: (name, 0o444) for name in (
        'launcher.py', 'worker.py', 'ssh-shim.py', 'reference-transaction.py', 'public-entries.json')}
    files.update({prefix + '/' + name: ('launcher.py', 0o555)
                  for prefix in ('/opt/uas/bin', '/usr/bin', '/usr/lib/git-core') for name in entries})
    files['/opt/uas/bin/git-ssh-shim'] = ('ssh-shim.py', 0o555)
    files['/opt/uas/git-hooks/reference-transaction'] = ('reference-transaction.py', 0o555)
    return files


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    require(str(Path(__file__)) == '/build/prepare-git.py' and os.getuid() == 0
            and len(sys.argv) == 2, 'fixed root build-stage invocation only')
    expected = sys.argv[1]
    actual = '.'.join(map(str, sys.version_info[:3]))
    require(re.fullmatch(r'3\.11\.[0-9]{1,3}', expected) and actual == expected,
            'selected Python patch differs from installed interpreter')
    python = Path('/usr/bin/python3.11')
    backend = Path('/usr/bin/git')
    for path in (python, backend):
        require(path.is_file() and not path.is_symlink() and path.read_bytes()[:4] == b'\x7fELF',
                'selected native ELF package artifact required')
    require(subprocess.check_output([str(backend), '--exec-path'], timeout=10).strip() == b'/usr/lib/git-core',
            'unexpected native Git helper tree')
    export = Path('/build/git-export')
    export.mkdir()
    shutil.copyfile(backend, export / 'git-backend')
    (export / 'git-backend').chmod(0o555)

    # ldd is confined to known installed Debian ELF files, never Project inputs.
    # Include stdlib extension dependencies, not just the interpreter executable.
    targets = [python, backend]
    targets.extend(sorted(Path('/usr/lib/python3.11/lib-dynload').glob('*.so')))
    require(2 < len(targets) <= 192, 'bounded Python extension closure required')
    names = set()
    for target in targets:
        output = subprocess.check_output(['/usr/bin/ldd', str(target)], stderr=subprocess.STDOUT,
                                         timeout=10, text=True)
        free = False
        if output.strip() == 'statically linked' and target not in (python, backend):
            free = dependency_free_extension(target.read_bytes())
        names.update(dependency_paths(output, dependency_free=free))
    def observe(name):
        path = Path(name)
        require(path.is_file(), 'missing ABI file')
        return digest(path), os.readlink(path) if path.is_symlink() else None
    abi = abi_records(names, observe)

    src = Path('/build/runtime/git')
    entries = public_entries(json.loads((src / 'public-entries.json').read_text()))
    package = Path('/opt/uas/uas')
    package.mkdir()
    texts = {p.stem: p.read_text() for p in Path('/build/uas').glob('*.py')}
    for name, text in source_closure(texts).items():
        path = package / (name + '.py')
        path.write_text(text)
        path.chmod(0o444)
    sources = {p.name: digest(p) for p in package.iterdir()}
    destination = Path('/opt/uas/runtime/git')
    destination.mkdir()
    # No raw upstream git-core helper survives into the final filesystem.
    shutil.rmtree('/usr/lib/git-core')
    Path('/usr/lib/git-core').mkdir()
    hooks = Path('/opt/uas/git-hooks')
    hooks.mkdir()
    for target, (source, mode) in layout(entries).items():
        path = Path(target)
        path.unlink(missing_ok=True)
        shutil.copyfile(src / source, path)
        path.chmod(mode)
    helpers = Path('/opt/uas/git-helpers')
    helpers.mkdir(mode=0o755)
    (helpers / 'git').symlink_to('/proc/self/fd/19')
    os.chown(hooks, 65530, 65532)
    hooks.chmod(0o500)
    link = Path('/usr/bin/python3')
    link.unlink(missing_ok=True)
    link.symlink_to('python3.11')

    # Use the existing verifier's authoritative inventory (source-only import).
    sys.path.insert(0, '/build')
    from uas.native_git_resources import FIXED_ARTIFACTS
    payload = {'version': 1, 'profile': 'native-git-primary-v1', 'python_version': actual,
               'artifacts': {p: digest(p) for p in FIXED_ARTIFACTS}, 'abi_artifacts': abi,
               'uas_tree_sha256': hashlib.sha256(canonical(sources)).hexdigest(),
               'backend_sha256': digest(export / 'git-backend')}
    for path in (export / 'git-payload.json', Path('/opt/uas/git-payload.json')):
        path.write_bytes(canonical(payload))
        path.chmod(0o444)


if __name__ == '__main__':
    main()
