"""Pure fixed Hub build/readback contract; not launch or installation authority."""
import hashlib
import re

from .native_image_package import canonical, SHA

COMMAND = ['/opt/uas/bin/tini', '--', '/usr/bin/python3', '-m', 'uas.workstation_service']
BINARIES = {'/opt/uas/bin/tini', '/usr/bin/python3'}
MANIFEST = '/opt/uas/hub-payload.json'


def dockerfile(selection):
    if (type(selection) is not dict or set(selection) != {
            'base_image', 'python_package', 'python_version', 'tini_package'}
            or type(selection['base_image']) is not str
            or not re.fullmatch(r'node:24\.22\.1-bookworm-slim@sha256:[0-9a-f]{64}', selection['base_image'])
            or any(type(selection[k]) is not str or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]{0,127}', selection[k])
                   for k in ('python_package', 'tini_package'))
            or type(selection['python_version']) is not str
            or not re.fullmatch(r'3\.11\.[0-9]{1,3}', selection['python_version'])):
        raise ValueError('exact immutable Hub build inputs required')
    # Reuse the already selected Bookworm base; no extra mutable image default.
    return f'''# Fixed Hub packaging only; no credentials or running service.
FROM --platform=linux/amd64 {selection['base_image']}
USER 0:0
RUN apt-get update && apt-get install -y --no-install-recommends python3.11={selection['python_package']} tini={selection['tini_package']} && rm -rf /var/lib/apt/lists/*
COPY uas/*.py /opt/uas/uas/
COPY runtime/native/prepare-hub.py /build/prepare-hub.py
RUN /usr/bin/python3.11 -I /build/prepare-hub.py {selection['python_version']} && rm -rf /build
ENV PYTHONPATH=/opt/uas PYTHONDONTWRITEBYTECODE=1
WORKDIR /
USER 65531:65531
ENTRYPOINT ["/opt/uas/bin/tini"]
CMD ["--","/usr/bin/python3","-m","uas.workstation_service"]
'''


def source_inventory(root):
    """Only committed flat UAS modules; no checkout data or recursive discovery."""
    result = {}
    for file in sorted((root / 'uas').glob('*.py')):
        if file.is_symlink() or not file.is_file() or file.stat().st_size > 262144:
            raise ValueError('regular bounded Hub source required')
        result['/opt/uas/uas/' + file.name] = hashlib.sha256(file.read_bytes()).hexdigest()
    if (not 1 <= len(result) <= 256 or '/opt/uas/uas/workstation_service.py' not in result
            or '/opt/uas/uas/__init__.py' not in result):
        raise ValueError('complete bounded Hub source required')
    return result


def validate_payload(value, sources, python_version, observe):
    if (type(value) is not dict or set(value) != {'version','profile','python_version','artifacts'}
            or type(value['version']) is not int or value['version'] != 1
            or value['profile'] != 'fixed-hub-v1' or value['python_version'] != python_version
            or type(value['artifacts']) is not dict or set(value['artifacts']) != set(sources) | BINARIES
            or any(type(v) is not str or not SHA.fullmatch(v) for v in value['artifacts'].values())
            or any(value['artifacts'].get(k) != v for k,v in sources.items())):
        raise ValueError('Hub payload differs from exact source/build contract')
    for name, digest in value['artifacts'].items():
        if observe(name)['sha256'] != digest:
            raise ValueError('Hub artifact differs: ' + name)
    return {'artifact_count': len(value['artifacts']), 'source_count': len(sources),
            'manifest_sha256': hashlib.sha256(canonical(value)).hexdigest()}
