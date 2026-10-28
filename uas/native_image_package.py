"""Pure native image recipe/identity construction; never builds or launches.

The caller supplies independently selected official image digests. The returned
Dockerfile is a build input, not proof of an image or permission to build it.
"""
import hashlib
import json
import re

VERSIONS = {'pi': {'runtime_version': '1.4.0'},
            'claude': {'runtime_version': '2.1.310', 'sdk_version': '0.3.310'}}
SHA = re.compile(r'[0-9a-f]{64}\Z')
REFERENCE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}@sha256:[0-9a-f]{64}\Z')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def inventory(runtime):
    if runtime == 'pi':
        from .native_pi_recipe import ARTIFACTS
    elif runtime == 'claude':
        from .native_claude_recipe import ARTIFACTS
    else:
        raise ValueError('unsupported native runtime')
    return ARTIFACTS


def payload(runtime, artifacts):
    if (runtime not in VERSIONS or type(artifacts) is not dict
            or set(artifacts) != inventory(runtime)
            or any(type(v) is not str or not SHA.fullmatch(v) for v in artifacts.values())):
        raise ValueError('exact fixed native artifact inventory required')
    return {'version': 1, 'runtime': runtime, **VERSIONS[runtime], 'artifacts': dict(artifacts)}


def envelope(selected_payload, *, image_reference, image_id):
    """Finalize AFTER build: external installation record, never baked back in."""
    if type(selected_payload) is not dict:
        raise ValueError('payload required')
    expected = payload(selected_payload.get('runtime'), selected_payload.get('artifacts'))
    if canonical(selected_payload) != canonical(expected):
        raise ValueError('unexpected payload fields or versions')
    if (type(image_reference) is not str or not REFERENCE.fullmatch(image_reference)
            or type(image_id) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id)):
        raise ValueError('exact observed image identities required')
    return {**expected, 'image_reference': image_reference, 'image_id': image_id,
            'payload_manifest_digest': hashlib.sha256(canonical(expected)).hexdigest()}


def dockerfile(*, node_image, compiler_image):
    """linux/amd64 only; version and immutable content identity both mandatory."""
    for value, name in ((node_image, 'node:24.22.1-bookworm-slim'),
                        (compiler_image, 'gcc:14-bookworm')):
        if type(value) is not str or not re.fullmatch(re.escape(name) + r'@sha256:[0-9a-f]{64}', value):
            raise ValueError('select exact official version and digest before build')
    return f'''# Generated installation build input; no default digest, no credential mounts.
FROM --platform=linux/amd64 {compiler_image} AS compiler
COPY runtime/workstation/pi-native-connector.c /src/pi-native-connector.c
COPY runtime/claude/host-bootstrap.c /src/claude-host-bootstrap.c
COPY runtime/claude/native-bootstrap.c /src/claude-native-bootstrap.c
COPY runtime/claude/mcp-connector.c /src/claude-mcp-connector.c
RUN mkdir /out && for name in pi-native-connector claude-host-bootstrap claude-native-bootstrap claude-mcp-connector; do gcc -std=c11 -Wall -Wextra -Werror -O2 -static -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,noexecstack -Wl,-z,relro,-z,now -o /out/$name /src/$name.c || exit; done
FROM --platform=linux/amd64 {node_image} AS payload
ENV NPM_CONFIG_IGNORE_SCRIPTS=true NPM_CONFIG_AUDIT=false NPM_CONFIG_FUND=false NPM_CONFIG_USERCONFIG=/build/empty-user.npmrc NPM_CONFIG_GLOBALCONFIG=/build/empty-global.npmrc
COPY tests/pi/package*.json tests/pi/check-lock.mjs /opt/uas/pi/
COPY tests/claude/package*.json tests/claude/check-lock.mjs /opt/uas/claude-install/
COPY tests/claude/sdk/package*.json tests/claude/sdk/check-lock.mjs /opt/uas/claude-sdk/
RUN mkdir -p /build && touch /build/empty-user.npmrc /build/empty-global.npmrc && test "$(node --version)" = v24.22.1 && cd /opt/uas/pi && node check-lock.mjs && npm ci --ignore-scripts --registry=https://registry.npmjs.org --fetch-retries=0 --fetch-timeout=20000 && cd /opt/uas/claude-install && node check-lock.mjs && npm ci --ignore-scripts --registry=https://registry.npmjs.org --fetch-retries=0 --fetch-timeout=20000 && cd /opt/uas/claude-sdk && node check-lock.mjs && npm ci --omit=optional --legacy-peer-deps --ignore-scripts --registry=https://registry.npmjs.org --fetch-retries=0 --fetch-timeout=20000
COPY --from=compiler /out/ /opt/uas/bin/
COPY runtime/pi/ /opt/uas/runtime/pi/
COPY runtime/claude/ /opt/uas/runtime/claude/
COPY runtime/provider-auth.mjs /opt/uas/runtime/provider-auth.mjs
COPY runtime/native/write-payload.mjs /build/write-payload.mjs
COPY native-inventory.json /build/native-inventory.json
RUN mkdir -p /opt/uas/node/bin /opt/uas/claude && cp /usr/local/bin/node /opt/uas/node/bin/node && cp /opt/uas/claude-install/node_modules/@anthropic-ai/claude-code-linux-x64/claude /opt/uas/claude/claude && echo 'b73676430af12f97316a798b8371f81d640f90a58bdcb8f3ce56a835bb47df56  /opt/uas/claude/claude' | sha256sum -c - && node /build/write-payload.mjs && chmod -R go-w /opt/uas && rm -rf /build /root/.npm
USER 65532:65532
ENTRYPOINT []
CMD []
# Intentionally no native ENTRYPOINT: canonical Supervisor owns exact launch.
'''


def build_inventory():
    return {runtime: {'version': 1, 'runtime': runtime, **VERSIONS[runtime],
                      'paths': sorted(inventory(runtime))} for runtime in VERSIONS}
