"""Pure packaging tests: no compiler, image engine, subprocess or native imports."""
import copy
import hashlib
import unittest
from uas.native_image_package import (payload, envelope, canonical, inventory,
                                      build_inventory, dockerfile)


class NativeImagePackageTests(unittest.TestCase):
    def selected(self, runtime='claude'):
        return payload(runtime, dict.fromkeys(inventory(runtime), 'a' * 64))

    def test_non_circular_identity(self):
        for runtime in ('pi', 'claude'):
            selected = self.selected(runtime)
            before = canonical(selected)
            external = envelope(selected, image_reference='example/image@sha256:'+'b'*64,
                                image_id='sha256:'+'c'*64)
            self.assertNotIn('image_id', selected)
            self.assertNotIn('image_reference', selected)
            self.assertEqual(before, canonical(selected))
            self.assertEqual(external['payload_manifest_digest'], hashlib.sha256(before).hexdigest())
            self.assertEqual(external['artifacts'], selected['artifacts'])
            different = envelope(selected, image_reference='example/image@sha256:'+'d'*64,
                                 image_id='sha256:'+'e'*64)
            self.assertNotEqual(canonical(external), canonical(different))
            self.assertEqual(external['payload_manifest_digest'], different['payload_manifest_digest'])

    def test_artifact_drift_changes_payload_identity(self):
        first = self.selected()
        changed = copy.deepcopy(first)
        changed['artifacts'][next(iter(changed['artifacts']))] = 'b'*64
        self.assertNotEqual(hashlib.sha256(canonical(first)).digest(), hashlib.sha256(canonical(changed)).digest())

    def test_reject_malformed_or_extended_payload(self):
        for change in ({'image_id': 'sha256:'+'a'*64}, {'runtime_version': 'latest'},
                       {'version': 2}, {'version': True}, {'artifacts': {}}, {'sdk_version': 'wrong'}):
            bad = {**self.selected(), **change}
            with self.assertRaises(ValueError):
                envelope(bad, image_reference='example/image@sha256:'+'b'*64, image_id='sha256:'+'c'*64)
        for value in ('x:latest', 'x@sha256:short', 'x@sha256:'+'A'*64):
            with self.assertRaises(ValueError):
                envelope(self.selected(), image_reference=value, image_id='sha256:'+'c'*64)

    def test_payload_exact_inventory(self):
        for runtime in ('pi', 'claude'):
            base = self.selected(runtime)['artifacts']
            for malformed in ({}, {**base, '/tmp/extra': 'a'*64}, dict.fromkeys(base, 'bad')):
                with self.assertRaises(ValueError): payload(runtime, malformed)
            self.assertEqual(build_inventory()[runtime]['paths'], sorted(base))

    def test_build_requires_official_digest_pins(self):
        node = 'node:24.22.1-bookworm-slim@sha256:'+'a'*64
        compiler = 'gcc:14-bookworm@sha256:'+'b'*64
        for invalid in ('node:latest', 'node:24.22.1-bookworm-slim', node+'\nRUN evil', 'private/'+node):
            with self.assertRaises(ValueError): dockerfile(node_image=invalid, compiler_image=compiler)
        source = dockerfile(node_image=node, compiler_image=compiler)
        self.assertEqual(source.count('FROM --platform=linux/amd64 '), 2)
        self.assertIn('-static -fstack-protector-strong', source)
        self.assertIn('--ignore-scripts', source)
        self.assertIn('NPM_CONFIG_USERCONFIG=/build/empty-user.npmrc', source)
        self.assertIn('NPM_CONFIG_GLOBALCONFIG=/build/empty-global.npmrc', source)
        self.assertNotIn('curl ', source)
        self.assertNotIn('latest', source)
        self.assertIn('USER 65532:65532', source)
