"""Mock/file-only warm payload assembly; no compiler, RPM, ISO or native effects."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_prepared_room_contract as contracts
import prepared_room
import prepare_payload
import prepare_room_payload


class PreparedPayloadTests(unittest.TestCase):
    def test_prepared_modules_have_unique_discoverable_partition_ids(self):
        # unittest discovers imported TestCase classes as well as local ones.
        # Keep the fixture helper behind its module, never as a class alias.
        import ci_unit
        loader=unittest.TestLoader()
        suite=loader.loadTestsFromNames(('test_prepared_room_contract','test_prepared_room_payload'))
        self.assertEqual([],loader.errors)
        cases,groups=ci_unit.partition_suite(suite)
        ids=[case.id() for case in cases]
        self.assertEqual(len(ids),len(set(ids)))
        self.assertEqual([],groups['slow'])
        self.assertEqual(len(cases),len(groups['remainder']))
        self.assertEqual(30,sum(value.startswith('test_prepared_room_contract.') for value in ids))
        self.assertEqual(3,sum(value.startswith('test_prepared_room_payload.') for value in ids))

    def test_warm_pool_skips_network_solver_metadata_and_uses_fresh_source_nonce(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, artifact, manifest, receipt, digest = contracts.PreparedRoomContractTests().fixture(root)
            (repo / 'tests/vm/fedora-image.json').write_text(json.dumps({
                'release':'44-1.7','signing_fingerprint':'A'*40,'keyring_url':'https://fedoraproject.org/fedora.gpg'}))
            (repo / 'tests/vm/boundary_fixture.go').write_bytes(b'fresh current source')
            build = root/'build'; build.mkdir()
            calls = []
            def command(arguments, **kwargs):
                calls.append(arguments)
                tool = arguments[0]
                if tool == 'gpg': return 'pub:::::::::\nfpr:::::::::' + 'A'*40 + ':\n'
                if tool == 'rpmkeys' and '--checksig' in arguments: return 'Release Signature: OK\n'
                if tool == 'go':
                    self.assertEqual(b'fresh current source',Path(arguments[-1]).read_bytes())
                    Path(arguments[arguments.index('-o')+1]).write_bytes(b'new compiled fixture')
                elif tool == 'genisoimage': Path(arguments[arguments.index('-output')+1]).write_bytes(b'new ISO')
                elif tool not in ('gpg','rpm','rpmkeys'): self.fail('unexpected native command '+tool)
                return ''
            with patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}), \
                 patch.object(prepare_payload.os,'geteuid',return_value=1000), \
                 patch.object(prepared_room,'select',return_value=receipt) as select, \
                 patch.object(prepare_payload,'command',side_effect=command), \
                 patch.object(prepare_room_payload,'guest_package_roots'), \
                 patch.object(prepare_room_payload,'stage_native',return_value={'sha256':'c'*64}) as stage, \
                 patch.object(Path,'chmod'):
                iso = prepare_payload.build_payload(build,repo,'d'*32,
                    source_paths=['tests/vm/boundary_fixture.go'],profile=prepared_room.PROFILE,
                    prepared_directory=artifact,prepared_sha256=digest)
            select.assert_called_once_with(artifact,digest,repo)
            self.assertTrue(iso.exists()); stage.assert_called_once()
            output=json.loads((iso.parent/'payload/manifest.json').read_bytes())
            self.assertEqual('d'*32,output['nonce'])
            self.assertEqual(hashlib.sha256(b'fresh current source').hexdigest(),output['source'][0]['sha256'])
            self.assertEqual(manifest['packages'],output['packages'])
            self.assertFalse(any(args[0] in ('curl','dnf','createrepo_c') for args in calls))
            self.assertTrue(any(args[0]=='rpmkeys' and '--checksig' in args for args in calls))

    def test_rejected_artifact_never_creates_payload_or_invokes_tool(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            with patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}), \
                 patch.object(prepare_payload.os,'geteuid',return_value=1000), \
                 patch.object(prepared_room,'select',side_effect=ValueError('expired')), \
                 patch.object(prepare_payload,'command') as command:
                with self.assertRaises(ValueError):
                    prepare_payload.build_payload(root,root,'a'*32,source_paths=[],
                        profile=prepared_room.PROFILE,prepared_directory=root,prepared_sha256='b'*64)
            command.assert_not_called()
            self.assertFalse((root/'payload-build').exists())
