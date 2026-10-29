"""Build readback parser tests only, not Docker or native execution."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import subprocess
import unittest
from unittest.mock import patch
from uas.native_image_package import payload
from uas.native_pi_recipe import ARTIFACTS
from uas.native_claude_recipe import ARTIFACTS as CLAUDE_ARTIFACTS
from uas.native_git_resources import FIXED_ARTIFACTS, LOADER, OriginDenied

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('image_readback', ROOT / 'runtime/native/check-image.py')
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class NativeImageReadbackTests(unittest.TestCase):
    def archive(self, *, name='payload', uid=0, mode=0o444, kind=tarfile.REGTYPE, extra=False):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as output:
            member = tarfile.TarInfo(name)
            member.uid, member.mode, member.type = uid, mode, kind
            member.size = 4 if kind == tarfile.REGTYPE else 0
            member.linkname = 'other' if kind != tarfile.REGTYPE else ''
            output.addfile(member, io.BytesIO(b'data'))
            if extra:
                output.addfile(tarfile.TarInfo('extra'), io.BytesIO())
        return stream.getvalue()

    def test_regular_fixed_readback_hash(self):
        result = CHECK.single_archive(self.archive(), 'payload')
        self.assertEqual(result, {'size': 4, 'sha256': hashlib.sha256(b'data').hexdigest(), 'data': b'data'})

    def test_path_link_permissions_and_extra_entries_rejected(self):
        for kwargs in ({'name': '../payload'}, {'uid': 1}, {'mode': 0o666},
                       {'kind': tarfile.SYMTYPE}, {'kind': tarfile.LNKTYPE}, {'extra': True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                CHECK.single_archive(self.archive(**kwargs), 'payload')

    def test_duplicate_fields_and_oversized_json_rejected(self):
        for raw in (b'{"version":1,"version":2}', b' ' * 65537):
            with self.assertRaises(ValueError): CHECK.document(raw)

    def test_native_payload_checks_every_fixed_artifact(self):
        selected = payload('pi', dict.fromkeys(ARTIFACTS, 'a' * 64))
        visited = []
        def observe(name):
            visited.append(name)
            return {'sha256': 'a' * 64}
        result = CHECK.validate_native(selected, 'pi', observe)
        self.assertEqual(set(visited), ARTIFACTS)
        self.assertEqual(result['artifact_count'], len(ARTIFACTS))
        with self.assertRaises(ValueError):
            CHECK.validate_native(selected, 'pi', lambda _: {'sha256': 'b' * 64})

    def test_manifest_metadata_cannot_substitute_versions_or_runtime(self):
        selected = payload('pi', dict.fromkeys(ARTIFACTS, 'a' * 64))
        for changes in ({'runtime': 'claude'}, {'runtime_version': '999'}, {'extra': True}):
            with self.assertRaises(ValueError):
                CHECK.validate_native({**selected, **changes}, 'pi', lambda _: {'sha256': 'a' * 64})

    def test_backend_export_must_match_final_payload_and_elf(self):
        backend = b'\x7fELFexample'
        selected = {'backend_sha256': hashlib.sha256(backend).hexdigest()}
        CHECK.validate_export(selected, copy.deepcopy(selected), backend)
        for exported, raw in (({'backend_sha256': 'a' * 64}, backend), (selected, backend + b'x')):
            with self.assertRaises(ValueError): CHECK.validate_export(selected, exported, raw)
        text = b'not ELF'
        selected = {'backend_sha256': hashlib.sha256(text).hexdigest()}
        with self.assertRaises(ValueError): CHECK.validate_export(selected, selected, text)

    def test_manual_tool_has_no_native_start_push_or_auto_workflow(self):
        source = (ROOT / 'runtime/native/check-image.py').read_text()
        self.assertIn("['create', '--network=none', '--read-only'", source)
        self.assertIn('verify_engine_payload(', source)
        self.assertNotIn("['run',", source)
        self.assertNotIn("['push',", source)
        self.assertIn("'not-created-no-published-reference'", source)

    def test_cleanup_reconciles_only_exact_owned_stopped_image(self):
        state = {'Id': 'a' * 64, 'Name': '/owned', 'Image': 'sha256:' + 'b' * 64,
                 'Config': {'Labels': {'io.uas.image-check': 'owner'}},
                 'State': {'Status': 'created', 'Running': False}}
        with patch.object(CHECK, 'command', side_effect=[b'{"ID":"a"}', json.dumps([state]).encode(), b'']) as call:
            CHECK.cleanup_container(['docker'], 'owned', 'owner', state['Image'])
            self.assertEqual(call.call_args.args[0], ['docker', 'rm', 'a' * 64])
        for changes in ({'Name': '/foreign'}, {'Image': 'other'}, {'Config': {'Labels': {}}},
                        {'State': {'Status': 'running', 'Running': True}}):
            with self.subTest(changes=changes), patch.object(CHECK, 'command', side_effect=[b'{}', json.dumps([{**state, **changes}]).encode()]) as call:
                with self.assertRaises(ValueError):
                    CHECK.cleanup_container(['docker'], 'owned', 'owner', state['Image'])
                self.assertEqual(call.call_count, 2)

    def test_cleanup_absent_is_noop_and_uncertain_read_is_not_success(self):
        with patch.object(CHECK, 'command', return_value=b'') as call:
            CHECK.cleanup_container(['docker'], 'owned', 'owner', 'sha256:' + 'b' * 64)
            self.assertEqual(call.call_count, 1)
        with patch.object(CHECK, 'command', return_value=b''):
            with self.assertRaises(ValueError):
                CHECK.cleanup_container(['docker'], 'owned', 'owner', 'sha256:' + 'b' * 64, uncertain=True)
        with patch.object(CHECK, 'command', side_effect=TimeoutError):
            with self.assertRaises(TimeoutError):
                CHECK.cleanup_container(['docker'], 'owned', 'owner', 'sha256:' + 'b' * 64)

    def test_official_selection_renders_without_fallback(self):
        selected = CHECK.document((ROOT / 'runtime/native/image-check-selection.json').read_bytes())
        result = CHECK.dockerfile(**selected)
        self.assertIn('FROM payload AS combined', result)
        self.assertEqual(selected['git_packages']['python_version'], '3.11.2')
        self.assertNotIn(':latest', result)
        workflow = (ROOT / '.github/workflows/native-image-readback.yml').read_text()
        self.assertNotIn('  push:', workflow)
        self.assertIn('types: [labeled]', workflow)
        self.assertIn('qualify-native-image', workflow)
        self.assertIn('persist-credentials: false', workflow)

    def scenario(self, failure=None, cleanup_failure=False):
        image_id = 'sha256:' + 'b' * 64
        container = 'c' * 64
        backend = b'\x7fELFfixture'
        git = self.git_payload(backend)
        commands = []
        owner = None
        native = {'pi': payload('pi', dict.fromkeys(ARTIFACTS, 'a' * 64)),
                  'claude': payload('claude', dict.fromkeys(CLAUDE_ARTIFACTS, 'a' * 64))}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'result'
            def run(args, **kwargs):
                nonlocal owner
                commands.append(args)
                if args[:2] == ['git', 'rev-parse']: return b'd' * 40 + b'\n'
                if args[:2] == ['git', 'status']: return b''
                if args[:2] == ['git', 'archive']:
                    destination = next(x.split('=', 1)[1] for x in args if x.startswith('--output='))
                    with tarfile.open(destination, 'w'): pass
                    return
                if 'build' in args:
                    stage = 'export' if '--target=git-backend-export' in args else 'build'
                    if failure == stage: raise ValueError(stage + ' failed')
                    if failure == stage + '-timeout': raise subprocess.TimeoutExpired(args, 600)
                    if stage == 'build': (output / 'image-id').write_text(image_id)
                    else:
                        (output / 'backend').mkdir()
                        (output / 'backend/git-backend').write_bytes(backend)
                        (output / 'backend/git-payload.json').write_bytes(CHECK.canonical(git))
                    return
                if 'image' in args:
                    return json.dumps([{'Id': image_id, 'Os': 'linux', 'Architecture': 'amd64',
                                        'Config': {'User': '65532:65532', 'Entrypoint': [], 'Cmd': []}}]).encode()
                if 'create' in args:
                    owner = next(x.split('=', 1)[1] for x in args if x.startswith('--name='))
                    if failure == 'create': raise subprocess.TimeoutExpired(args, 60)
                    return container.encode()
                if 'ls' in args:
                    return b'' if failure == 'create' else b'{"ID":"owned"}'
                if 'inspect' in args:
                    return json.dumps([{'Id': container, 'Name': '/' + owner, 'Image': image_id,
                        'Config': {'Labels': {'io.uas.image-check': owner.removeprefix('uas-image-check-')}},
                        'State': {'Status': 'created', 'Running': False}}]).encode()
                if 'rm' in args:
                    if cleanup_failure: raise TimeoutError('cleanup failed')
                    return b''
                raise AssertionError('unexpected command')
            def read(cid, name):
                self.assertEqual(cid, container)
                if failure == 'readback': raise ValueError('readback failed')
                if name.endswith('git-payload.json'): return {'data': CHECK.canonical(git)}
                for runtime in native:
                    if name.endswith(runtime + '-manifest.json'): return {'data': CHECK.canonical(native[runtime])}
                return {'sha256': 'a' * 64}
            def verify(engine, cid, manifest, *, deadline):
                self.assertEqual(cid, container)
                self.assertEqual(manifest['image_id'], image_id)
                if failure == 'git-readback': raise ValueError('git readback failed')
                return {'image_id': image_id}
            argv = ['check-image', '--selection', str(ROOT / 'runtime/native/image-check-selection.json'),
                    '--output', str(output)]
            with patch.object(CHECK.sys, 'argv', argv), patch.object(CHECK, 'command', side_effect=run), \
                 patch.object(CHECK, 'read_file', side_effect=read), \
                 patch.object(CHECK, 'verify_engine_payload', side_effect=verify), patch('builtins.print'):
                status = CHECK.main()
            report = json.loads((output / 'report.json').read_bytes())
        self.assertFalse(any('start' in args or 'push' in args or 'run' in args for args in commands))
        return status, report, commands

    def test_main_composes_build_export_actual_identity_readback_and_cleanup(self):
        status, report, commands = self.scenario()
        self.assertEqual(status, 0)
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(report['container_cleanup'], 'complete')
        self.assertEqual(report['build_execution'], 'completed')
        self.assertEqual(report['native_lifecycle'], 'not-run')
        self.assertEqual(len([c for c in commands if 'build' in c]), 2)
        self.assertEqual(len([c for c in commands if 'create' in c]), 1)
        self.assertEqual(len([c for c in commands if 'rm' in c]), 1)

    def test_main_failure_boundaries_do_not_retry_or_report_success(self):
        for failure in ('build', 'export', 'create', 'readback', 'git-readback'):
            with self.subTest(failure=failure):
                status, report, commands = self.scenario(failure)
                self.assertEqual(status, 1)
                self.assertEqual(report['status'], 'failed')
                self.assertIn('error', report)
                self.assertLessEqual(len([c for c in commands if 'create' in c]), 1)
                if failure == 'create': self.assertEqual(report['container_cleanup'], 'failed')

    def test_build_timeout_is_unknown_daemon_outcome_not_cleanup_success(self):
        for failure in ('build-timeout', 'export-timeout'):
            with self.subTest(failure=failure):
                status, report, _ = self.scenario(failure)
                self.assertEqual(status, 1)
                self.assertEqual(report['build_execution'], 'unknown-daemon-outcome')
                self.assertEqual(report['container_cleanup'], 'not-created')

    def test_cleanup_failure_preserves_primary_error_and_prevents_success(self):
        status, report, _ = self.scenario('readback', cleanup_failure=True)
        self.assertEqual(status, 1)
        self.assertIn('readback failed', report['error'])
        self.assertEqual(report['container_cleanup'], 'failed')
        status, report, _ = self.scenario(cleanup_failure=True)
        self.assertEqual(status, 1)
        self.assertEqual(report['status'], 'failed')

    def git_payload(self, backend=b'\x7fELFfixture'):
        return {'version': 1, 'profile': 'native-git-primary-v1', 'python_version': '3.11.2',
                'artifacts': dict.fromkeys(FIXED_ARTIFACTS, 'a' * 64),
                'abi_artifacts': {LOADER: 'b' * 64, '/lib/x86_64-linux-gnu/libc.so.6': 'c' * 64},
                'uas_tree_sha256': 'd' * 64, 'backend_sha256': hashlib.sha256(backend).hexdigest()}

    def test_shared_baked_git_validation_rejects_incomplete_or_foreign_metadata(self):
        value = self.git_payload()
        self.assertEqual(CHECK.validate_payload(value), value)
        for change in ({'version': True}, {'profile': 'other'}, {'python_version': '3.12.1'},
                       {'artifacts': {}}, {'abi_artifacts': {}}, {'uas_tree_sha256': 'bad'},
                       {'backend_sha256': 'bad'}, {'extra': True}):
            with self.subTest(change=change), self.assertRaises(OriginDenied):
                CHECK.validate_payload({**value, **change})
        wrong = copy.deepcopy(value)
        wrong['artifacts']['/usr/bin/git'] = 'b' * 64
        with self.assertRaises(OriginDenied): CHECK.validate_payload(wrong)
