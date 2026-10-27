"""Inert repository/ordinary-file tests; no helper, listener or confinement runs."""
from contextlib import nullcontext
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zlib

from uas.artifact_protocol import ArtifactError, RESERVATION_BYTES
from uas.artifact_target import (ArtifactSourceResolver, CopiedObjectReader,
    _tree_entries, copy_objects, materialize, observe_target, ArtifactTargets, ArtifactTargetLease)


def identity(path):
    value = path.stat(); return [value.st_dev, value.st_ino]


class TargetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'; self.repo.mkdir()
        self.common = self.repo / '.git'; self.common.mkdir()
        (self.common / 'objects').mkdir(); (self.common / 'objects' / 'pack').mkdir()
        (self.common / 'objects' / 'info').mkdir()
        (self.common / 'refs' / 'heads').mkdir(parents=True)
        (self.common / 'HEAD').write_bytes(b'ref: refs/heads/main\n')
        self.slots = self.root / 'slots'; self.slots.mkdir()
        self.control = self.root / 'control'; self.control.mkdir(mode=0o700)
        self.room = {'id': 'room-a', 'project': {'id': 'project-a', 'repository': 'owner/repo'}}
        self.lifecycle = {'phase': 'running', 'instance_id': 'a' * 32,
            'spec': {'project_id': 'project-a', 'project_paths': [str(self.repo), str(self.slots)]}}
        self.supervisor = SimpleNamespace(directory=self.control,
            _locked=lambda: nullcontext(), _read=lambda: deepcopy(self.lifecycle))
        self.allocator = SimpleNamespace(supervisor=self.supervisor, room=self.room,
            repo=self.repo, root=self.slots, manifest=self.control / 'checkouts.json')
        self.raw_objects = {}
        self.blob = self.object('blob', b'committed\n')
        self.tree = self.object('tree', b'100644 file.txt\0' + bytes.fromhex(self.blob))
        self.head = self.object('commit', ('tree ' + self.tree + '\nauthor Fixture <f@invalid> 0 +0000\n'
            'committer Fixture <f@invalid> 0 +0000\n\nfixture\n').encode())
        (self.common / 'refs' / 'heads' / 'main').write_text(self.head + '\n')
        self.state = {'version': 1, 'room_id': 'room-a', 'instance_id': 'a' * 32,
            'project_id': 'project-a', 'repo': str(self.repo), 'root': str(self.slots),
            'common': str(self.common), 'filesystem': {'repo': identity(self.repo),
            'root': identity(self.slots), 'common': identity(self.common)},
            'slots': {'primary': {'path': str(self.repo), 'branch': 'refs/heads/main',
                'base': self.head, 'run': 'run-a', 'participant': 'alice', 'active': True,
                'phase': 'ready', 'identity': {'directory': identity(self.repo), 'git_metadata': identity(self.common)}}}}
        self.save(); self.resolver = ArtifactSourceResolver(self.supervisor, self.allocator)

    def object(self, kind, data):
        raw = kind.encode() + b' ' + str(len(data)).encode() + b'\0' + data
        oid = hashlib.sha1(raw).hexdigest(); self.raw_objects[oid] = (kind, data); directory = self.common / 'objects' / oid[:2]
        directory.mkdir(exist_ok=True); (directory / oid[2:]).write_bytes(zlib.compress(raw))
        return oid

    def save(self):
        self.allocator.manifest.write_text(json.dumps(self.state))

    def resolve(self):
        return self.resolver.resolve('run-a', 'alice', 'a' * 32)

    def store(self):
        store = self.root / 'view'; store.mkdir()
        copy_objects(self.common, store / 'objects', time.monotonic() + 10)
        (store / 'refs').mkdir(); (store / 'HEAD').write_bytes(b'ref: refs/heads/unused\n')
        (store / 'config').write_bytes(b'[core]\nrepositoryformatversion=0\nbare=true\n')
        return store

    def target(self, head=None):
        # Explicit pure reader fixture. The cloud executor exposes /usr/bin/git
        # as overflow-owned65534, which runtime admission correctly refuses.
        def read(oid, kind):
            actual, data = self.raw_objects[oid]
            self.assertEqual(kind, actual)
            self.assertEqual(oid, hashlib.sha1(kind.encode()+b' '+str(len(data)).encode()+b'\0'+data).hexdigest())
            return data
        reader = SimpleNamespace(read=read)
        return materialize(reader, head or self.head, self.root/'target', time.monotonic()+10)

    def test_resolves_owned_head_without_allocator_git_or_dirty_worktree(self):
        self.allocator._git = lambda *_: self.fail('source Git invoked')
        (self.common / 'config').write_text('[core]\n hooksPath=/attacker\n[filter "evil"]\n smudge=attacker\n')
        (self.repo / 'file.txt').write_text('dirty attacker')
        source = self.resolve()
        self.assertEqual(self.head, source['head_sha']); self.assertEqual('primary', source['slot_id'])
        self.assertNotIn('path', source)

    def test_current_reports_new_head_and_recheck_fences_it(self):
        source = self.resolve(); other = self.object('commit', ('tree ' + self.tree + '\n\nother\n').encode())
        (self.common / 'refs/heads/main').write_text(other + '\n')
        self.assertEqual(other, self.resolver.current(source)['head_sha'])
        self.assertEqual(source['source_digest'], self.resolver.current(source)['source_digest'])
        with self.assertRaises(ArtifactError): self.resolver.recheck(source)

    def test_guarded_checkout_scope_remains_inert_strict_and_source_bound(self):
        original = self.resolve()
        scope = {'kind': 'docker-workstation', 'instance': 'a' * 32,
                 'container': 'b' * 64, 'started_at': '2026-10-27T14:00:00Z'}
        slot = self.state['slots']['primary']
        slot['writer_scope'] = scope; self.save()
        self.allocator._git = lambda *_: self.fail('source Git invoked')
        guarded = self.resolve()
        self.assertEqual(original['head_sha'], guarded['head_sha'])
        self.assertNotEqual(original['source_digest'], guarded['source_digest'])
        for bad in (None, {}, {**scope, 'instance': 'c' * 32},
                    {**scope, 'container': 'name-only'}, {**scope, 'extra': True}):
            slot['writer_scope'] = bad; self.save()
            with self.assertRaises(ArtifactError) as error: self.resolve()
            self.assertEqual('ARTIFACT_SLOT_NOT_OWNED', error.exception.code)
        slot['writer_scope'] = scope; slot['unknown'] = True; self.save()
        with self.assertRaises(ArtifactError): self.resolve()

    def test_wrong_run_participant_instance_phase_and_stored_identity_fail(self):
        for change in ('participant', 'instance', 'phase', 'identity'):
            with self.subTest(change=change):
                old, lifecycle = deepcopy(self.state), deepcopy(self.lifecycle)
                if change == 'participant': self.state['slots']['primary']['participant'] = 'bob'
                if change == 'instance': self.lifecycle['instance_id'] = 'b' * 32
                if change == 'phase': self.state['slots']['primary']['phase'] = 'creating'
                if change == 'identity': self.state['filesystem']['common'][1] += 1
                self.save()
                with self.assertRaises(ArtifactError): self.resolve()
                self.state, self.lifecycle = old, lifecycle; self.save()

    def test_symlink_head_and_hardlink_ref_rejected(self):
        head = self.common / 'HEAD'; head.unlink(); head.symlink_to('refs/heads/main')
        with self.assertRaises(ArtifactError): self.resolve()
        head.unlink(); head.write_bytes(b'ref: refs/heads/main\n')
        os.link(self.common / 'refs/heads/main', self.root / 'linked-ref')
        with self.assertRaises(ArtifactError): self.resolve()

    def test_detached_symbolic_ref_and_external_gitdir_rejected(self):
        (self.common / 'HEAD').write_text(self.head + '\n')
        with self.assertRaises(ArtifactError): self.resolve()
        (self.common / 'HEAD').write_bytes(b'ref: refs/heads/main\n')
        (self.common / 'refs/heads/main').write_bytes(b'ref: refs/heads/elsewhere\n')
        with self.assertRaises(ArtifactError): self.resolve()
        self.common.rename(self.root / 'external'); (self.repo / '.git').write_text('gitdir: ' + str(self.root / 'external') + '\n')
        with self.assertRaises(ArtifactError): self.resolve()

    def test_packed_ref_is_bounded_inert_and_duplicates_fail(self):
        (self.common / 'refs/heads/main').unlink()
        packed = self.common / 'packed-refs'; line = self.head + ' refs/heads/main\n'
        packed.write_text('# pack-refs with: peeled fully-peeled sorted\n' + line)
        self.assertEqual(self.head, self.resolve()['head_sha'])
        packed.write_text(line + line)
        with self.assertRaises(ArtifactError): self.resolve()

    def test_linked_slot_requires_exact_reciprocal_binding(self):
        key = 'b' * 32; slot = self.slots / key; slot.mkdir()
        admin = self.common / 'worktrees' / key; admin.mkdir(parents=True)
        (slot / '.git').write_text('gitdir: ' + str(admin) + '\n')
        (admin / 'commondir').write_text('../..\n'); (admin / 'gitdir').write_text(str(slot / '.git') + '\n')
        branch = 'refs/heads/uas-slot/' + key
        (admin / 'HEAD').write_text('ref: ' + branch + '\n')
        (self.common / 'refs/heads/uas-slot').mkdir(); (self.common / branch).write_text(self.head + '\n')
        entry = self.state['slots'].pop('primary'); entry.update(path=str(slot), branch=branch,
            identity={'directory':identity(slot), 'git_metadata':identity(slot / '.git')})
        self.state['slots'][key] = entry; self.save()
        self.assertEqual(key, self.resolve()['slot_id'])
        (admin / 'gitdir').write_text(str(self.repo / '.git') + '\n')
        with self.assertRaises(ArtifactError): self.resolve()

    def test_object_copy_ignores_config_hooks_index_attributes_and_worktree(self):
        for name in ('config', 'index', 'grafts', '.gitattributes'):
            (self.common / name).write_text('malicious opaque data')
        (self.common / 'hooks').mkdir(); (self.common / 'hooks/pre-commit').write_text('never run')
        store = self.store()
        self.assertEqual({'objects', 'refs', 'HEAD', 'config'}, {p.name for p in store.iterdir()})
        self.assertNotIn(b'malicious', (store / 'config').read_bytes())

    def test_alternate_promisor_symlink_and_hardlink_objects_fail(self):
        for kind in ('alternate', 'promisor', 'symlink', 'hardlink'):
            with self.subTest(kind=kind):
                path = None
                if kind == 'alternate':
                    path=self.common / 'objects/info/alternates'; path.write_text('/elsewhere')
                elif kind == 'promisor':
                    path=self.common / ('objects/pack/pack-' + 'a'*40 + '.promisor'); path.write_bytes(b'')
                elif kind == 'symlink':
                    path=self.common / ('objects/pack/pack-' + 'a'*40 + '.pack'); path.symlink_to('/outside')
                else:
                    path=self.root/'hardlink'; os.link(self.common/'objects'/self.blob[:2]/self.blob[2:], path)
                with self.assertRaises((ArtifactError, OSError)):
                    copy_objects(self.common, self.root / ('copy-'+kind), time.monotonic()+10)
                path.unlink()

    def test_reader_postspawn_setup_failures_reap_owned_child(self):
        for failure in ('blocking', 'selector', 'register'):
            with self.subTest(failure=failure):
                child=Mock(); child.stdout.fileno.return_value=41; child.returncode=-9
                selector=Mock()
                blocking=OSError('mock blocking') if failure=='blocking' else None
                factory=OSError('mock selector') if failure=='selector' else None
                if failure=='register': selector.register.side_effect=OSError('mock register')
                with patch('uas.artifact_target._trusted_executable'), \
                     patch('uas.artifact_target.subprocess.Popen',return_value=child) as spawn, \
                     patch('uas.artifact_target.os.set_blocking',side_effect=blocking), \
                     patch('uas.artifact_target.selectors.DefaultSelector',return_value=selector,side_effect=factory):
                    with self.assertRaises(OSError): CopiedObjectReader(self.root,time.monotonic()+10)
                child.kill.assert_called_once(); child.wait.assert_called_once()
                child.stdin.close.assert_called_once(); child.stdout.close.assert_called_once()
                self.assertNotIn('preexec_fn',spawn.call_args.kwargs)
                self.assertEqual('/usr/bin/prlimit',spawn.call_args.args[0][0])
                self.assertIn('/usr/bin/git',spawn.call_args.args[0])

    def test_reader_selector_close_failure_does_not_leak_process_or_pipes(self):
        reader=CopiedObjectReader.__new__(CopiedObjectReader)
        child=Mock();child.returncode=0;reader.process=child
        reader.selector=Mock();reader.selector.close.side_effect=OSError('mock close')
        reader.deadline=time.monotonic()+10
        with self.assertRaises(ArtifactError): reader.close()
        child.wait.assert_called_once();child.stdin.close.assert_called_once();child.stdout.close.assert_called_once()
        self.assertIsNone(reader.process)

    def test_object_directory_acquisition_failure_closes_common_descriptor(self):
        original = os.open
        opened = []
        def tracked(path, flags, *args, **kwargs):
            if path == 'objects':
                raise PermissionError('simulated denial before objects fd acquisition')
            fd = original(path, flags, *args, **kwargs); opened.append(fd); return fd
        with patch('uas.artifact_target.os.open', side_effect=tracked):
            with self.assertRaises(PermissionError):
                copy_objects(self.common, self.root/'deniedcopy', time.monotonic()+10)
        for fd in set(opened):
            with self.assertRaises(OSError): os.fstat(fd)

    def test_current_does_not_accept_changed_ownership_with_same_head(self):
        source = self.resolve()
        self.state['slots']['primary']['base'] = 'f'*40; self.save()
        with self.assertRaises(ArtifactError): self.resolver.current(source)

    def test_materialization_uses_committed_blob_and_reconstructs_tree(self):
        (self.repo / 'file.txt').write_bytes(b'dirty')
        result = self.target()
        self.assertEqual(self.tree, result['tree_sha'])
        self.assertEqual(b'committed\n', (self.root/'target/file.txt').read_bytes())
        self.assertEqual(0o444, (self.root/'target/file.txt').stat().st_mode & 0o777)
        self.assertEqual(result, observe_target(self.root/'target', time.monotonic()+10))

    def test_target_content_mode_symlink_and_extra_file_mutation_rejected(self):
        expected = self.target(); path = self.root/'target/file.txt'
        path.chmod(0o644)
        with self.assertRaises(ArtifactError): observe_target(path.parent,time.monotonic()+10)
        path.write_bytes(b'changed'); path.chmod(0o444)
        self.assertNotEqual(expected, observe_target(path.parent,time.monotonic()+10))
        path.parent.chmod(0o755); path.unlink(); path.symlink_to('/outside'); path.parent.chmod(0o555)
        with self.assertRaises(ArtifactError): observe_target(path.parent,time.monotonic()+10)
        path.parent.chmod(0o755); path.unlink()

    def test_unsupported_tree_modes_names_duplicates_and_order_rejected(self):
        for raw in (b'120000 link\0'+bytes.fromhex(self.blob), b'160000 sub\0'+bytes.fromhex(self.head),
                    b'100644 ../escape\0'+bytes.fromhex(self.blob), b'100644 .git\0'+bytes.fromhex(self.blob),
                    b'100644 x\0'+bytes.fromhex(self.blob)+b'100644 x\0'+bytes.fromhex(self.blob),
                    b'100644 z\0'+bytes.fromhex(self.blob)+b'100644 a\0'+bytes.fromhex(self.blob)):
            with self.subTest(raw=raw[:20]), self.assertRaises(ArtifactError): _tree_entries(raw)

    def test_corrupt_used_object_never_materializes(self):
        path=self.common/'objects'/self.blob[:2]/self.blob[2:]; path.write_bytes(zlib.compress(b'blob 4\0evil'))
        with self.assertRaises(ArtifactError):
            # Test the real reader's hash verification, without executing Git.
            reader=CopiedObjectReader.__new__(CopiedObjectReader)
            reader.deadline=time.monotonic()+10
            reader.process=SimpleNamespace(stdin=SimpleNamespace(write=lambda *_:None,flush=lambda:None))
            reader.buffer=bytearray((self.blob+' blob 4\n').encode()+b'evil\n')
            reader.read(self.blob,'blob')

    def test_target_expansion_and_object_copy_limits_refuse(self):
        with patch('uas.artifact_target.MAX_OBJECT_BYTES', 1), self.assertRaises(ArtifactError): self.store()
        with patch('uas.artifact_target.MAX_TARGET_BYTES', 1), self.assertRaises(ArtifactError):
            # A separate copy avoids relying on cleanup after the rejected store.
            reader = SimpleNamespace(read=lambda oid, kind: {'commit':('tree '+self.tree+'\n').encode(),
                'tree':b'100644 file.txt\0'+bytes.fromhex(self.blob), 'blob':b'committed\n'}[kind])
            materialize(reader,self.head,self.root/'bounded',time.monotonic()+10)

    def private_lease(self):
        scratch=self.root/'private-scratch';scratch.mkdir(mode=0o711)
        parent=scratch/('a'*32);parent.mkdir(mode=0o700)
        (parent/'tree').mkdir(mode=0o555);(parent/'store').mkdir(mode=0o700)
        (parent/'store'/'opaque').write_bytes(b'objects')
        owner=SimpleNamespace(root=scratch,root_identity=identity(scratch),_save=Mock(),resolver=self.resolver)
        lease=ArtifactTargetLease(owner,'evaluation-a',self.resolve(),'a'*32,identity(parent))
        lease.phase='prepared'
        return lease

    def test_cleanup_requires_actual_exit_and_removes_only_owned_private_resources(self):
        lease=self.private_lease();lease.mark_launch_possible()
        with self.assertRaises(ArtifactError):lease.cleanup()
        self.assertTrue(lease.path.exists())
        lease.mark_exit_confirmed();self.assertTrue(lease.cleanup())
        self.assertFalse(lease.path.exists());self.assertTrue(self.repo.exists())
        self.assertEqual(self.head,self.resolve()['head_sha'])

    def test_cleanup_fences_unconfirmed_materializer_and_replaced_parent(self):
        lease=self.private_lease();lease.materializer_exit_unconfirmed=True
        with self.assertRaises(ArtifactError):lease.cleanup()
        lease.materializer_exit_unconfirmed=False
        old=lease.path.with_name('retained');lease.path.rename(old);lease.path.mkdir(mode=0o700)
        with self.assertRaises(ArtifactError):lease.cleanup()
        self.assertTrue(old.exists());self.assertTrue(lease.path.exists())

    def test_cleanup_rejects_symlink_and_retains_quarantine(self):
        lease=self.private_lease();(lease.path/'escape').symlink_to(self.repo)
        with self.assertRaises(ArtifactError):lease.cleanup()
        self.assertEqual('quarantined',lease.phase);self.assertTrue(self.repo.exists())

    def test_cleanup_hardlinked_private_node_is_quarantined_not_unlinked(self):
        lease=self.private_lease()
        os.link(lease.path/'store/opaque',self.root/'retained-object')
        with self.assertRaises(ArtifactError):lease.cleanup()
        self.assertEqual('quarantined',lease.phase)
        self.assertEqual(b'objects',(self.root/'retained-object').read_bytes())

    def test_cleanup_unlink_final_rmdir_and_fsync_failures_quarantine(self):
        for stage in ('unlink','rmdir','fsync'):
            with self.subTest(stage=stage):
                # Each synthetic owner gets its own exclusively named scratch.
                lease=self.private_lease()
                if stage=='unlink':
                    guard=patch('uas.artifact_target.os.unlink',side_effect=OSError('mock unlink'))
                elif stage=='rmdir':
                    real=os.rmdir
                    def remove(name,*args,**kwargs):
                        if name==lease.target_id:raise OSError('mock final rmdir')
                        return real(name,*args,**kwargs)
                    guard=patch('uas.artifact_target.os.rmdir',side_effect=remove)
                else:
                    guard=patch('uas.artifact_target.os.fsync',side_effect=OSError('mock fsync'))
                with guard,self.assertRaises(OSError):lease.cleanup()
                self.assertEqual('quarantined',lease.phase);lease.owner._save.assert_called()
                # Ordinary test fixture cleanup, never a retry of runtime lease.
                import shutil
                shutil.rmtree(lease.owner.root)

    def test_resource_marker_capacity_refuses_before_new_scratch(self):
        scratch=self.root/'scratch-cap';scratch.mkdir(mode=0o711)
        journals=self.root/'journals-cap';journals.mkdir(mode=0o700)
        for i in range(16):(journals/(f'{i:064x}'+'.json')).write_bytes(b'{}')
        admit=Mock(return_value=True)
        targets=ArtifactTargets(scratch,journals,self.resolver,reserve_capacity=admit)
        scope={'version':1,'evaluation_id':'evaluation-a','room_id':'room-a','room_instance':'a'*32,
            'project_id':'project-a','repository':'owner/repo','run_id':'run-a','generation':1,
            'participant_id':'alice','policy_id':'policy-a','policy_version':1,'policy_digest':'b'*64,
            'gate_id':'gate-a','config_digest':'c'*64}
        with self.assertRaises(ArtifactError):targets.prepare(scope,self.resolve())
        admit.assert_not_called();self.assertEqual([],list(scratch.iterdir()))

    def test_capacity_admission_refuses_before_resource_effects(self):
        scratch=self.root/'scratch'; scratch.mkdir(mode=0o711)
        journals=self.root/'journals'; journals.mkdir(mode=0o700)
        targets=ArtifactTargets(scratch,journals,self.resolver,reserve_capacity=lambda *_:False)
        scope={'version':1,'evaluation_id':'evaluation-a','room_id':'room-a','room_instance':'a'*32,
            'project_id':'project-a','repository':'owner/repo','run_id':'run-a','generation':1,
            'participant_id':'alice','policy_id':'policy-a','policy_version':1,'policy_digest':'b'*64,
            'gate_id':'gate-a','config_digest':'c'*64}
        with self.assertRaises(ArtifactError):targets.prepare(scope,self.resolve())
        self.assertEqual([],list(scratch.iterdir()));self.assertEqual([],list(journals.iterdir()))
        self.assertEqual(32<<20,RESERVATION_BYTES)


if __name__ == '__main__': unittest.main()
