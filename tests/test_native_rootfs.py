"""Pure rootfs/archive contracts: no DNF, guest boot, container or installer runs."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('native_rootfs', Path(__file__).parent/'vm/native_rootfs.py')
rootfs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rootfs)


class NativeRootfsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.payload = self.directory/'payload'; self.payload.mkdir()
        self.root = self.directory/'image'; self.root.mkdir()
        self.items = {'opt/uas/bin/pi-connector': (b'fixed connector', 0o555),
                      'opt/uas/pi/package.json': (b'{"version":"1.4.0"}', 0o444)}
        self.native = self.make_payload()

    def make_payload(self, members=None, entries=None):
        archive_path = self.payload/'native-runtime.tar'
        with tarfile.open(archive_path, 'w', format=tarfile.PAX_FORMAT) as archive:
            for name, (content, mode) in self.items.items() if members is None else members:
                item = tarfile.TarInfo(name); item.size = len(content); item.mode = mode
                archive.addfile(item, io.BytesIO(content))
        files = [{'file': name, 'bytes': len(content), 'mode': mode,
                  'sha256': hashlib.sha256(content).hexdigest()}
                 for name, (content, mode) in self.items.items()] if entries is None else entries
        listing = self.payload/'native-files.json'
        listing.write_text(json.dumps({'version': 1, 'profile': 'native-pi-v1', 'files': files}))
        def asset(path):
            return {'file': path.name, 'bytes': path.stat().st_size, 'sha256': rootfs.digest(path)}
        return {**asset(archive_path), 'file_manifest': asset(listing), 'profile': 'native-pi-v1',
                'node_version': '24.22.1', 'pi_version': '1.4.0', 'rpm_roots': list(rootfs.ROOTS),
                'rpm_scriptlets': False, 'dependencies_reproducibly_pinned': False,
                'file_count': len(files), 'unpacked_bytes': sum(item['bytes'] for item in files)}

    def extract(self):
        archive, files = rootfs.verify_runtime(self.payload, self.native)
        rootfs.extract_runtime(archive, files, self.root)

    def test_exact_files_modes_and_final_fingerprint(self):
        self.extract()
        for name, (content, mode) in self.items.items():
            path = self.root/name
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
        first = rootfs.fingerprint(self.root)
        self.assertEqual(first, rootfs.fingerprint(self.root))
        (self.root/'opt/uas/pi/package.json').chmod(0o555)
        self.assertNotEqual(first['rootfs_manifest_sha256'], rootfs.fingerprint(self.root)['rootfs_manifest_sha256'])

    def test_asset_hash_failure_precedes_extraction(self):
        (self.payload/'native-runtime.tar').write_bytes(b'changed')
        with self.assertRaises(ValueError): self.extract()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_file_manifest_hash_failure_precedes_extraction(self):
        (self.payload/'native-files.json').write_text('{}')
        with self.assertRaises(ValueError): self.extract()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_manifest_traversal_absolute_and_noncanonical_paths(self):
        for name in ('../outside', '/opt/uas/file', 'opt/uas/../other', 'opt//uas/file', 'opt/uas/./file'):
            with self.subTest(name=name):
                self.native = self.make_payload(entries=[{'file':name,'bytes':0,'mode':0o444,
                                                         'sha256': hashlib.sha256(b'').hexdigest()}])
                with self.assertRaises(ValueError): rootfs.verify_runtime(self.payload, self.native)

    def test_manifest_duplicate_and_invalid_modes_rejected(self):
        entries = [{'file':'opt/uas/x','bytes':0,'mode':0o444,'sha256':hashlib.sha256(b'').hexdigest()}]
        for invalid in (entries*2, [{**entries[0], 'mode':0o4755}], [{**entries[0], 'mode':True}]):
            self.native = self.make_payload(entries=invalid)
            with self.assertRaises(ValueError): rootfs.verify_runtime(self.payload, self.native)

    def test_archive_extra_or_missing_files_rejected(self):
        for members in (list(self.items.items()) + [('opt/uas/extra',(b'x',0o444))],
                        list(self.items.items())[:1]):
            self.native = self.make_payload(members)
            with tempfile.TemporaryDirectory(dir=self.directory) as tmp:
                archive,files=rootfs.verify_runtime(self.payload,self.native)
                with self.assertRaises(ValueError): rootfs.extract_runtime(archive,files,Path(tmp))

    def test_archive_duplicate_and_changed_content_rejected(self):
        for members in ([list(self.items.items())[0]]*2,
                        [('opt/uas/bin/pi-connector',(b'wrong connector',0o555))]):
            self.native=self.make_payload(members)
            with tempfile.TemporaryDirectory(dir=self.directory) as tmp:
                archive,files=rootfs.verify_runtime(self.payload,self.native)
                with self.assertRaises(ValueError): rootfs.extract_runtime(archive,files,Path(tmp))

    def test_archive_symlink_hardlink_directory_and_special_rejected(self):
        for kind in (tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.DIRTYPE,tarfile.FIFOTYPE,tarfile.CHRTYPE):
            with self.subTest(kind=kind):
                self.native=self.make_payload()
                path=self.payload/'native-runtime.tar'
                with tarfile.open(path,'w') as archive:
                    item=tarfile.TarInfo('opt/uas/bin/pi-connector'); item.type=kind
                    item.mode=0o555; item.linkname='/outside' if kind in (tarfile.SYMTYPE,tarfile.LNKTYPE) else ''
                    archive.addfile(item)
                self.native.update(bytes=path.stat().st_size,sha256=rootfs.digest(path))
                with self.assertRaises(ValueError): self.extract()

    def test_concatenated_archive_rejected(self):
        path=self.payload/'native-runtime.tar'; data=path.read_bytes(); path.write_bytes(data+data)
        self.native.update(bytes=path.stat().st_size,sha256=rootfs.digest(path))
        with self.assertRaisesRegex(ValueError,'trailer'): self.extract()

    def test_preexisting_symlink_parent_or_file_is_not_followed(self):
        outside=self.directory/'outside'; outside.mkdir()
        (self.root/'opt').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError): self.extract()
        self.assertEqual(list(outside.iterdir()), [])

    def test_payload_symlink_or_hardlink_is_rejected(self):
        path=self.payload/'native-runtime.tar'; other=self.directory/'archive'; path.rename(other)
        path.symlink_to(other)
        with self.assertRaises(ValueError): self.extract()
        path.unlink(); os.link(other,path)
        with self.assertRaises(ValueError): self.extract()

    def test_rpm_usrmerge_absolute_and_relative_links_are_root_relative(self):
        (self.root/'usr/bin').mkdir(parents=True); (self.root/'usr/bin/tool').write_text('tool')
        (self.root/'bin').symlink_to('usr/bin',target_is_directory=True)
        (self.root/'tool').symlink_to('/bin/tool')
        self.assertEqual(rootfs.resolve_inside(self.root,'tool'),self.root/'usr/bin/tool')
        result=rootfs.fingerprint(self.root)
        self.assertEqual([item['target'] for item in result['manifest']['entries'] if item['kind']=='symlink'],
                         ['usr/bin','/bin/tool'])

    def test_escaping_dangling_and_cyclic_rpm_links_rejected(self):
        for target in ('../../outside', '/../../outside', '/missing', 'link'):
            link=self.root/'link';link.symlink_to(target)
            with self.assertRaises((ValueError,FileNotFoundError)): rootfs.fingerprint(self.root)
            link.unlink()

    def test_external_hardlink_and_special_rootfs_rejected(self):
        outside=self.directory/'external';outside.write_text('content')
        os.link(outside,self.root/'link')
        with self.assertRaisesRegex(ValueError,'hardlink'):rootfs.fingerprint(self.root)
        (self.root/'link').unlink();os.mkfifo(self.root/'fifo')
        with self.assertRaisesRegex(ValueError,'special'):rootfs.fingerprint(self.root)

    def test_build_uses_only_offline_noscript_solver_and_external_manifest(self):
        destination=self.directory/'built';calls=[]
        def fake_run(*args,timeout,native_failure_context=False):
            if args[0] == 'rpm':
                return 'rpm-0:6.0.2-1.fc44.x86_64\n'
            rootfs.require_usrmerge(destination)
            self.assertTrue(native_failure_context)
            calls.append((args,timeout))
            destination.chmod(0o700)  # restrictive installer/umask must not survive import
            (destination/'usr/bin').mkdir(parents=True)
            (destination/'usr/bin/tini').write_bytes(b'packaged tini')
            (destination/'usr/bin/tini').chmod(0o555)
        with patch.object(rootfs,'guest_guard') as guard, patch.object(rootfs,'PAYLOAD',self.payload):
            result=rootfs.build_rootfs('a'*32,{'native_runtime':self.native},destination,run=fake_run)
        guard.assert_called_once_with('a'*32)
        args,timeout=calls[0]
        self.assertEqual(len(calls),1)
        for required in ('--disablerepo=*','--enablerepo=uas-native','--setopt=tsflags=noscripts',
                         '--setopt=plugins=False','--setopt=install_weak_deps=False','--setopt=uas-native.gpgcheck=1'):
            self.assertIn(required,args)
        self.assertEqual(args[-4:],rootfs.ROOTS)
        self.assertNotIn('manifest',result)
        self.assertLess(len(json.dumps(result)),2048)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode),0o755)
        self.assertEqual(json.loads(Path(result['rootfs_manifest']).read_text())['root_mode'],0o755)
        self.assertFalse(Path(result['rootfs_manifest']).is_relative_to(destination))
        self.assertEqual(rootfs.digest(Path(result['rootfs_manifest'])),result['rootfs_manifest_sha256'])
        self.assertEqual((destination/'opt/uas/bin/tini').read_bytes(),b'packaged tini')

    def test_exact_runtime_mtab_link_allowed_without_host_proc_following(self):
        (self.root/'etc').mkdir()
        link=self.root/'etc/mtab';link.symlink_to('../proc/self/mounts')
        result=rootfs.fingerprint(self.root)
        entry=next(x for x in result['manifest']['entries'] if x['path']=='etc/mtab')
        self.assertEqual(entry['target'],'../proc/self/mounts')
        for target in ('../../proc/self/mounts','../proc/self/status','/proc/self/mounts'):
            link.unlink();link.symlink_to(target)
            with self.assertRaises((ValueError,FileNotFoundError)):rootfs.fingerprint(self.root)
        link.unlink();link.symlink_to('../proc/self/mounts')
        (self.root/'proc').symlink_to('/elsewhere')
        with self.assertRaises(FileNotFoundError):rootfs.fingerprint(self.root)

    def test_guest_guard_denies_local_call_before_install(self):
        with patch.object(rootfs.os,'geteuid',return_value=1000):
            with self.assertRaises(RuntimeError):rootfs.guest_guard('a'*32)


if __name__=='__main__':unittest.main()
