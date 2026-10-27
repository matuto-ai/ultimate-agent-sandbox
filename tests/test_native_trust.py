"""Pure generation-contract tests: all RPM and chroot commands are mocked."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / 'vm'))
import native_trust as trust


class NativeTrustTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        for key in (*trust.CA_OUTPUTS,trust.FIPS_OUTPUT):
            (self.root/key).parent.mkdir(parents=True,exist_ok=True)
        for path in trust.VERIFIED_INPUTS:
            target=self.root/path;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(('signed fixture '+path).encode());target.chmod(0o755 if path.startswith('usr/bin') else 0o644)
        self.commands=[];self.mutation=None;self.header_mutation=None

    def fake_run(self,*args,**kwargs):
        self.commands.append((args,kwargs))
        if args[0]=='rpm':
            self.assertEqual(args[:3],('rpm','--root',str(self.root)))
            key=args[4].lstrip('/');path=self.root/key
            owner=trust.VERIFIED_INPUTS[key]
            text=owner+'\t0:1.0-1.fc44.x86_64\t8\n/'+key+'\t'+str(path.stat().st_mode)+'\t'+hashlib.sha256(path.read_bytes()).hexdigest()+'\n'
            return self.header_mutation(text) if self.header_mutation else text
        self.assertIn(args,trust.fixed_commands(self.root))
        self.assertEqual(kwargs,{'timeout':90,'native_trust_context':True})
        number=trust.fixed_commands(self.root).index(args)
        if number==0:(self.root/trust.FIPS_OUTPUT).write_bytes(b'generated DEFAULT fips backend')
        else:(self.root/trust.CA_OUTPUTS[number-1]).write_bytes(b'generated signed trust bundle')
        if self.mutation:self.mutation(number)
        return ''

    def generate(self):return trust.generate_trust(self.root,run=self.fake_run)

    def test_exact_four_commands_outputs_and_bounded_evidence(self):
        evidence=self.generate()
        calls=[args for args,kwargs in self.commands if args[0]=='/usr/bin/chroot']
        self.assertEqual(tuple(calls),trust.fixed_commands(self.root))
        self.assertEqual(len(calls),4)
        for args in calls:
            self.assertEqual(args[:4],('/usr/bin/chroot',str(self.root),'/usr/bin/env','-i'))
            self.assertIn('P11_KIT_NO_USER_CONFIG=1',args)
            self.assertIn('HOME=/nonexistent',args)
        self.assertIn('--no-reload',calls[0]);self.assertIn('-B',calls[0])
        self.assertEqual(evidence['policy'],'DEFAULT');self.assertFalse(evidence['package_scriptlets'])
        self.assertEqual(len(evidence['verified_inputs']),6);self.assertEqual(len(evidence['outputs']),4)
        self.assertLess(len(json.dumps(evidence)),8192)
        self.assertNotEqual(evidence['before']['sha256'],evidence['after']['sha256'])

    def test_python_entrypoint_is_fixed_and_independently_verified(self):
        evidence=self.generate()
        command=trust.fixed_commands(self.root)[0]
        entry='usr/share/crypto-policies/python/update-crypto-policies.py'
        self.assertIn('/'+entry,command)
        self.assertNotIn('/usr/bin/update-crypto-policies',command)
        self.assertNotIn('/bin/sh',command)
        inputs={row['path']:row for row in evidence['verified_inputs']}
        self.assertIn('usr/bin/update-crypto-policies',inputs)
        self.assertTrue(inputs[entry]['owner'].startswith('crypto-policies-scripts-'))
        self.assertEqual(inputs[entry]['sha256'],hashlib.sha256((self.root/entry).read_bytes()).hexdigest())

    def test_python_entrypoint_header_mismatch_prevents_any_execution(self):
        entry='usr/share/crypto-policies/python/update-crypto-policies.py'
        def corrupt(text):
            return text.replace('crypto-policies-scripts\t','wrong-owner\t') if '/'+entry+'\t' in text else text
        self.header_mutation=corrupt
        with self.assertRaisesRegex(ValueError,'owner'):self.generate()
        self.assertFalse(any(args[0]=='/usr/bin/chroot' for args,kwargs in self.commands))

    def test_existing_output_file_directory_or_symlink_denied_before_commands(self):
        output=self.root/trust.CA_OUTPUTS[0]
        for kind in ('file','directory','symlink'):
            with self.subTest(kind=kind):
                if kind=='file':output.write_bytes(b'existing')
                elif kind=='directory':output.mkdir()
                else:output.symlink_to('absent')
                with self.assertRaisesRegex(ValueError,'fresh'):self.generate()
                self.assertEqual(self.commands,[])
                output.rmdir() if kind=='directory' else output.unlink()

    def test_owner_algorithm_digest_and_mode_mismatch_prevents_generation(self):
        mutations=[lambda s:s.replace('coreutils\t','other\t'),lambda s:s.replace('\t8\n','\t1\n'),
                   lambda s:s[:-65]+'0'*64+'\n',lambda s:s.replace('\t33261\t','\t33188\t')]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.commands=[];self.header_mutation=mutation
                with self.assertRaises(ValueError):self.generate()
                self.assertFalse(any(args[0]=='/usr/bin/chroot' for args,kwargs in self.commands))

    def test_unexpected_content_permissions_and_link_changes_fail(self):
        target=self.root/'usr/bin/trust'
        for mutation in ('bytes','mode','link'):
            with self.subTest(mutation=mutation):
                original=target.read_bytes();mode=target.stat().st_mode & 0o777
                def change(number):
                    if number==3:
                        if mutation=='bytes':target.write_bytes(b'changed')
                        elif mutation=='mode':target.chmod(0o700)
                        else:target.unlink();target.symlink_to('other')
                self.mutation=change
                with self.assertRaisesRegex(ValueError,'unexpected trust generation changes'):self.generate()
                if target.is_symlink():target.unlink()
                target.write_bytes(original);target.chmod(mode)
                for key in trust.CA_OUTPUTS:(self.root/key).unlink()

    def test_command_failure_still_inventories_changes_and_preserves_original(self):
        def fail(number):
            (self.root/'outside-allowed-subtree').write_bytes(b'unexpected')
            raise RuntimeError('original command failure')
        self.mutation=fail
        with self.assertRaisesRegex(RuntimeError,'original command failure') as caught:self.generate()
        self.assertIn('unexpected trust generation changes',' '.join(caught.exception.__notes__))
        self.assertEqual(sum(args[0]=='/usr/bin/chroot' for args,kwargs in self.commands),1)

    def test_empty_output_and_escaping_backend_fail_closed(self):
        def empty(number):
            if number==3:(self.root/trust.CA_OUTPUTS[1]).write_bytes(b'')
        self.mutation=empty
        with self.assertRaisesRegex(ValueError,'empty generated trust output'):self.generate()
        for key in trust.CA_OUTPUTS:(self.root/key).unlink()
        def escape(number):
            if number==3:
                p=self.root/trust.FIPS_OUTPUT;p.unlink();p.symlink_to('../../../../outside')
        self.mutation=escape
        with self.assertRaises((ValueError,FileNotFoundError)):self.generate()

    def test_special_file_rejected_before_queries(self):
        os.mkfifo(self.root/'fifo')
        with self.assertRaisesRegex(ValueError,'special file'):self.generate()
        self.assertEqual(self.commands,[])

    def test_root_alias_and_redirected_output_parent_rejected(self):
        alias=self.root/'alias';alias.symlink_to(self.root)
        with self.assertRaisesRegex(ValueError,'canonical'):trust.generate_trust(alias,run=self.fake_run)
        alias.unlink()
        parent=(self.root/trust.CA_OUTPUTS[0]).parent
        parent.rmdir();parent.symlink_to('/tmp')
        with self.assertRaises((ValueError,FileNotFoundError)):self.generate()
        self.assertEqual(self.commands,[])

    def test_directory_timestamps_ignored_but_uid_gid_modes_not(self):
        before,_=trust._snapshot(self.root)
        os.utime(self.root/'usr',ns=(1,1))
        after,_=trust._snapshot(self.root)
        self.assertEqual(trust._check_changes(before,after),[])
        for field in ('mode','uid','gid'):
            changed={key:dict(value) for key,value in after.items()}
            changed['usr'][field]+=1
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'unexpected'):
                trust._check_changes(before,changed)

    def test_generated_ca_symlink_not_accepted_as_ordinary_output(self):
        def replace(number):
            if number==3:
                path=self.root/trust.CA_OUTPUTS[0]
                path.unlink();path.symlink_to('../pem/tls-ca-bundle.pem')
        self.mutation=replace
        with self.assertRaisesRegex(ValueError,'CA output is not ordinary'):self.generate()

    def test_backend_symlink_to_packaged_inroot_policy_is_recorded_resolved(self):
        policy=self.root/'usr/share/crypto-policies/default-fips/openssl.txt'
        policy.parent.mkdir(parents=True);policy.write_bytes(b'packaged policy fixture')
        def link(number):
            if number==3:
                path=self.root/trust.FIPS_OUTPUT
                path.unlink();path.symlink_to('/usr/share/crypto-policies/default-fips/openssl.txt')
        self.mutation=link
        result=self.generate()
        fips=result['outputs'][-1]
        self.assertEqual(fips['resolved_path'],'usr/share/crypto-policies/default-fips/openssl.txt')
        self.assertEqual(fips['sha256'],hashlib.sha256(policy.read_bytes()).hexdigest())

    def test_missing_output_parent_rejected_before_header_queries(self):
        (self.root/trust.CA_OUTPUTS[0]).parent.rmdir()
        with self.assertRaises(FileNotFoundError):self.generate()
        self.assertEqual(self.commands,[])

    def test_fips_and_ca_escape_or_loop_outputs_rejected(self):
        for key in (trust.CA_OUTPUTS[0],trust.FIPS_OUTPUT):
            for target in ('../../../../../../outside',Path(key).name):
                with self.subTest(path=key,target=target):
                    def change(number):
                        if number==3:
                            path=self.root/key;path.unlink();path.symlink_to(target)
                    self.mutation=change
                    with self.assertRaises((ValueError,FileNotFoundError)):self.generate()
                    for output in trust.CA_OUTPUTS:(self.root/output).unlink()
                    fips=self.root/trust.FIPS_OUTPUT
                    if fips.is_symlink():fips.unlink()

    def test_mutation_error_reports_total_and_truncation(self):
        before={'unchanged':{'kind':'file'}}
        after={**before,**{'unexpected-'+str(i):{'kind':'file'} for i in range(21)}}
        with self.assertRaises(ValueError) as caught:trust._check_changes(before,after)
        value=json.loads(str(caught.exception).split(': ',1)[1])
        self.assertEqual(value['changed_count'],21)
        self.assertEqual(value['forbidden_count'],21)
        self.assertTrue(value['truncated']);self.assertEqual(len(value['paths']),16)

    def test_root_or_output_parent_mode_changes_not_allowed(self):
        for key in ('.',str(Path(trust.CA_OUTPUTS[0]).parent)):
            with self.subTest(path=key):
                path=self.root/key;original=path.stat().st_mode & 0o777
                def change(number):
                    if number==3:path.chmod(original ^ 0o020)
                self.mutation=change
                with self.assertRaisesRegex(ValueError,'unexpected trust generation changes'):self.generate()
                path.chmod(original)
                for output in trust.CA_OUTPUTS:(self.root/output).unlink()

    def test_snapshot_directory_read_error_fails_before_generation(self):
        def walk(*args,**kwargs):
            self.assertFalse(kwargs['followlinks'])
            kwargs['onerror'](PermissionError('scandir denied'))
            return iter(())
        with patch.object(trust.os,'walk',side_effect=walk):
            with self.assertRaisesRegex(PermissionError,'scandir denied'):self.generate()
        self.assertEqual(self.commands,[])

    def test_snapshot_symlink_target_byte_budget(self):
        (self.root/'link').symlink_to('absent')
        with patch.object(trust.os,'readlink',return_value='é'*2049):
            with self.assertRaisesRegex(ValueError,'link target exceeds bound'):trust._snapshot(self.root)


if __name__=='__main__':unittest.main()
