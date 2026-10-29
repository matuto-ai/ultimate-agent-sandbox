"""Pure materialization/generation contracts: RPM and CA commands are mocked."""
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
        for key in (*trust.CA_OUTPUTS,*trust.POLICY_OUTPUTS):
            (self.root/key).parent.mkdir(parents=True,exist_ok=True)
        for path in trust.VERIFIED_INPUTS:
            target=self.root/path;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(('signed fixture '+path).encode());target.chmod(0o755 if path.startswith('usr/bin') else 0o644)
        for path in trust.POLICY_ASSETS.values():
            target=self.root/path;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(('packaged DEFAULT '+path).encode());target.chmod(0o644)
        self.default_data=b'# Packaged comments are retained for config only.\nDEFAULT\n'
        (self.root/trust.DEFAULT_CONFIG).write_bytes(self.default_data)
        (self.root/trust.DEFAULT_CONFIG).chmod(0o644)
        self.commands=[];self.mutation=None;self.header_mutation=None;self.policy_header_mutation=None
        self.policy_header=self.make_policy_header()

    def make_policy_header(self):
        rows=['crypto-policies\t0:20251128-3.git19878fe.fc44.noarch\t8']
        for path in (*trust.POLICY_ASSETS.values(),trust.DEFAULT_CONFIG):
            p=self.root/path
            rows.append('/'+path+'\t'+str(p.stat().st_mode)+'\t0\t'+hashlib.sha256(p.read_bytes()).hexdigest()+'\t')
        for path in trust.POLICY_OUTPUTS:
            link=trust.POLICY_LINKS.get(path,'')
            rows.append('/'+path+'\t'+str(0o120777 if link else 0o100644)+'\t'+str(64 if path==trust.POLICY_CURRENT else 89)+'\t\t'+link)
        return '\n'.join(rows)+'\n'

    def clear_outputs(self):
        for key in (*trust.CA_OUTPUTS,*trust.POLICY_OUTPUTS):
            path=self.root/key
            if path.exists() or path.is_symlink():path.unlink()

    def fake_run(self,*args,**kwargs):
        self.commands.append((args,kwargs))
        if args[0]=='rpm':
            self.assertEqual(args[:3],('rpm','--root',str(self.root)))
            if args[3]=='-q':
                self.assertEqual(args[4],'--qf');self.assertEqual(args[-1],'crypto-policies')
                return self.policy_header_mutation(self.policy_header) if self.policy_header_mutation else self.policy_header
            key=args[4].lstrip('/');path=self.root/key
            owner=trust.VERIFIED_INPUTS[key]
            text=owner+'\t0:1.0-1.fc44.x86_64\t8\n/'+key+'\t'+str(path.stat().st_mode)+'\t'+hashlib.sha256(path.read_bytes()).hexdigest()+'\n'
            return self.header_mutation(text) if self.header_mutation else text
        self.assertIn(args,trust.fixed_commands(self.root))
        self.assertEqual(kwargs,{'timeout':90,'native_trust_context':True})
        number=trust.fixed_commands(self.root).index(args)
        (self.root/trust.CA_OUTPUTS[number]).write_bytes(b'generated signed trust bundle')
        if self.mutation:self.mutation(number)
        return ''

    def generate(self):return trust.generate_trust(self.root,run=self.fake_run)

    def test_exact_three_commands_outputs_and_bounded_evidence(self):
        evidence=self.generate()
        calls=[args for args,kwargs in self.commands if args[0]=='/usr/bin/chroot']
        self.assertEqual(tuple(calls),trust.fixed_commands(self.root))
        self.assertEqual(len(calls),3)
        for args in calls:
            self.assertEqual(args[:4],('/usr/bin/chroot',str(self.root),'/usr/bin/env','-i'))
            self.assertIn('P11_KIT_NO_USER_CONFIG=1',args)
            self.assertIn('HOME=/nonexistent',args)
        self.assertTrue(all('/usr/bin/trust' in args for args in calls))
        self.assertEqual(evidence['policy'],'DEFAULT');self.assertFalse(evidence['package_scriptlets'])
        self.assertEqual(len(evidence['verified_inputs']),3);self.assertEqual(len(evidence['outputs']),4)
        self.assertLess(len(json.dumps(evidence)),8192)
        self.assertNotEqual(evidence['before']['sha256'],evidence['after']['sha256'])
        self.assertEqual(evidence['changed_count'],18)

    def test_signed_default_assets_and_exact_config_state_are_materialized(self):
        evidence=self.generate()
        policy=evidence['policy_materialization']
        self.assertFalse(policy['updater_executed']);self.assertFalse(policy['current_pol_created'])
        self.assertEqual(set(policy['backend_inputs']),set(trust.POLICY_BACKENDS))
        self.assertEqual(policy['ghost_destination_count'],15)
        self.assertEqual((self.root/trust.POLICY_CONFIG).read_bytes(),self.default_data)
        self.assertEqual((self.root/trust.POLICY_CURRENT).read_bytes(),b'DEFAULT\n')
        self.assertFalse((self.root/'etc/crypto-policies/state/CURRENT.pol').exists())
        for key,target in trust.POLICY_LINKS.items():self.assertEqual(os.readlink(self.root/key),target)
        self.assertTrue(evidence['before']['internal_hardlinks_verified'])
        self.assertFalse(any('update-crypto-policies' in str(args) or '/bin/sh' in args or 'mount' in args for args,kwargs in self.commands))

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
                    if number==2:
                        if mutation=='bytes':target.write_bytes(b'changed')
                        elif mutation=='mode':target.chmod(0o700)
                        else:target.unlink();target.symlink_to('other')
                self.mutation=change
                with self.assertRaisesRegex(ValueError,'unexpected trust generation changes'):self.generate()
                if target.is_symlink():target.unlink()
                target.write_bytes(original);target.chmod(mode)
                self.clear_outputs()

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
            if number==2:(self.root/trust.CA_OUTPUTS[1]).write_bytes(b'')
        self.mutation=empty
        with self.assertRaisesRegex(ValueError,'empty generated trust output'):self.generate()
        self.clear_outputs()
        def escape(number):
            if number==2:
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
            if number==2:
                path=self.root/trust.CA_OUTPUTS[0]
                path.unlink();path.symlink_to('../pem/tls-ca-bundle.pem')
        self.mutation=replace
        with self.assertRaisesRegex(ValueError,'CA output is not ordinary'):self.generate()

    def test_packaged_backend_internal_hardlinks_are_proved_and_recorded(self):
        name='openssl_fips';path=self.root/trust.POLICY_ASSETS[name]
        alias=self.root/'usr/share/crypto-policies/back-ends/DEFAULT/openssl_fips.config'
        alias.parent.mkdir(parents=True);os.link(path,alias)
        result=self.generate()
        self.assertEqual(result['policy_materialization']['backend_inputs'][name]['links'],2)
        fips=result['outputs'][-1]
        self.assertEqual(fips['resolved_path'],trust.POLICY_ASSETS[name])
        self.assertEqual(fips['sha256'],hashlib.sha256(path.read_bytes()).hexdigest())

    def test_missing_output_parent_rejected_before_header_queries(self):
        (self.root/trust.CA_OUTPUTS[0]).parent.rmdir()
        with self.assertRaises(FileNotFoundError):self.generate()
        self.assertEqual(self.commands,[])

    def test_fips_and_ca_escape_or_loop_outputs_rejected(self):
        for key in (trust.CA_OUTPUTS[0],trust.FIPS_OUTPUT):
            for target in ('../../../../../../outside',Path(key).name):
                with self.subTest(path=key,target=target):
                    def change(number):
                        if number==2:
                            path=self.root/key;path.unlink();path.symlink_to(target)
                    self.mutation=change
                    with self.assertRaises((ValueError,FileNotFoundError)):self.generate()
                    self.clear_outputs()
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
                    if number==2:path.chmod(original ^ 0o020)
                self.mutation=change
                with self.assertRaisesRegex(ValueError,'unexpected trust generation changes'):self.generate()
                path.chmod(original)
                self.clear_outputs()

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

    def test_all_policy_outputs_must_be_fresh_files_directories_or_links_refused(self):
        for key in trust.POLICY_OUTPUTS:
            for kind in ('file','directory','symlink'):
                path=self.root/key
                with self.subTest(path=key,kind=kind):
                    if kind=='file':path.write_bytes(b'existing')
                    elif kind=='directory':path.mkdir()
                    else:path.symlink_to('absent')
                    with self.assertRaisesRegex(ValueError,'fresh'):self.generate()
                    self.assertEqual(self.commands,[])
                    path.rmdir() if kind=='directory' else path.unlink()

    def test_policy_owner_algorithm_missing_duplicate_and_extra_asset_headers_refused(self):
        lines=self.policy_header.splitlines(keepends=True)
        extra='/usr/share/crypto-policies/DEFAULT/extra.txt\t33188\t0\t'+'a'*64+'\t\n'
        mutations=[lambda s:s.replace('crypto-policies\t','wrong-owner\t'),
                   lambda s:s.replace('\t8\n','\t1\n'),
                   lambda s:s.replace(lines[1],''),lambda s:s+lines[1],lambda s:s+extra,
                   lambda s:s.replace('.noarch\t','.x86_64\t')]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.policy_header_mutation=mutation;self.commands=[]
                with self.assertRaises(ValueError):self.generate()
                self.assertFalse(any(args[0]=='/usr/bin/chroot' for args,kwargs in self.commands))
                self.assertFalse(any((self.root/key).exists() or (self.root/key).is_symlink() for key in trust.POLICY_OUTPUTS))

    def test_each_policy_ghost_has_exact_mode_flags_target_and_no_digest(self):
        original=self.policy_header
        for key in trust.POLICY_OUTPUTS:
            line=next(row for row in original.splitlines() if row.startswith('/'+key+'\t'))
            for index,value in ((1,'33152'),(2,'0'),(3,'a'*64),(4,'/wrong-target')):
                with self.subTest(path=key,field=index):
                    fields=line.split('\t');fields[index]=value
                    self.policy_header=original.replace(line+'\n','\t'.join(fields)+'\n')
                    with self.assertRaisesRegex(ValueError,'ghost destination'):self.generate()
        self.policy_header=original

    def test_policy_asset_bytes_mode_and_symlink_substitution_refused(self):
        path=self.root/trust.POLICY_ASSETS['openssl_fips'];data=path.read_bytes()
        for mutation in ('bytes','mode','link','empty','oversized'):
            with self.subTest(mutation=mutation):
                if mutation=='bytes':path.write_bytes(b'changed')
                elif mutation=='mode':path.chmod(0o600)
                elif mutation=='empty':path.write_bytes(b'')
                elif mutation=='oversized':path.write_bytes(b'x'*(trust.MAX_POLICY_BYTES+1))
                else:path.unlink();path.symlink_to('gnutls.txt')
                with self.assertRaisesRegex(ValueError,'policy asset'):self.generate()
                if path.is_symlink():path.unlink()
                path.write_bytes(data);path.chmod(0o644)

    def test_default_config_must_have_one_DEFAULT_directive_not_policy_content(self):
        path=self.root/trust.DEFAULT_CONFIG
        for content in (b'LEGACY\n',b'# DEFAULT only in comment\n',b'DEFAULT\nDEFAULT\n',b'DEFAULT:NO-SHA1\n'):
            with self.subTest(content=content):
                path.write_bytes(content);self.policy_header=self.make_policy_header()
                with self.assertRaisesRegex(ValueError,'select only DEFAULT'):self.generate()
                self.assertFalse(any((self.root/key).exists() for key in trust.POLICY_OUTPUTS))

    def test_extra_actual_policy_asset_refused_even_if_not_in_header(self):
        (self.root/'usr/share/crypto-policies/DEFAULT/unlisted.txt').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError,'asset directory'):self.generate()

    def test_external_hardlink_refused_before_any_package_query(self):
        with tempfile.TemporaryDirectory() as outside:
            os.link(self.root/trust.POLICY_ASSETS['openssl_fips'],Path(outside)/'external')
            with self.assertRaisesRegex(ValueError,'external hardlink'):self.generate()
            self.assertEqual(self.commands,[])

    def test_internal_tool_hardlinks_still_refused(self):
        os.link(self.root/'usr/bin/trust',self.root/'usr/bin/trust-alias')
        with self.assertRaisesRegex(ValueError,'ordinary unlinked'):self.generate()

    def test_inventory_cannot_authorize_new_hardlinks_added_during_query(self):
        def changed(text):
            os.link(self.root/trust.POLICY_ASSETS['openssl_fips'],self.root/'late-alias')
            return text
        self.policy_header_mutation=changed
        with self.assertRaisesRegex(ValueError,'policy asset'):self.generate()

    def test_mutations_elsewhere_in_crypto_subtree_are_not_permitted(self):
        for key in ('etc/crypto-policies/unexpected','etc/crypto-policies/state/CURRENT.pol'):
            with self.subTest(path=key):
                def change(number):
                    if number==2:(self.root/key).write_bytes(b'unexpected')
                self.mutation=change
                with self.assertRaisesRegex(ValueError,'unexpected trust generation changes'):self.generate()
                (self.root/key).unlink();self.clear_outputs()

    def test_allowed_policy_outputs_cannot_be_changed_to_another_valid_inroot_shape(self):
        for key in (trust.POLICY_CONFIG,trust.POLICY_CURRENT,trust.FIPS_OUTPUT):
            with self.subTest(path=key):
                def change(number):
                    if number==2:
                        path=self.root/key
                        if key in trust.POLICY_LINKS:
                            path.unlink();path.symlink_to('/'+trust.POLICY_ASSETS['gnutls'])
                        else:path.write_bytes(b'LEGACY\n')
                self.mutation=change
                with self.assertRaisesRegex(ValueError,'materialized policy'):self.generate()
                self.clear_outputs()

    def test_partial_materialization_failure_keeps_inventory_and_never_runs_CA(self):
        original=Path.symlink_to
        def fail(path,*args,**kwargs):
            if str(path).endswith('/back-ends/java.config'):raise OSError('partial materialization')
            return original(path,*args,**kwargs)
        with patch.object(Path,'symlink_to',fail):
            with self.assertRaisesRegex(OSError,'partial materialization') as caught:self.generate()
        self.assertIn('changed_count',' '.join(caught.exception.__notes__))
        self.assertFalse(any(args[0]=='/usr/bin/chroot' for args,kwargs in self.commands))




class NativePublicCAValidationTests(unittest.TestCase):
    """Real offline SSL code-path tests; public fixture is NOT Fedora trust proof."""
    def test_real_public_fixture_load_and_empty_malformed_fail_closed(self):
        import ssl
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / trust.CA_OUTPUTS[1]
            target.parent.mkdir(parents=True)
            public = Path(__file__).parent / 'fixtures/public-isrg-root-x1.pem'
            data = public.read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(),
                '22b557a27055b33606b6559f37703928d3e4ad79f110b407d04986e1843543d1')
            target.write_bytes(data)
            receipt = trust.validate_public_ca(root)
            self.assertEqual('passed', receipt['status'])
            self.assertEqual(1, receipt['ca_anchors'])
            self.assertTrue(receipt['certificate_required'])
            self.assertTrue(receipt['hostname_check'])
            self.assertEqual('offline-native-SSL-load-only', receipt['scope'])
            for bad in (b'', b'not a PEM bundle'):
                target.write_bytes(bad)
                with self.assertRaises((ValueError, ssl.SSLError)):
                    trust.validate_public_ca(root)
            target.unlink()
            with self.assertRaises((ValueError, FileNotFoundError)):
                trust.validate_public_ca(root)


class PublicCAContractTests(unittest.TestCase):
    def test_exact_path_no_fallback_and_verification_or_anchor_failures(self):
        import ssl
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); target = root / trust.CA_OUTPUTS[1]
            target.parent.mkdir(parents=True); target.write_bytes(b'mocked parse input')
            context = Mock(verify_mode=ssl.CERT_REQUIRED, check_hostname=True)
            context.cert_store_stats.return_value = {'x509_ca': 1}
            with patch.object(ssl, 'create_default_context', return_value=context) as create:
                trust.validate_public_ca(root)
                create.assert_called_once_with(cafile=str(target))
            for field, bad in [('verify_mode', ssl.CERT_NONE), ('check_hostname', False)]:
                original = getattr(context, field); setattr(context, field, bad)
                with patch.object(ssl, 'create_default_context', return_value=context):
                    with self.assertRaises(ValueError): trust.validate_public_ca(root)
                setattr(context, field, original)
            context.cert_store_stats.return_value = {'x509_ca': 0}
            with patch.object(ssl, 'create_default_context', return_value=context):
                with self.assertRaises(ValueError): trust.validate_public_ca(root)
            with patch.object(ssl, 'create_default_context', side_effect=ssl.SSLError('synthetic')) as create:
                with self.assertRaises(ssl.SSLError): trust.validate_public_ca(root)
                create.assert_called_once_with(cafile=str(target))

if __name__=='__main__':unittest.main()
