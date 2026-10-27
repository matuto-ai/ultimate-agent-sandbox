"""Native-only exact RPM roots; all package/daemon commands are mocked."""
from copy import deepcopy
from contextlib import ExitStack
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('exact_native_guest_boundary',Path(__file__).parent/'vm/guest_boundary.py')
boundary=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(boundary)
NONCE='a'*32
PROFILE={'moby-engine':('0','29.8.2','2.fc44','x86_64'),
         'container-selinux':('4','2.251.0','1.fc44','noarch')}


class NativePackageProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.marker=self.root/'boot';self.marker.write_text(NONCE)
        self.net=self.root/'net';self.net.mkdir();(self.net/'lo').mkdir()
        self.manifest={'profile':'native-pi-v1','packages':[{'name':name,'epoch':epoch,'version':version,'release':release,
            'arch':arch,'file':name+'.rpm'} for name,(epoch,version,release,arch) in PROFILE.items()]}
        self.installed={'moby-engine':'0:29.8.2-2.fc44.x86_64',
                        'container-selinux':'4:2.247.0-1.fc44.noarch'}
        self.commands=[]
        self.upgrade=True

    def mapped_path(self,value):
        if value=='/run/uas-vm-fixture':return self.marker
        if value=='/run/uas-repositories':return self.root/'repositories'
        if value=='/sys/class/net':return self.net
        if str(value).startswith('/etc/'):
            result=self.root/str(value).lstrip('/')
            result.parent.mkdir(parents=True,exist_ok=True)
            return result
        return Path(value)

    def fake_run(self,*arguments,**kwargs):
        self.commands.append(arguments)
        if arguments[0]=='getenforce':return 'Enforcing\n'
        if arguments[0]=='dnf' and self.upgrade:
            for name,values in PROFILE.items():
                epoch,version,release,arch=values
                if name+'-'+epoch+':'+version+'-'+release+'.'+arch in arguments:
                    self.installed[name]=epoch+':'+version+'-'+release+'.'+arch
        if arguments[0]=='rpm' and '-q' in arguments:
            self.assertIn('%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n',arguments)
            return self.installed[arguments[-1]]+'\n'
        return ''

    def mocks(self):
        stack=ExitStack()
        stack.enter_context(patch.object(boundary,'Path',side_effect=self.mapped_path))
        stack.enter_context(patch.object(boundary,'PAYLOAD',self.root/'payload'))
        stack.enter_context(patch.object(boundary.os,'geteuid',return_value=0))
        stack.enter_context(patch.object(boundary,'run',side_effect=self.fake_run))
        return stack

    def test_explicit_native_roots_upgrade_preinstalled_older_signed_policy(self):
        self.assertEqual(self.installed['container-selinux'],'4:2.247.0-1.fc44.noarch')
        with self.mocks():boundary.install_packages(NONCE,self.manifest,exact_roots=PROFILE)
        dnf=next(args for args in self.commands if args[0]=='dnf')
        expected=tuple(name+'-'+':'.join((PROFILE[name][0],PROFILE[name][1]))+'-'+PROFILE[name][2]+'.'+PROFILE[name][3]
                       if name in PROFILE else name for name in boundary.REQUIRED_PACKAGES)
        self.assertEqual(dnf[dnf.index('install')+1:],expected)
        self.assertEqual(self.installed['container-selinux'],'4:2.251.0-1.fc44.noarch')
        self.assertIn('--disable-repo=*',dnf);self.assertIn('--enable-repo=uas-offline',dnf)
        self.assertNotIn('--nogpgcheck',dnf);self.assertNotIn('--allowerasing',dnf)
        queries=[args for args in self.commands if args[0]=='rpm']
        self.assertEqual({args[-1] for args in queries},set(PROFILE))
        self.assertTrue(all(self.commands.index(args)>self.commands.index(dnf) for args in queries))

    def test_default_static_profile_keeps_original_name_only_roots_and_no_exact_queries(self):
        with self.mocks():boundary.install_packages(NONCE,{'packages':[{'file':'legacy.rpm'}]})
        dnf=next(args for args in self.commands if args[0]=='dnf')
        self.assertEqual(dnf[dnf.index('install')+1:],boundary.REQUIRED_PACKAGES)
        self.assertFalse(any(args[0]=='rpm' for args in self.commands))
        self.assertEqual(self.installed['container-selinux'],'4:2.247.0-1.fc44.noarch')

    def test_missing_ambiguous_or_mismatched_manifest_prevents_install(self):
        variants=[]
        missing=deepcopy(self.manifest);missing['packages'].pop();variants.append(missing)
        duplicate=deepcopy(self.manifest);duplicate['packages'].append(deepcopy(duplicate['packages'][1]));variants.append(duplicate)
        for key,value in [('epoch','0'),('version','2.247.0'),('release','2.fc44'),('arch','x86_64')]:
            changed=deepcopy(self.manifest);changed['packages'][1][key]=value;variants.append(changed)
        for manifest in variants:
            with self.subTest(manifest=manifest),self.mocks():
                with self.assertRaises((AssertionError,ValueError)):
                    boundary.install_packages(NONCE,manifest,exact_roots=PROFILE)
                self.assertFalse(any(args[0]=='dnf' for args in self.commands))

    def test_exact_profile_type_names_tuple_and_components_are_strict(self):
        profiles=[{'unknown-package':('0','1','1','noarch')},
                  {'moby-engine':['0','29.8.2','2.fc44','x86_64']},
                  {'moby-engine':('0','29.8.2','2.fc44')},
                  {'moby-engine':(0,'29.8.2','2.fc44','x86_64')},
                  {'moby-engine':('0','29.8.2\n--nogpgcheck','2.fc44','x86_64')},
                  {'moby-engine':('0','29.8.2','../2.fc44','x86_64')},
                  {'moby-engine':('0','29.8.2','2.fc44','x86_64;true')}]
        for profile in profiles:
            with self.subTest(profile=profile),self.assertRaises((AssertionError,ValueError)):
                boundary.exact_install_roots(self.manifest,profile)

    def test_exact_roots_require_explicit_native_profile_before_install(self):
        for profile in (None,'static-go-v1','another-native-profile'):
            manifest={**self.manifest,'profile':profile}
            with self.subTest(profile=profile),self.mocks():
                with self.assertRaises((AssertionError,ValueError)):
                    boundary.install_packages(NONCE,manifest,exact_roots=PROFILE)
                self.assertFalse(any(args[0] in ('rpmkeys','dnf') for args in self.commands))

    def test_installed_query_requires_exact_single_line_without_trimming(self):
        expected='4:2.251.0-1.fc44.noarch\n'
        for observed in (expected.rstrip(),expected+expected,' '+expected,expected+'extra\n'):
            with self.subTest(observed=observed),patch.object(boundary,'run',return_value=observed):
                with self.assertRaises((AssertionError,ValueError)):
                    boundary.require_installed_roots({'container-selinux':PROFILE['container-selinux']})

    def test_manifest_epoch_type_cannot_alias_expected_string(self):
        manifest=deepcopy(self.manifest);manifest['packages'][1]['epoch']=4
        with self.assertRaises((AssertionError,ValueError)):
            boundary.exact_install_roots(manifest,PROFILE)

    def test_postinstall_epoch_version_release_and_arch_mismatch_failclosed(self):
        for observed in ('0:2.251.0-1.fc44.noarch','4:2.247.0-1.fc44.noarch',
                         '4:2.251.0-2.fc44.noarch','4:2.251.0-1.fc44.x86_64'):
            with self.subTest(observed=observed):
                repositories=self.root/'repositories'
                if repositories.exists():
                    (repositories/'uas.repo').unlink();repositories.rmdir()
                self.upgrade=False;self.installed['container-selinux']=observed
                with self.mocks(),self.assertRaises((AssertionError,ValueError)):
                    boundary.install_packages(NONCE,self.manifest,exact_roots=PROFILE)

    def test_postinstall_mismatch_stops_outer_install_before_daemon_or_runtime_copy(self):
        self.upgrade=False
        with self.mocks(),patch.object(boundary,'verify_payload',return_value=self.manifest), \
                patch.object(boundary.shutil,'copytree') as copytree, \
                patch.object(boundary.shutil,'copyfile') as copyfile:
            with self.assertRaises((AssertionError,ValueError)):
                boundary.install(NONCE,'d'*64,exact_roots=PROFILE)
            copytree.assert_not_called();copyfile.assert_not_called()
        self.assertFalse(any(args[:3]==('systemctl','start','docker') for args in self.commands))
        self.assertFalse(any(args[0]=='useradd' for args in self.commands))


if __name__=='__main__':unittest.main()
