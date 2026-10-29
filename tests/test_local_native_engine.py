"""Selected Engine contract; all host commands, sockets and spawns are doubles."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock
from uas import local_native as local, local_hub_host as hub
from uas import native_qualification_backend as native
from uas.lifecycle import LifecycleError
from uas.native_qualification import QualificationError
from tests import test_local_native as fixtures
from tests.test_local_host_plan import profile


def selections():
    config,doc=fixtures.selections()
    host=profile();host['engine'].update(socket='/run/uas-engine.sock',
        data_root='/var/lib/uas-engine',exec_root='/run/uas-engine')
    host['mapping']['user']='uas-local'
    doc.update(version=2,profile='local-native-v2',host_profile=host)
    return config,doc


class SelectedEngineTests(unittest.TestCase):
    def test_versioned_profile_and_cli_never_use_ambient_or_default_engine(self):
        config,doc=selections();p=local.LocalNativeProfile(config,doc,'room','/srv/uas/control')
        backend=local.LocalNativeBackend(p)
        with patch.object(native.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='[]',stderr='')) as command:
            backend._run(['ps'])
        self.assertEqual(command.call_args.args[0][:3],['/usr/bin/docker','--host','unix:///run/uas-engine.sock'])
        self.assertNotIn('DOCKER_HOST',command.call_args.kwargs['env'])
        self.assertEqual(backend.engine_selection()['docker_root'],'/var/lib/uas-engine/100000.100000')
        self.assertEqual(backend.engine_selection()['remap_user'],'uas-local')

    def test_qualification_default_endpoint_unchanged(self):
        with patch.object(native.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='[]',stderr='')) as command:
            native.fixed_docker(['ps'],timeout=1)
        self.assertEqual(command.call_args.args[0][:3],['/usr/bin/docker','--host','unix:///run/docker.sock'])

    def test_admission_reads_selected_root_account_and_kernel_mapping(self):
        config,doc=selections();p=local.LocalNativeProfile(config,doc,'room','/srv/uas/control')
        backend=local.LocalNativeBackend(p);container={'State':{'Running':True,'Pid':1234}}
        reads=[]
        def read(path):
            reads.append(str(path))
            return 'uas-local:100000:65536\n' if str(path).startswith('/etc/') else '0 100000 65536'
        def run(args):
            return {'{{json .SecurityOptions}}':'["name=seccomp,profile=builtin","name=selinux","name=userns"]',
                    '{{.Server.Version}}':'29.8.2','{{.DockerRootDir}}':'/var/lib/uas-engine/100000.100000'}[args[-1]]
        with patch.object(backend,'_guard'),patch.object(backend,'_binding'),patch.object(p,'observe_storage'), \
             patch.object(backend,'_network_policy'),patch.object(backend,'_inspect_object',return_value=container), \
             patch.object(backend,'validate_container'),patch.object(backend,'_run',side_effect=run),patch.object(Path,'read_text',read):
            self.assertEqual(backend.admit({}),container)
        self.assertEqual(reads,['/etc/subuid','/etc/subgid','/proc/1234/uid_map','/proc/1234/gid_map'])

    def test_dynamic_mapping_and_duplicate_selection_mismatch_rejected(self):
        for mutation in ('offset','id','root-overlap'):
            config,doc=selections()
            if mutation=='offset':doc['mapping']['offset']=doc['host_profile']['mapping']['offset']=200000
            if mutation=='id':doc['host_profile']['installation_id']='b'*32
            if mutation=='root-overlap':doc['host_profile']['engine']['data_root']=doc['storage_root']
            with self.assertRaises((LifecycleError,ValueError)):
                local.LocalNativeProfile(config,doc,'room','/srv/uas/control')

    def startup(self,doc):
        return {'version':2,'host_profile':doc['host_profile'],'room':{'id':'room'},
                'resources':{'hub_id':'owned','instance':'instance','control_path':'/run/uas/control',
                             'mapping_digest':'b'*64,'control_fd':9,'peer_fd':10}}

    def test_idle_hub_and_runtime_hub_bind_same_selected_engine_before_channel(self):
        _,doc=selections();value=self.startup(doc)
        self.assertEqual(hub.startup_engine(hub.startup_document(json.dumps(value).encode())),doc['host_profile']['engine']['socket'])
        value['runtime']={'native_document':doc}
        self.assertEqual(hub.startup_engine(hub.startup_document(json.dumps(value).encode())),doc['host_profile']['engine']['socket'])
        value['runtime']['native_document']=deepcopy(doc)
        value['runtime']['native_document']['host_profile']['engine']['socket']='/run/foreign.sock'
        with self.assertRaisesRegex(QualificationError,'ENGINE_BINDING'):hub.startup_document(json.dumps(value).encode())

    def test_legacy_startup_cannot_smuggle_alternate_runtime_engine(self):
        _,doc=selections();value=self.startup(doc);value.pop('host_profile');value['version']=1
        value['runtime']={'native_document':doc}
        with self.assertRaisesRegex(QualificationError,'ENGINE_BINDING'):hub.startup_document(json.dumps(value).encode())
